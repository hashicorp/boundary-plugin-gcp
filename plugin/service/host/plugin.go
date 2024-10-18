// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"github.com/hashicorp/boundary-plugin-gcp/internal/credential"
	errors "github.com/hashicorp/boundary-plugin-gcp/internal/errors"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HostPlugin implements the HostPluginServiceServer interface for the
// GCP host service plugin.
type HostPlugin struct {
	pb.UnimplementedHostPluginServiceServer
	// testGCPClientOpts are passed in to the GCP client to control test behavior
	testGCPClientOpts []option.ClientOption
	// testCatalogStateOpts are passed in to the stored state to control test behavior
	testCatalogStateOpts []gcpCatalogPersistedStateOption
}

var (
	_ pb.HostPluginServiceServer = (*HostPlugin)(nil)
)

// OnCreateCatalog is called when a dynamic host catalog is created.
func (p *HostPlugin) OnCreateCatalog(ctx context.Context, req *pb.OnCreateCatalogRequest) (*pb.OnCreateCatalogResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, status.Error(codes.InvalidArgument, "catalog is nil")
	}

	attrs := catalog.GetAttributes()
	if attrs == nil {
		return nil, status.Error(codes.InvalidArgument, "attributes are required")
	}

	catalogAttributes, err := getCatalogAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credConfig, err := credential.GetCredentialsConfig(catalog.GetSecrets(), catalogAttributes.CredentialAttributes)
	if err != nil {
		return nil, err
	}

	credState, err := credential.NewPersistedState([]credential.Option{
		credential.WithCredentialsConfig(credConfig),
	}...,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error creating new persisted state: %s", err)
	}

	permissions := []string{
		credential.ComputeInstancesListPermission,
		credential.IAMServiceAccountKeysCreatePermission,
		credential.IAMServiceAccountKeysDeletePermission,
	}

	if credState.CredentialsConfig.IsRotatable() && !catalogAttributes.DisableCredentialRotation {
		if err := credState.CredentialsConfig.RotateServiceAccountKey(ctx, permissions, p.testGCPClientOpts...); err != nil {
			return nil, err
		}
	}

	catalogState, err := newGCPCatalogPersistedState(
		append([]gcpCatalogPersistedStateOption{
			withCredentials(credState),
		}, p.testCatalogStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error setting up persisted state: %s", err)
	}

	if st := dryRunValidation(ctx, catalogState, p.testGCPClientOpts...); st != nil {
		return nil, st.Err()
	}

	persistedProto, err := catalogState.toProto()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting state to proto: %s", err)
	}

	return &pb.OnCreateCatalogResponse{
		Persisted: persistedProto,
	}, nil
}

// OnUpdateCatalog is called when a dynamic host catalog is updated.
func (p *HostPlugin) OnUpdateCatalog(ctx context.Context, req *pb.OnUpdateCatalogRequest) (*pb.OnUpdateCatalogResponse, error) {
	currentCatalog := req.GetCurrentCatalog()
	if currentCatalog == nil {
		return nil, status.Errorf(codes.InvalidArgument, "current catalog is required")
	}
	newCatalog := req.GetNewCatalog()
	if newCatalog == nil {
		return nil, status.Errorf(codes.InvalidArgument, "new catalog is required")
	}

	oldAttrs := currentCatalog.GetAttributes()
	if oldAttrs == nil {
		return nil, status.Errorf(codes.InvalidArgument, "old catalog attributes are required")
	}
	oldCatalogAttributes, err := getCatalogAttributes(oldAttrs)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error getting old catalog attributes: %s", err)
	}
	newAttrs := newCatalog.GetAttributes()
	if newAttrs == nil {
		return nil, status.Errorf(codes.InvalidArgument, "new catalog attributes are required")
	}
	newCatalogAttributes, err := getCatalogAttributes(newAttrs)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error getting new catalog attributes: %s", err)
	}

	credState, err := credential.PersistedStateFromProto(
		req.GetPersisted().GetSecrets(),
		oldCatalogAttributes.CredentialAttributes,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error getting persisted state from proto: %s", err)
	}

	updatedCredentials, err := credential.GetCredentialsConfig(newCatalog.GetSecrets(), newCatalogAttributes.CredentialAttributes)
	if err != nil {
		return nil, err
	}

	if newCatalog.GetSecrets() != nil {
		newCredState, err := credential.NewPersistedState([]credential.Option{
			credential.WithCredentialsConfig(updatedCredentials),
		}...,
		)
		if err != nil {
			return nil, status.Error(codes.Internal, fmt.Sprintf("error creating new persisted state: %s", err))
		}
		newCatalogState, err := newGCPCatalogPersistedState(
			append([]gcpCatalogPersistedStateOption{
				withCredentials(newCredState),
			}, p.testCatalogStateOpts...)...,
		)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "error setting up persisted state: %s", err)
		}
		if st := dryRunValidation(ctx, newCatalogState); st != nil {
			return nil, st.Err()
		}

		// Replace the existing credential state.
		// This checks the timestamp on the last rotation time as well
		// and deletes the credentials if we are managing them
		// (ie: if we've rotated them before).
		if err := credState.ReplaceCreds(ctx, updatedCredentials, p.testGCPClientOpts...); err != nil {
			return nil, err
		}
	}

	if credState.CredentialsConfig.IsRotatable() {
		if !updatedCredentials.IsRotatable() && !newCatalogAttributes.DisableCredentialRotation {
			return nil, status.Error(codes.InvalidArgument, "cannot rotate credentials for non-rotatable credentials")
		}

		// This is a validate check to make sure that we aren't disabling
		// rotation for credentials currently being managed by rotation.
		// This is not allowed.
		if newCatalogAttributes.DisableCredentialRotation && newCatalog.GetSecrets() == nil {
			if !credState.CredsLastRotatedTime.IsZero() {
				return nil, status.Error(codes.InvalidArgument, "cannot disable credential rotation for credentials currently being rotated")
			}
		}

		permissions := []string{
			credential.ComputeInstancesListPermission,
			credential.IAMServiceAccountKeysCreatePermission,
			credential.IAMServiceAccountKeysDeletePermission,
		}

		// If we're enabling rotation now but didn't before, or have
		// freshly replaced credentials, we can rotate here.
		if !newCatalogAttributes.DisableCredentialRotation && credState.CredsLastRotatedTime.IsZero() {
			if err := credState.CredentialsConfig.RotateServiceAccountKey(ctx, permissions, p.testGCPClientOpts...); err != nil {
				return nil, err
			}
		}
	}

	catalogState, err := newGCPCatalogPersistedState(
		append([]gcpCatalogPersistedStateOption{
			withCredentials(credState),
		}, p.testCatalogStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error setting up persisted state: %s", err)
	}

	// perform dry run to ensure we can interact with GCP as expected.
	if st := dryRunValidation(ctx, catalogState, p.testGCPClientOpts...); st != nil {
		return nil, st.Err()
	}

	persistedProto, err := catalogState.toProto()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting state to proto: %s", err)
	}

	return &pb.OnUpdateCatalogResponse{
		Persisted: persistedProto,
	}, nil
}

// OnDeleteCatalog is called when a dynamic host catalog is deleted.
func (p *HostPlugin) OnDeleteCatalog(ctx context.Context, req *pb.OnDeleteCatalogRequest) (*pb.OnDeleteCatalogResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, status.Error(codes.InvalidArgument, "new catalog is nil")
	}

	attrs := catalog.GetAttributes()
	if attrs == nil {
		return nil, status.Error(codes.InvalidArgument, "new catalog missing attributes")
	}

	catalogAttributes, err := getCatalogAttributes(attrs)
	if err != nil {
		return nil, err
	}

	credState, err := credential.PersistedStateFromProto(
		req.GetPersisted().GetSecrets(),
		catalogAttributes.CredentialAttributes)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error getting persisted state from proto: %s", err)
	}

	_, err = newGCPCatalogPersistedState(
		append([]gcpCatalogPersistedStateOption{
			withCredentials(credState),
		}, p.testCatalogStateOpts...)...,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error loading persisted state: %s", err)
	}

	// try to delete static credentials for dynamic and static credentials
	if credState.CredentialsConfig.IsRotatable() {
		if !credState.CredsLastRotatedTime.IsZero() {
			// Delete old/existing credentials. This is done with the same
			// credentials to ensure that it has the proper permissions to do
			// it.
			if err := credState.DeleteCreds(ctx, p.testGCPClientOpts...); err != nil {
				return nil, err
			}
		}
	}

	return &pb.OnDeleteCatalogResponse{}, nil
}

// OnCreateSet is called when a dynamic host set is created.
func (p *HostPlugin) OnCreateSet(_ context.Context, req *pb.OnCreateSetRequest) (*pb.OnCreateSetResponse, error) {
	if err := validateSet(req.GetSet()); err != nil {
		return nil, err
	}
	return &pb.OnCreateSetResponse{}, nil
}

// OnUpdateSet is called when a dynamic host set is updated.
func (p *HostPlugin) OnUpdateSet(_ context.Context, req *pb.OnUpdateSetRequest) (*pb.OnUpdateSetResponse, error) {
	if err := validateSet(req.GetNewSet()); err != nil {
		return nil, err
	}
	return &pb.OnUpdateSetResponse{}, nil
}

// OnDeleteSet is called when a dynamic host set is deleted.
func (p *HostPlugin) OnDeleteSet(ctx context.Context, req *pb.OnDeleteSetRequest) (*pb.OnDeleteSetResponse, error) {
	return &pb.OnDeleteSetResponse{}, nil
}

// ListHosts returns the list of instances based on filter or instance group name.
func (p *HostPlugin) ListHosts(ctx context.Context, req *pb.ListHostsRequest) (*pb.ListHostsResponse, error) {
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, status.Error(codes.InvalidArgument, "catalog is nil")
	}

	catalogAttrsRaw := catalog.GetAttributes()
	if catalogAttrsRaw == nil {
		return nil, status.Error(codes.InvalidArgument, "catalog missing attributes")
	}

	catalogAttributes, err := getCatalogAttributes(catalogAttrsRaw)
	if err != nil {
		return nil, err
	}

	sets := req.GetSets()
	if sets == nil {
		return nil, status.Error(codes.InvalidArgument, "sets is nil")
	}

	type hostSetQuery struct {
		Id             string
		InputInstances *computepb.ListInstancesRequest
		InputGroups    *computepb.ListInstancesInstanceGroupsRequest
		Project        string
		Zone           string
		Output         []*computepb.Instance
		OutputHosts    []*pb.ListHostsResponseHost
	}

	queries := make([]hostSetQuery, len(sets))
	for i, set := range sets {
		// Validate Id since we use it in output
		if set.GetId() == "" {
			return nil, status.Error(codes.InvalidArgument, "set missing id")
		}

		if set.GetAttributes() == nil {
			return nil, status.Error(codes.InvalidArgument, "set missing attributes")
		}
		setAttrs, err := getSetAttributes(set.GetAttributes())
		if err != nil {
			return nil, err
		}

		if setAttrs.InstanceGroup != "" {
			queries[i] = hostSetQuery{
				Id:          set.GetId(),
				InputGroups: buildListInstanceGroupsRequest(setAttrs, catalogAttributes),
			}
		} else {
			queries[i] = hostSetQuery{
				Id:             set.GetId(),
				InputInstances: buildListInstancesRequest(setAttrs, catalogAttributes),
			}
		}
	}

	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error creating NewInstancesRESTClient: %s", err)
	}

	instanceGroupsClient, err := compute.NewInstanceGroupsRESTClient(ctx)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error creating NewInstanceGroupsRESTClient: %s", err)
	}

	gclient := GoogleClient{
		InstancesClient:     instancesClient,
		InstanceGroupClient: instanceGroupsClient,
		Context:             ctx,
	}

	// Run all queries now and assemble output.
	var maxLen int
	for i, query := range queries {
		var output []*computepb.Instance
		if query.InputGroups != nil {
			output, err = gclient.getInstancesForInstanceGroup(query.InputGroups)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "error running getInstancesForInstanceGroup for host set id %q: %s", query.Id, err)
			}
		} else {
			output, err = gclient.getInstances(query.InputInstances)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "error running getInstances for host set id %q: %s", query.Id, err)
			}
		}

		queries[i].Output = output

		// Process the output here, we will normalize this into a single
		// set of hosts afterwards (possibly removing duplicates).
		for _, instance := range output {
			host, err := instanceToHost(instance)

			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "error processing host results for host set id %q: %s", query.Id, err)
			}

			queries[i].OutputHosts = append(queries[i].OutputHosts, host)
			maxLen++
		}
	}

	// Now de-duplicate the hosts for the output. Maintain two sets:
	// * A slice of hosts that will be used in the output
	// * A map of hosts indexed by their external ID
	//
	// The map will is used in de-duplication to determine whether or
	// not we've seen the host before to simply add the query's set ID
	// to the list of set IDs that the host was seen in.
	hostResultSlice := make([]*pb.ListHostsResponseHost, 0, maxLen)
	hostResultMap := make(map[string]*pb.ListHostsResponseHost)
	for _, query := range queries {
		for _, host := range query.OutputHosts {
			if existingHost, ok := hostResultMap[host.ExternalId]; ok {
				// Existing host, just add the set ID to the list of seen IDs
				// and continue
				existingHost.SetIds = append(existingHost.SetIds, query.Id)
				continue
			}

			// This will be the first seen entry, so append the set ID to
			// this host, and add it.
			host.SetIds = append(host.SetIds, query.Id)
			hostResultSlice = append(hostResultSlice, host)
			hostResultMap[host.ExternalId] = host
		}
	}

	return &pb.ListHostsResponse{
		Hosts: hostResultSlice,
	}, nil
}

func validateSet(s *hostsets.HostSet) error {
	if s == nil {
		return status.Error(codes.InvalidArgument, "set is nil")
	}
	var attrs SetAttributes
	attrMap := s.GetAttributes().AsMap()
	if err := mapstructure.Decode(attrMap, &attrs); err != nil {
		return status.Errorf(codes.InvalidArgument, "error decoding set attributes: %s", err)
	}

	badFields := make(map[string]string)
	_, filterSet := attrMap[ConstListInstancesFilter]
	_, instanceGroupSet := attrMap[ConstInstanceGroup]

	if instanceGroupSet && filterSet {
		badFields["attributes"] = "must set instance group or filter, cannot set both"
	} else if instanceGroupSet && len(attrs.InstanceGroup) == 0 {
		badFields[fmt.Sprintf("attributes.%s", ConstInstanceGroup)] = "must not be empty."
	} else if filterSet && len(attrs.Filter) == 0 {
		badFields[fmt.Sprintf("attributes.%s", ConstListInstancesFilter)] = "must not be empty."
	}

	for f := range attrMap {
		if _, ok := allowedSetFields[f]; !ok {
			badFields[fmt.Sprintf("attributes.%s", f)] = "Unrecognized field."
		}
	}

	if len(badFields) > 0 {
		return errors.InvalidArgumentError("Invalid arguments in the new set", badFields)
	}
	return nil
}

// dryRunValidation performs an GCP List Instances call to verify the state's
// credentials. If the call fails, the error is returned.
func dryRunValidation(
	ctx context.Context,
	state *gcpCatalogPersistedState,
	clientOptions ...option.ClientOption,
) *status.Status {
	if state == nil {
		return status.New(codes.InvalidArgument, "persisted state is required")
	}

	instancesClient, err := state.InstancesClient(ctx, clientOptions...)
	if err != nil {
		return status.New(codes.InvalidArgument, fmt.Sprintf("error getting instances client: %s", err))
	}

	it := instancesClient.List(ctx, &computepb.ListInstancesRequest{
		Project: state.CredentialsConfig.ProjectId,
		Zone:    state.CredentialsConfig.Zone,
	})

	_, err = it.Next()
	if err != nil && err != iterator.Done {
		return status.New(codes.FailedPrecondition, fmt.Sprintf("gcp list instances failed: %s", err))
	}

	return nil
}
