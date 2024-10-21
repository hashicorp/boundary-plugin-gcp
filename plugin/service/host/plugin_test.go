// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/google/go-cmp/cmp"
	cred "github.com/hashicorp/boundary-plugin-gcp/internal/credential"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func wrapMap(t *testing.T, in map[string]interface{}) *structpb.Struct {
	t.Helper()
	out, err := structpb.NewStruct(in)
	require.NoError(t, err)
	return out
}

func TestListHosts(t *testing.T) {
	t.Skip("TODO: this needs a secrets file to run - maybe only manually?")
	ctx := context.Background()
	p := &HostPlugin{}

	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NotEmpty(t, wd)
	project, err := parseutil.ParsePath("file://" + filepath.Join(wd, "secrets", "project"))
	require.NoError(t, err)
	zone, err := parseutil.ParsePath("file://" + filepath.Join(wd, "secrets", "zone"))
	require.NoError(t, err)

	hostCatalogAttributes := &hostcatalogs.HostCatalog_Attributes{
		Attributes: wrapMap(t, map[string]interface{}{
			cred.ConstProjectId: project,
			cred.ConstZone:      zone,
		}),
	}

	cases := []struct {
		name        string
		req         *pb.ListHostsRequest
		expected    []*pb.ListHostsResponseHost
		expectedErr string
	}{
		{
			name:        "nil catalog",
			req:         &pb.ListHostsRequest{},
			expectedErr: "catalog is nil",
		},
		{
			name: "project not defined",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: wrapMap(t, map[string]interface{}{
							cred.ConstZone: zone,
						}),
					},
				},
			},
			expectedErr: "attributes.project: missing required value \"project\"",
		},
		{
			name: "get all three instances",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: hostCatalogAttributes,
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "get-all-instances",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: wrapMap(t, map[string]interface{}{}),
						},
					},
				},
			},
			expected: []*pb.ListHostsResponseHost{
				{
					Name: "boundary-0",
				},
				{
					Name: "boundary-1",
				},
				{
					Name: "boundary-2",
				},
			},
		},
		{
			name: "get one instance by name",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: hostCatalogAttributes,
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "get-one-instance-by-name",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: wrapMap(t, map[string]interface{}{
								ConstListInstancesFilter: "name = boundary-1",
							}),
						},
					},
				},
			},
			expected: []*pb.ListHostsResponseHost{
				{
					Name: "boundary-1",
				},
			},
		},
		{
			name: "get instance group",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: hostCatalogAttributes,
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "get-instance-group",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: wrapMap(t, map[string]interface{}{
								ConstInstanceGroup: "boundary-servers",
							}),
						},
					},
				},
			},
			expected: []*pb.ListHostsResponseHost{
				{
					Name: "boundary-0",
				},
				{
					Name: "boundary-1",
				},
				{
					Name: "boundary-2",
				},
			},
		},
		{
			name: "get two specific instances with two host sets",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: hostCatalogAttributes,
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "get-one-instance-by-name-0",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: wrapMap(t, map[string]interface{}{
								ConstListInstancesFilter: "name = boundary-0",
							}),
						},
					},
					{
						Id: "get-one-instance-by-name-2",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: wrapMap(t, map[string]interface{}{
								ConstListInstancesFilter: "name = boundary-2",
							}),
						},
					},
				},
			},
			expected: []*pb.ListHostsResponseHost{
				{
					Name: "boundary-0",
				},
				{
					Name: "boundary-2",
				},
			},
		},
		{
			name: "get one instance and an instance group in two host sets",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: hostCatalogAttributes,
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "get-one-instance-by-name",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: wrapMap(t, map[string]interface{}{
								ConstListInstancesFilter: "name = boundary-1",
							}),
						},
					},
					{
						Id: "get-instance-group",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: wrapMap(t, map[string]interface{}{
								ConstInstanceGroup: "boundary-servers",
							}),
						},
					},
				},
			},
			expected: []*pb.ListHostsResponseHost{
				{
					Name: "boundary-0",
				},
				{
					Name: "boundary-1",
				},
				{
					Name: "boundary-2",
				},
			},
		},
		{
			name: "get an instance group and one instance in two host sets",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: hostCatalogAttributes,
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "get-instance-group",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: wrapMap(t, map[string]interface{}{
								ConstInstanceGroup: "boundary-servers",
							}),
						},
					},
					{
						Id: "get-one-instance-by-name",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: wrapMap(t, map[string]interface{}{
								ConstListInstancesFilter: "name = boundary-2",
							}),
						},
					},
				},
			},
			expected: []*pb.ListHostsResponseHost{
				{
					Name: "boundary-0",
				},
				{
					Name: "boundary-1",
				},
				{
					Name: "boundary-2",
				},
			},
		},
		{
			name: "invalid filter",
			req: &pb.ListHostsRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: hostCatalogAttributes,
				},
				Sets: []*hostsets.HostSet{
					{
						Id: "invalid-filter",
						Attrs: &hostsets.HostSet_Attributes{
							Attributes: wrapMap(t, map[string]interface{}{
								ConstListInstancesFilter: "not-a-filter",
							}),
						},
					},
				},
			},
			expectedErr: "Invalid list filter expression",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			actual, err := p.ListHosts(ctx, tc.req)
			if tc.expectedErr != "" {
				require.Contains(err.Error(), tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(len(tc.expected), len(actual.GetHosts()))
		})
	}
}

func TestCreateCatalog(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name        string
		req         *pb.OnCreateCatalogRequest
		expected    *pb.HostCatalogPersisted
		catalogOpts []gcpCatalogPersistedStateOption
		expectedErr string
		expectedRsp *pb.OnCreateCatalogResponse
	}{
		{
			name:        "nil catalog",
			req:         &pb.OnCreateCatalogRequest{},
			expectedErr: "catalog is nil",
		},
		{
			name: "nil attributes",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{},
			},
			expectedErr: "attributes are required",
		},
		{
			name: "error reading attributes",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: new(structpb.Struct),
					},
				},
			},
			expectedErr: "attributes.project_id: missing required value \"project_id\"",
		},
		{
			name: "using static credentials",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId:                 structpb.NewStringValue("test-project"),
								cred.ConstZone:                      structpb.NewStringValue("us-central1-a"),
								cred.ConstClientEmail:               structpb.NewStringValue("test-client-email@email.com"),
								cred.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							},
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId: structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:   structpb.NewStringValue("test-private-key"),
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				withTestInstancesAPIFunc(newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{
						Items: []*computepb.Instance{
							{
								Name: pointer("boundary-0"),
								NetworkInterfaces: []*computepb.NetworkInterface{
									{
										AccessConfigs: []*computepb.AccessConfig{
											{
												NatIP:        pointer("102.1.1.1"),
												ExternalIpv6: pointer("2001:db8::1"),
											},
										},
									},
								},
							},
						},
					}),
					testMockInstancesWithListInstancesError(nil),
				)),
			},
			expectedRsp: &pb.OnCreateCatalogResponse{
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKey:   structpb.NewStringValue("test-private-key"),
							cred.ConstPrivateKeyId: structpb.NewStringValue("test-private-key-id"),
						},
					},
				},
			},
		},
		{
			name: "using rotated static credentials",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId:                 structpb.NewStringValue("test-project"),
								cred.ConstZone:                      structpb.NewStringValue("us-central1-a"),
								cred.ConstClientEmail:               structpb.NewStringValue("test-client-email@email.com"),
								cred.ConstDisableCredentialRotation: structpb.NewBoolValue(false),
							},
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId: structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:   structpb.NewStringValue("test-private-key"),
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				withTestInstancesAPIFunc(newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{
						Items: []*computepb.Instance{
							{
								Name: pointer("boundary-0"),
								NetworkInterfaces: []*computepb.NetworkInterface{
									{
										AccessConfigs: []*computepb.AccessConfig{
											{
												NatIP:        pointer("102.1.1.1"),
												ExternalIpv6: pointer("2001:db8::1"),
											},
										},
									},
								},
							},
						},
					}),
					testMockInstancesWithListInstancesError(nil),
				)),
			},
			expectedRsp: &pb.OnCreateCatalogResponse{
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKey:   structpb.NewStringValue("updated-private-key"),
							cred.ConstPrivateKeyId: structpb.NewStringValue("updated-private-key-id"),
						},
					},
				},
			},
		},
		{
			name: "using impersonated credentials",
			req: &pb.OnCreateCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId:                 structpb.NewStringValue("test-project"),
								cred.ConstZone:                      structpb.NewStringValue("us-central1-a"),
								cred.ConstClientEmail:               structpb.NewStringValue("test-client-email@email.com"),
								cred.ConstTargetServiceAccountID:    structpb.NewStringValue("test-target-service-account-id"),
								cred.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							},
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId: structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:   structpb.NewStringValue("test-private-key"),
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				withTestInstancesAPIFunc(newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{}),
					testMockInstancesWithListInstancesError(nil),
				)),
			},
			expectedRsp: &pb.OnCreateCatalogResponse{
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKey:   structpb.NewStringValue("test-private-key"),
							cred.ConstPrivateKeyId: structpb.NewStringValue("test-private-key-id"),
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			testIAMAdminServer := cred.NewTestIAMAdminServer(nil, nil)
			testResourceServer := cred.NewTestResourceServer(&iampb.TestIamPermissionsResponse{
				Permissions: []string{
					cred.ComputeInstancesListPermission,
					cred.IAMServiceAccountKeysCreatePermission,
					cred.IAMServiceAccountKeysDeletePermission,
				},
			}, nil)

			gsrv := cred.NewGRPCServer()
			adminpb.RegisterIAMServer(gsrv.Server, testIAMAdminServer)
			resourcemanagerpb.RegisterProjectsServer(gsrv.Server, testResourceServer)
			addr, err := gsrv.Start()
			require.NoError(err)

			p := &HostPlugin{
				testGCPClientOpts: []option.ClientOption{
					option.WithEndpoint(addr),
					option.WithoutAuthentication(),
					option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
					option.WithTokenSource(nil),
				},
				testCatalogStateOpts: tc.catalogOpts,
			}

			actual, err := p.OnCreateCatalog(ctx, tc.req)
			if tc.expectedErr != "" {
				require.Contains(err.Error(), tc.expectedErr)
				return
			}
			require.NoError(err)
			delete(actual.GetPersisted().GetSecrets().GetFields(), cred.ConstCredsLastRotatedTime)
			require.Empty(cmp.Diff(tc.expectedRsp, actual, protocmp.Transform()))
		})
	}
}

func TestUpdateCatalog(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name        string
		req         *pb.OnUpdateCatalogRequest
		catalogOpts []gcpCatalogPersistedStateOption
		expectedRsp *pb.OnUpdateCatalogResponse
		expectedErr string
	}{
		{
			name:        "nil current catalog",
			req:         &pb.OnUpdateCatalogRequest{},
			expectedErr: "current catalog is required",
		},
		{
			name: "nil new catalog",
			req: &pb.OnUpdateCatalogRequest{
				CurrentCatalog: &hostcatalogs.HostCatalog{},
			},
			expectedErr: "new catalog is required",
		},
		{
			name: "nil attributes",
			req: &pb.OnUpdateCatalogRequest{
				CurrentCatalog: &hostcatalogs.HostCatalog{},
				NewCatalog:     &hostcatalogs.HostCatalog{},
			},
			expectedErr: "attributes are required",
		},
		{
			name: "error reading attributes",
			req: &pb.OnUpdateCatalogRequest{
				CurrentCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: new(structpb.Struct),
					},
				},
				NewCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: new(structpb.Struct),
					},
				},
			},
			expectedErr: "attributes.project_id: missing required value \"project_id\"",
		},
		{
			name: "staticCredentialToStaticRotated",
			req: &pb.OnUpdateCatalogRequest{
				CurrentCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId:                 structpb.NewStringValue("test-project"),
								cred.ConstClientEmail:               structpb.NewStringValue("test@example.com"),
								cred.ConstZone:                      structpb.NewStringValue("us-central1-a"),
								cred.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							},
						},
					},
				},
				NewCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId:   structpb.NewStringValue("test-project"),
								cred.ConstZone:        structpb.NewStringValue("us-central1-a"),
								cred.ConstClientEmail: structpb.NewStringValue("test@example.com"),
							},
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId: structpb.NewStringValue("new-private-key-id"),
							cred.ConstPrivateKey:   structpb.NewStringValue("new-private-key"),
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("persisted-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("persisted-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue(time.Time{}.Format(time.RFC3339Nano)),
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				withTestInstancesAPIFunc(newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{}),
					testMockInstancesWithListInstancesError(nil),
				)),
			},
			expectedRsp: &pb.OnUpdateCatalogResponse{
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId: structpb.NewStringValue("updated-private-key-id"),
							cred.ConstPrivateKey:   structpb.NewStringValue("updated-private-key"),
						},
					},
				},
			},
		},
		{
			name: "staticRotatedCredentialToStatic",
			req: &pb.OnUpdateCatalogRequest{
				CurrentCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId:   structpb.NewStringValue("test-project"),
								cred.ConstClientEmail: structpb.NewStringValue("test@example.com"),
								cred.ConstZone:        structpb.NewStringValue("us-central1-a"),
							},
						},
					},
				},
				NewCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId:                 structpb.NewStringValue("test-project"),
								cred.ConstZone:                      structpb.NewStringValue("us-central1-a"),
								cred.ConstClientEmail:               structpb.NewStringValue("test@example.com"),
								cred.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							},
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId: structpb.NewStringValue("not-rotated-private-key-id"),
							cred.ConstPrivateKey:   structpb.NewStringValue("not-rotated-private-key"),
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("persisted-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("persisted-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue(time.Now().Format(time.RFC3339Nano)),
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				withTestInstancesAPIFunc(newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{}),
					testMockInstancesWithListInstancesError(nil),
				)),
			},
			expectedRsp: &pb.OnUpdateCatalogResponse{
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId: structpb.NewStringValue("not-rotated-private-key-id"),
							cred.ConstPrivateKey:   structpb.NewStringValue("not-rotated-private-key"),
						},
					},
				},
			},
		},
		{
			name: "staticCredentialToImpersonateCredential",
			req: &pb.OnUpdateCatalogRequest{
				CurrentCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId:                 structpb.NewStringValue("test-project"),
								cred.ConstClientEmail:               structpb.NewStringValue("test@example.com"),
								cred.ConstZone:                      structpb.NewStringValue("us-central1-a"),
								cred.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							},
						},
					},
				},
				NewCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId:                 structpb.NewStringValue("test-project"),
								cred.ConstZone:                      structpb.NewStringValue("us-central1-a"),
								cred.ConstClientEmail:               structpb.NewStringValue("test@example.com"),
								cred.ConstTargetServiceAccountID:    structpb.NewStringValue("test-target-service-account-id"),
								cred.ConstDisableCredentialRotation: structpb.NewBoolValue(true),
							},
						},
					},
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId: structpb.NewStringValue("new-private-key-id"),
							cred.ConstPrivateKey:   structpb.NewStringValue("new-private-key"),
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("persisted-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("persisted-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue(time.Time{}.Format(time.RFC3339Nano)),
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				withTestInstancesAPIFunc(newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{}),
					testMockInstancesWithListInstancesError(nil),
				)),
			},
			expectedRsp: &pb.OnUpdateCatalogResponse{
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId: structpb.NewStringValue("new-private-key-id"),
							cred.ConstPrivateKey:   structpb.NewStringValue("new-private-key"),
						},
					},
				},
			},
		},
		{
			name: "staticRotatedCredentialToAppDefaultCredential",
			req: &pb.OnUpdateCatalogRequest{
				CurrentCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId:   structpb.NewStringValue("test-project"),
								cred.ConstClientEmail: structpb.NewStringValue("test@example.com"),
								cred.ConstZone:        structpb.NewStringValue("us-central1-a"),
							},
						},
					},
				},
				NewCatalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId: structpb.NewStringValue("test-project"),
								cred.ConstZone:      structpb.NewStringValue("us-central1-a"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("persisted-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("persisted-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue(time.Time{}.Format(time.RFC3339Nano)),
						},
					},
				},
			},
			expectedErr: "cannot rotate credentials for non-rotatable credentials",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			testIAMAdminServer := cred.NewTestIAMAdminServer(nil, nil)
			testResourceServer := cred.NewTestResourceServer(&iampb.TestIamPermissionsResponse{
				Permissions: []string{
					cred.ComputeInstancesListPermission,
					cred.IAMServiceAccountKeysCreatePermission,
					cred.IAMServiceAccountKeysDeletePermission,
				},
			}, nil)

			gsrv := cred.NewGRPCServer()
			adminpb.RegisterIAMServer(gsrv.Server, testIAMAdminServer)
			resourcemanagerpb.RegisterProjectsServer(gsrv.Server, testResourceServer)
			addr, err := gsrv.Start()
			require.NoError(err)

			p := &HostPlugin{
				testGCPClientOpts: []option.ClientOption{
					option.WithEndpoint(addr),
					option.WithoutAuthentication(),
					option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
					option.WithTokenSource(nil),
				},
				testCatalogStateOpts: tc.catalogOpts,
			}

			actual, err := p.OnUpdateCatalog(ctx, tc.req)
			if tc.expectedErr != "" {
				require.Contains(err.Error(), tc.expectedErr)
				return
			}
			require.NoError(err)

			delete(actual.GetPersisted().GetSecrets().GetFields(), cred.ConstCredsLastRotatedTime)
			require.Empty(cmp.Diff(tc.expectedRsp, actual, protocmp.Transform()))
		})
	}
}

func TestCreateSet(t *testing.T) {
	ctx := context.Background()
	p := &HostPlugin{}

	cases := []struct {
		name        string
		req         *pb.OnCreateSetRequest
		expectedErr string
	}{
		{
			name:        "nil set",
			req:         &pb.OnCreateSetRequest{},
			expectedErr: "set is nil",
		},
		{
			name: "nil set",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId: structpb.NewStringValue("test-project"),
								cred.ConstZone:      structpb.NewStringValue("us-central1-a"),
							},
						},
					},
				},
			},
			expectedErr: "set is nil",
		},
		{
			name: "only allow instance group or filter, not both",
			req: &pb.OnCreateSetRequest{
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewStringValue("status=RUNNING"),
								ConstInstanceGroup:       structpb.NewStringValue("test"),
							},
						},
					},
				},
			},
			expectedErr: "attributes: must set instance group or filter",
		},
		{
			name: "empty filter",
			req: &pb.OnCreateSetRequest{
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewStringValue(""),
							},
						},
					},
				},
			},
			expectedErr: "attributes.filter: must not be empty",
		},
		{
			name: "empty instance group",
			req: &pb.OnCreateSetRequest{
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstInstanceGroup: structpb.NewStringValue(""),
							},
						},
					},
				},
			},
			expectedErr: "attributes.instance_group: must not be empty",
		},
		{
			name: "good filter",
			req: &pb.OnCreateSetRequest{
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstInstanceGroup: structpb.NewStringValue("status=RUNNING"),
							},
						},
					},
				},
			},
		},
		{
			name: "good instance group",
			req: &pb.OnCreateSetRequest{
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstInstanceGroup: structpb.NewStringValue("test"),
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			_, err := p.OnCreateSet(ctx, tc.req)
			if tc.expectedErr != "" {
				require.Contains(err.Error(), tc.expectedErr)
				return
			}

			require.NoError(err)
		})
	}
}

func TestUpdateSet(t *testing.T) {
	ctx := context.Background()
	p := &HostPlugin{}

	cases := []struct {
		name        string
		req         *pb.OnUpdateSetRequest
		expectedErr string
	}{
		{
			name:        "nil set",
			req:         &pb.OnUpdateSetRequest{},
			expectedErr: "set is nil",
		},
		{
			name: "nil set",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId: structpb.NewStringValue("test-project"),
								cred.ConstZone:      structpb.NewStringValue("us-central1-a"),
							},
						},
					},
				},
			},
			expectedErr: "set is nil",
		},
		{
			name: "only allow instance group or filter, not both",
			req: &pb.OnUpdateSetRequest{
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewStringValue("status=RUNNING"),
								ConstInstanceGroup:       structpb.NewStringValue("test"),
							},
						},
					},
				},
			},
			expectedErr: "attributes: must set instance group or filter",
		},
		{
			name: "empty filter",
			req: &pb.OnUpdateSetRequest{
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewStringValue(""),
							},
						},
					},
				},
			},
			expectedErr: "attributes.filter: must not be empty",
		},
		{
			name: "empty instance group",
			req: &pb.OnUpdateSetRequest{
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstInstanceGroup: structpb.NewStringValue(""),
							},
						},
					},
				},
			},
			expectedErr: "attributes.instance_group: must not be empty",
		},
		{
			name: "good filter",
			req: &pb.OnUpdateSetRequest{
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstInstanceGroup: structpb.NewStringValue("status=RUNNING"),
							},
						},
					},
				},
			},
		},
		{
			name: "good instance group",
			req: &pb.OnUpdateSetRequest{
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstInstanceGroup: structpb.NewStringValue("test"),
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			_, err := p.OnUpdateSet(ctx, tc.req)
			if tc.expectedErr != "" {
				require.Contains(err.Error(), tc.expectedErr)
				return
			}

			require.NoError(err)
		})
	}
}
