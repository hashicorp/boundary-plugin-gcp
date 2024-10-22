// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"fmt"
	"net/http"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

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

func TestDeleteCatalog(t *testing.T) {
	cases := []struct {
		name            string
		req             *pb.OnDeleteCatalogRequest
		catalogOpts     []gcpCatalogPersistedStateOption
		deleteCredError error
		expectedRsp     *pb.OnDeleteCatalogResponse
		expectedErr     string
		expectedErrCode codes.Code
	}{
		{
			name: "persisted state setup error",
			req: &pb.OnDeleteCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstProjectId: structpb.NewStringValue("test-project-id"),
								cred.ConstZone:      structpb.NewStringValue("us-central1-a"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				func(s *gcpCatalogPersistedState) error {
					return fmt.Errorf("error loading persisted state")
				},
			},
			expectedErr:     "error loading persisted state",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "delete error",
			req: &pb.OnDeleteCatalogRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								cred.ConstClientEmail: structpb.NewStringValue("test@test.com"),
								cred.ConstProjectId:   structpb.NewStringValue("test-project-id"),
								cred.ConstZone:        structpb.NewStringValue("us-central1-a"),
							},
						},
					},
				},
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			deleteCredError: fmt.Errorf("failed to delete access key"),
			expectedErr:     "failed to delete access key",
			expectedErrCode: codes.Unknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			testIAMAdminServer := cred.NewTestIAMAdminServer(nil, tc.deleteCredError)

			gsrv := cred.NewGRPCServer()
			adminpb.RegisterIAMServer(gsrv.Server, testIAMAdminServer)
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

			_, err = p.OnDeleteCatalog(context.Background(), tc.req)
			require.Error(err)
			require.Contains(err.Error(), tc.expectedErr)
			require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
		})
	}
}

func TestCreateSet(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name            string
		req             *pb.OnCreateSetRequest
		catalogOpts     []gcpCatalogPersistedStateOption
		gcpOptions      []option.ClientOption
		expectedErr     string
		expectedErrCode codes.Code
	}{
		{
			name:            "nil host catalog",
			req:             &pb.OnCreateSetRequest{},
			expectedErr:     "catalog is required",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "nil host catalog attributes",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{},
			},
			expectedErr:     "catalog attributes are required",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "error reading catalog attributes",
			req: &pb.OnCreateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: new(structpb.Struct),
					},
				},
			},
			expectedErr:     "missing required value \"project_id\"",
			expectedErrCode: codes.InvalidArgument,
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
			expectedErr:     "set is required",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "persisted state setup error",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				func(s *gcpCatalogPersistedState) error {
					return fmt.Errorf("error loading persisted state")
				},
			},
			expectedErr:     "error loading persisted state",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "nil attributes in set",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{},
			},
			expectedErr:     "set attributes are required",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "set attribute load error",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"foo": structpb.NewBoolValue(true),
								"bar": structpb.NewBoolValue(true),
							},
						},
					},
				},
			},
			expectedErr:     "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "invalid filter",
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
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("invalid"),
										},
									},
								),
							},
						},
					},
				},
			},
			expectedErr:     "error building filters",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "client load error",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			gcpOptions: []option.ClientOption{
				option.WithHTTPClient(&http.Client{}),
			},
			expectedErr:     "error getting instances client",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "List instances error",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				withTestInstancesAPIFunc(newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesError(fmt.Errorf("failed to list instances")),
				)),
			},
			expectedErr:     "gcp list instances failed",
			expectedErrCode: codes.FailedPrecondition,
		},
		{
			name: "success",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				Set: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				withTestInstancesAPIFunc(newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{}),
					testMockInstancesWithListInstancesError(nil)),
				),
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			testIAMAdminServer := cred.NewTestIAMAdminServer(nil, nil)

			gsrv := cred.NewGRPCServer()
			adminpb.RegisterIAMServer(gsrv.Server, testIAMAdminServer)
			addr, err := gsrv.Start()
			require.NoError(err)

			clientOptions := []option.ClientOption{
				option.WithEndpoint(addr),
				option.WithoutAuthentication(),
				option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
				option.WithTokenSource(nil),
			}

			clientOptions = append(clientOptions, tc.gcpOptions...)

			p := &HostPlugin{
				testGCPClientOpts:    clientOptions,
				testCatalogStateOpts: tc.catalogOpts,
			}
			_, err = p.OnCreateSet(ctx, tc.req)
			if tc.expectedErr != "" {
				require.Contains(err.Error(), tc.expectedErr)
				require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
				return
			}

			require.NoError(err)
		})
	}
}

func TestUpdateSet(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name            string
		req             *pb.OnUpdateSetRequest
		catalogOpts     []gcpCatalogPersistedStateOption
		gcpOptions      []option.ClientOption
		expectedErr     string
		expectedErrCode codes.Code
	}{
		{
			name:            "nil host catalog",
			req:             &pb.OnUpdateSetRequest{},
			expectedErr:     "catalog is required",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "nil host catalog attributes",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{},
			},
			expectedErr:     "catalog attributes are required",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "error reading catalog attributes",
			req: &pb.OnUpdateSetRequest{
				Catalog: &hostcatalogs.HostCatalog{
					Secrets: new(structpb.Struct),
					Attrs: &hostcatalogs.HostCatalog_Attributes{
						Attributes: new(structpb.Struct),
					},
				},
			},
			expectedErr:     "missing required value \"project_id\"",
			expectedErrCode: codes.InvalidArgument,
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
			expectedErr:     "set is required",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "persisted state setup error",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				func(s *gcpCatalogPersistedState) error {
					return fmt.Errorf("error loading persisted state")
				},
			},
			expectedErr:     "error loading persisted state",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "nil attributes in set",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				NewSet: &hostsets.HostSet{},
			},
			expectedErr:     "set attributes are required",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "set attribute load error",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"foo": structpb.NewBoolValue(true),
								"bar": structpb.NewBoolValue(true),
							},
						},
					},
				},
			},
			expectedErr:     "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "invalid filter",
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
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("invalid"),
										},
									},
								),
							},
						},
					},
				},
			},
			expectedErr:     "error building filters",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "client load error",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			gcpOptions: []option.ClientOption{
				option.WithHTTPClient(&http.Client{}),
			},
			expectedErr:     "error getting instances client",
			expectedErrCode: codes.InvalidArgument,
		},
		{
			name: "List instances error",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				withTestInstancesAPIFunc(newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesError(fmt.Errorf("failed to list instances")),
				)),
			},
			expectedErr:     "gcp list instances failed",
			expectedErrCode: codes.FailedPrecondition,
		},
		{
			name: "success",
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
				Persisted: &pb.HostCatalogPersisted{
					Secrets: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							cred.ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
							cred.ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
							cred.ConstCredsLastRotatedTime: structpb.NewStringValue("2006-01-02T15:04:05+07:00"),
						},
					},
				},
				NewSet: &hostsets.HostSet{
					Attrs: &hostsets.HostSet_Attributes{
						Attributes: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								ConstListInstancesFilter: structpb.NewListValue(
									&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("tag-key=foo"),
										},
									},
								),
							},
						},
					},
				},
			},
			catalogOpts: []gcpCatalogPersistedStateOption{
				withTestInstancesAPIFunc(newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{}),
					testMockInstancesWithListInstancesError(nil)),
				),
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			testIAMAdminServer := cred.NewTestIAMAdminServer(nil, nil)

			gsrv := cred.NewGRPCServer()
			adminpb.RegisterIAMServer(gsrv.Server, testIAMAdminServer)
			addr, err := gsrv.Start()
			require.NoError(err)

			clientOptions := []option.ClientOption{
				option.WithEndpoint(addr),
				option.WithoutAuthentication(),
				option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
				option.WithTokenSource(nil),
			}

			clientOptions = append(clientOptions, tc.gcpOptions...)

			p := &HostPlugin{
				testGCPClientOpts:    clientOptions,
				testCatalogStateOpts: tc.catalogOpts,
			}
			_, err = p.OnUpdateSet(ctx, tc.req)
			if tc.expectedErr != "" {
				require.Contains(err.Error(), tc.expectedErr)
				require.Equal(status.Code(err).String(), tc.expectedErrCode.String())
				return
			}

			require.NoError(err)
		})
	}
}

func TestNormalizeSetData(t *testing.T) {
	ctx := context.Background()
	p := &HostPlugin{}

	cases := []struct {
		name                string
		req                 *pb.NormalizeSetDataRequest
		expectedRsp         *pb.NormalizeSetDataResponse
		expectedErrContains string
	}{
		{
			name: "nil attributes",
			req:  &pb.NormalizeSetDataRequest{},
			expectedRsp: &pb.NormalizeSetDataResponse{
				Attributes: nil,
			},
		},
		{
			name: "nil filters",
			req: &pb.NormalizeSetDataRequest{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{},
				},
			},
			expectedRsp: &pb.NormalizeSetDataResponse{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{},
				},
			},
		},
		{
			name: "filters not a string",
			req: &pb.NormalizeSetDataRequest{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"filters": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{
								structpb.NewStringValue("status = RUNNING"),
							},
						}),
					},
				},
			},
			expectedRsp: &pb.NormalizeSetDataResponse{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"filters": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{
								structpb.NewStringValue("status = RUNNING"),
							},
						}),
					},
				},
			},
		},
		{
			name: "filters is a string",
			req: &pb.NormalizeSetDataRequest{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"filters": structpb.NewStringValue("status = RUNNING"),
					},
				},
			},
			expectedRsp: &pb.NormalizeSetDataResponse{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"filters": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{
								structpb.NewStringValue("status = RUNNING"),
							},
						}),
					},
				},
			},
		},
		{
			name: "filters with multiple values",
			req: &pb.NormalizeSetDataRequest{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"filters": structpb.NewStringValue(`(cpuPlatform = "Intel Skylake") OR (cpuPlatform = "Intel Broadwell") AND (scheduling.automaticRestart = true)`),
					},
				},
			},
			expectedRsp: &pb.NormalizeSetDataResponse{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"filters": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{
								structpb.NewStringValue(`(cpuPlatform = "Intel Skylake") OR (cpuPlatform = "Intel Broadwell") AND (scheduling.automaticRestart = true)`),
							},
						}),
					},
				},
			},
		},
		{
			name: "filters is an number",
			req: &pb.NormalizeSetDataRequest{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"filters": structpb.NewNumberValue(1),
					},
				},
			},
			expectedErrContains: "attribute.filters must be a string or list",
		},
		{
			name: "filters is an boolean",
			req: &pb.NormalizeSetDataRequest{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"filters": structpb.NewBoolValue(true),
					},
				},
			},
			expectedErrContains: "attribute.filters must be a string or list",
		},
		{
			name: "filters is null",
			req: &pb.NormalizeSetDataRequest{
				Attributes: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"filters": structpb.NewNullValue(),
					},
				},
			},
			expectedErrContains: "attribute.filters must be a string or list",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			actual, err := p.NormalizeSetData(ctx, tc.req)
			if tc.expectedErrContains != "" {
				require.ErrorContains(err, tc.expectedErrContains)
				return
			}
			require.NoError(err)
			require.Empty(cmp.Diff(tc.expectedRsp, actual, protocmp.Transform()))
		})
	}
}
