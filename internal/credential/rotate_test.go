// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"github.com/stretchr/testify/require"
	googleOption "google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestRotateServiceAccountKey(t *testing.T) {
	testIAMAdminServer := &testIAMAdminServer{}
	testResourceServer := &testResourceServer{
		testIamPermissionsResponse: &iampb.TestIamPermissionsResponse{
			Permissions: []string{
				ComputeInstancesListPermission,
				IAMServiceAccountKeysCreatePermission,
				IAMServiceAccountKeysDeletePermission,
			},
		},
	}

	tests := []struct {
		name          string
		config        *Config
		setup         func()
		expectedError error
	}{
		{
			name: "PrivateKey is empty",
			config: &Config{
				PrivateKey: "",
			},
			expectedError: status.Error(codes.InvalidArgument, "cannot rotate credentials when private key is not set"),
		},
		{
			name: "PrivateKeyId is empty",
			config: &Config{
				PrivateKey:   "some-private-key",
				PrivateKeyId: "",
			},
			expectedError: status.Error(codes.InvalidArgument, "cannot rotate credentials when private key ID is not set"),
		},
		{
			name: "ClientEmail is empty",
			config: &Config{
				PrivateKey:   "some-private-key",
				PrivateKeyId: "some-private-key-id",
				ClientEmail:  "",
			},
			expectedError: status.Error(codes.InvalidArgument, "cannot rotate credentials when client email is not set"),
		},
		{
			name: "CreateServiceAccountKey returns error",
			config: &Config{
				PrivateKey:   "some-private-key",
				PrivateKeyId: "some-private-key-id",
				ClientEmail:  "client@example.com",
			},
			setup: func() {
				testIAMAdminServer.testCreateServiceAccountKeyError = errors.New("create key error")
			},
			expectedError: errors.New("create key error"),
		},
		{
			name: "DeleteServiceAccountKey returns error",
			config: &Config{
				PrivateKey:   "some-private-key",
				PrivateKeyId: "some-private-key-id",
				ClientEmail:  "client@example.com",
			},
			setup: func() {
				testIAMAdminServer.testCreateServiceAccountKeyError = nil
				testIAMAdminServer.testDeleteServiceAccountKeyError = errors.New("delete key error")
			},
			expectedError: errors.New("delete key error"),
		},
		{
			name: "Successful rotation",
			config: &Config{
				PrivateKey:   "some-private-key",
				PrivateKeyId: "some-private-key-id",
				ClientEmail:  "client@example.com",
			},
			setup: func() {
				testIAMAdminServer.testCreateServiceAccountKeyError = nil
				testIAMAdminServer.testDeleteServiceAccountKeyError = nil
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gsrv := newGRPCServer()
			adminpb.RegisterIAMServer(gsrv.Server, testIAMAdminServer)
			resourcemanagerpb.RegisterProjectsServer(gsrv.Server, testResourceServer)
			addr, err := gsrv.serve()
			require.NoError(t, err)

			ctx := context.Background()
			if tt.setup != nil {
				tt.setup()
			}
			testOptions := WithTestGoogleOptions([]googleOption.ClientOption{
				googleOption.WithEndpoint(addr),
				googleOption.WithoutAuthentication(),
				googleOption.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
			})
			initialPrivateKey := tt.config.PrivateKey
			initialPrivateKeyId := tt.config.PrivateKeyId
			initialClientEmail := tt.config.ClientEmail

			permissions := []string{
				ComputeInstancesListPermission,
				IAMServiceAccountKeysCreatePermission,
				IAMServiceAccountKeysDeletePermission,
			}

			err = tt.config.RotateServiceAccountKey(ctx, permissions, testOptions)
			if tt.expectedError != nil {
				require.ErrorContains(t, err, tt.expectedError.Error())
				require.Equal(t, initialClientEmail, tt.config.ClientEmail)
				require.Equal(t, initialPrivateKey, tt.config.PrivateKey)
				require.Equal(t, initialPrivateKeyId, tt.config.PrivateKeyId)
				return
			}

			require.Equal(t, initialClientEmail, tt.config.ClientEmail)
			require.NotEmpty(t, tt.config.PrivateKey)
			require.NotEmpty(t, tt.config.PrivateKeyId)
			require.NotEqual(t, initialPrivateKey, tt.config.PrivateKey)
			require.NotEqual(t, initialPrivateKeyId, tt.config.PrivateKeyId)
		})
	}
}

func TestTestIamPermissions(t *testing.T) {
	ctx := context.Background()
	testResourceServer := &testResourceServer{}

	tests := []struct {
		name                    string
		config                  *Config
		testIamResponse         *iampb.TestIamPermissionsResponse
		testIamPermissionsError error
		permissions             []string
		wantErr                 bool
		expectedErr             string
		expectedPermissions     []string
	}{
		{
			name: "Successful IAM Permissions Test",
			config: &Config{
				ProjectId:   "test-project-id",
				PrivateKey:  "test-private-key",
				ClientEmail: "test@test.com",
			},
			testIamResponse: &iampb.TestIamPermissionsResponse{
				Permissions: []string{"permission1", "permission2"},
			},
			permissions:         []string{"permission1", "permission2"},
			expectedPermissions: []string{"permission1", "permission2"},
		},
		{
			name: "Missing Permissions",
			config: &Config{
				ProjectId:  "test-project-id",
				PrivateKey: "test-private-key",
			},
			wantErr:     true,
			expectedErr: "permissions are required",
		},
		{
			name: "Failed to Generate Credentials",
			config: &Config{
				ProjectId:  "test-project-id",
				PrivateKey: "test-private-key",
			},
			permissions: []string{"permission1", "permission2"},
			wantErr:     true,
			expectedErr: "failed to generate credentials",
		},
		{
			name: "Failed to Test IAM Permissions",
			config: &Config{
				ProjectId:   "test-project-id",
				PrivateKey:  "test-private-key",
				ClientEmail: "test@test.com",
			},
			testIamPermissionsError: errors.New("failed to test IAM permissions"),
			permissions:             []string{"permission1", "permission2"},
			wantErr:                 true,
			expectedErr:             "failed to test IAM permissions",
		},
		{
			name: "No Permissions Granted",
			config: &Config{
				ProjectId:   "test-project-id",
				PrivateKey:  "test-private-key",
				ClientEmail: "test@test.com",
			},
			testIamResponse: &iampb.TestIamPermissionsResponse{
				Permissions: []string{},
			},
			testIamPermissionsError: nil,
			permissions:             []string{"permission1", "permission2"},
			wantErr:                 true,
			expectedErr:             "no permissions granted",
		},
		{
			name: "Missing Permissions",
			config: &Config{
				ProjectId:   "test-project-id",
				PrivateKey:  "test-private-key",
				ClientEmail: "test@test.com",
			},
			testIamResponse: &iampb.TestIamPermissionsResponse{
				Permissions: []string{"permission1"},
			},
			testIamPermissionsError: nil,
			permissions:             []string{"permission1", "permission2"},
			wantErr:                 true,
			expectedErr:             "missing permissions: [permission2]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testResourceServer.testIamPermissionsResponse = tt.testIamResponse
			testResourceServer.testIamPermissionsError = tt.testIamPermissionsError

			gsrv := newGRPCServer()
			resourcemanagerpb.RegisterProjectsServer(gsrv.Server, testResourceServer)
			addr, err := gsrv.serve()
			require.NoError(t, err)

			testOptions := WithTestGoogleOptions([]googleOption.ClientOption{
				googleOption.WithEndpoint(addr),
				googleOption.WithoutAuthentication(),
				googleOption.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
			})
			permissions, err := tt.config.TestIamPermissions(ctx, tt.permissions, testOptions)
			if tt.wantErr {
				require.ErrorContains(t, err, tt.expectedErr)
				require.Nil(t, permissions)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedPermissions, permissions)
		})
	}
}

type testIAMAdminServer struct {
	adminpb.UnimplementedIAMServer
	testCreateServiceAccountKeyError error
	testDeleteServiceAccountKeyError error
}

func (f *testIAMAdminServer) CreateServiceAccountKey(ctx context.Context, req *adminpb.CreateServiceAccountKeyRequest) (*adminpb.ServiceAccountKey, error) {
	resp := &adminpb.ServiceAccountKey{
		Name:           "projects/-/serviceAccounts/1234/keys/updated-private-key-id",
		PrivateKeyData: []byte("updated-private-key"),
	}
	return resp, f.testCreateServiceAccountKeyError
}

func (f *testIAMAdminServer) DeleteServiceAccountKey(ctx context.Context, req *adminpb.DeleteServiceAccountKeyRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, f.testDeleteServiceAccountKeyError
}

type testResourceServer struct {
	resourcemanagerpb.UnimplementedProjectsServer
	testIamPermissionsResponse *iampb.TestIamPermissionsResponse
	testIamPermissionsError    error
}

func (f *testResourceServer) TestIamPermissions(context.Context, *iampb.TestIamPermissionsRequest) (*iampb.TestIamPermissionsResponse, error) {
	return f.testIamPermissionsResponse, f.testIamPermissionsError
}

type grpcServer struct {
	*grpc.Server
}

func newGRPCServer() *grpcServer {
	return &grpcServer{Server: grpc.NewServer()}
}

func (s *grpcServer) serve() (string, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", fmt.Errorf("failed to listen: %v", err)
	}
	go func() {
		if err := s.Serve(l); err != nil {
			panic(err)
		}
	}()
	return l.Addr().String(), nil
}
