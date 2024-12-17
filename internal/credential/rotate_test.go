// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"errors"
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
			gsrv := NewGRPCServer()
			adminpb.RegisterIAMServer(gsrv.Server, testIAMAdminServer)
			resourcemanagerpb.RegisterProjectsServer(gsrv.Server, testResourceServer)
			addr, err := gsrv.Start()
			require.NoError(t, err)

			ctx := context.Background()
			if tt.setup != nil {
				tt.setup()
			}
			testOptions := []googleOption.ClientOption{
				googleOption.WithEndpoint(addr),
				googleOption.WithoutAuthentication(),
				googleOption.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
				googleOption.WithTokenSource(nil),
			}
			initialPrivateKey := tt.config.PrivateKey
			initialPrivateKeyId := tt.config.PrivateKeyId
			initialClientEmail := tt.config.ClientEmail

			permissions := []string{
				ComputeInstancesListPermission,
				IAMServiceAccountKeysCreatePermission,
				IAMServiceAccountKeysDeletePermission,
			}
			validateCredsCallbackCalled := false

			validateCredsCallBack := func(c *Config, opts ...googleOption.ClientOption) error {
				validateCredsCallbackCalled = true
				return nil
			}

			err = tt.config.RotateServiceAccountKey(ctx, permissions, validateCredsCallBack, testOptions...)
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
			require.True(t, validateCredsCallbackCalled)
		})
	}
}

func TestValidateIamPermissions(t *testing.T) {
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

			gsrv := NewGRPCServer()
			resourcemanagerpb.RegisterProjectsServer(gsrv.Server, testResourceServer)
			addr, err := gsrv.Start()
			require.NoError(t, err)

			testOptions := []googleOption.ClientOption{
				googleOption.WithEndpoint(addr),
				googleOption.WithoutAuthentication(),
				googleOption.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
				googleOption.WithTokenSource(nil),
			}
			permissions, err := tt.config.ValidateIamPermissions(ctx, tt.permissions, testOptions...)
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
func TestDeletePrivateKey(t *testing.T) {
	testIAMAdminServer := &testIAMAdminServer{}

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
			expectedError: status.Error(codes.InvalidArgument, "cannot delete credentials when private key is not set"),
		},
		{
			name: "PrivateKeyId is empty",
			config: &Config{
				PrivateKey:   "some-private-key",
				PrivateKeyId: "",
			},
			expectedError: status.Error(codes.InvalidArgument, "cannot delete credentials when private key ID is not set"),
		},
		{
			name: "ClientEmail is empty",
			config: &Config{
				PrivateKey:   "some-private-key",
				PrivateKeyId: "some-private-key-id",
				ClientEmail:  "",
			},
			expectedError: status.Error(codes.InvalidArgument, "cannot delete credentials when client email is not set"),
		},
		{
			name: "GenerateCredentials returns error",
			config: &Config{
				PrivateKey:             "some-private-key",
				PrivateKeyId:           "some-private-key-id",
				ClientEmail:            "client@example.com",
				TargetServiceAccountId: "test-service-account-id",
			},
			expectedError: status.Errorf(codes.Unauthenticated, "error generating credentials"),
		},
		{
			name: "DeleteServiceAccountKey returns error",
			config: &Config{
				PrivateKey:   "some-private-key",
				PrivateKeyId: "some-private-key-id",
				ClientEmail:  "client@example.com",
			},
			setup: func() {
				testIAMAdminServer.testDeleteServiceAccountKeyError = errors.New("delete key error")
			},
			expectedError: status.Errorf(codes.Unknown, "error deleting service account key"),
		},
		{
			name: "Successful deletion",
			config: &Config{
				PrivateKey:   "some-private-key",
				PrivateKeyId: "some-private-key-id",
				ClientEmail:  "client@example.com",
			},
			setup: func() {
				testIAMAdminServer.testDeleteServiceAccountKeyError = nil
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gsrv := NewGRPCServer()
			adminpb.RegisterIAMServer(gsrv.Server, testIAMAdminServer)
			addr, err := gsrv.Start()
			require.NoError(t, err)

			ctx := context.Background()
			if tt.setup != nil {
				tt.setup()
			}
			testOptions := []googleOption.ClientOption{
				googleOption.WithEndpoint(addr),
				googleOption.WithoutAuthentication(),
				googleOption.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
				googleOption.WithTokenSource(nil),
			}

			err = tt.config.DeletePrivateKey(ctx, testOptions...)
			if tt.expectedError != nil {
				require.ErrorContains(t, err, tt.expectedError.Error())
				return
			}

			require.NoError(t, err)
		})
	}
}
