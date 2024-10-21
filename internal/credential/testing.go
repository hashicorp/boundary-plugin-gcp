// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"fmt"
	"net"

	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type testIAMAdminServer struct {
	adminpb.UnimplementedIAMServer
	testCreateServiceAccountKeyError error
	testDeleteServiceAccountKeyError error
}

func NewTestIAMAdminServer(createServiceAccountKeyError error, deleteServiceAccountKeyError error) *testIAMAdminServer {
	return &testIAMAdminServer{
		testCreateServiceAccountKeyError: createServiceAccountKeyError,
		testDeleteServiceAccountKeyError: deleteServiceAccountKeyError,
	}
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

func NewTestResourceServer(testIamPermissionsResponse *iampb.TestIamPermissionsResponse, testIamPermissionsError error) *testResourceServer {
	return &testResourceServer{
		testIamPermissionsResponse: testIamPermissionsResponse,
		testIamPermissionsError:    testIamPermissionsError,
	}
}

func (f *testResourceServer) TestIamPermissions(context.Context, *iampb.TestIamPermissionsRequest) (*iampb.TestIamPermissionsResponse, error) {
	return f.testIamPermissionsResponse, f.testIamPermissionsError
}

type grpcServer struct {
	*grpc.Server
}

func NewGRPCServer() *grpcServer {
	return &grpcServer{Server: grpc.NewServer()}
}

func (s *grpcServer) Start() (string, error) {
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
