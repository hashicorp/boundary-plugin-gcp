// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"slices"

	admin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	ComputeInstancesListPermission        = "compute.instances.list"
	IAMServiceAccountKeysCreatePermission = "iam.serviceAccountKeys.create"
	IAMServiceAccountKeysDeletePermission = "iam.serviceAccountKeys.delete"
	CreateServiceAccountKeyResourceName   = "projects/-/serviceAccounts"
)

// RotateServiceAccountKey takes the private key from this credentials config
// and first creates a new private key and private key id, then deletes the
// old private key.
//
// If deletion of the old private key is successful, the new private key and
// private key id are written into the credentials config and nil is returned.
// On any error, the old credentials are not overwritten.
func (c *Config) RotateServiceAccountKey(ctx context.Context, permissions []string, opts ...option.ClientOption) error {
	if c.PrivateKey == "" {
		return status.Error(codes.InvalidArgument, "cannot rotate credentials when private key is not set")
	}
	if c.PrivateKeyId == "" {
		return status.Error(codes.InvalidArgument, "cannot rotate credentials when private key ID is not set")
	}
	if c.ClientEmail == "" {
		return status.Error(codes.InvalidArgument, "cannot rotate credentials when client email is not set")
	}

	creds, err := c.GenerateCredentials(ctx)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "error generating credentials: %v", err)
	}
	if creds.TokenSource == nil {
		return status.Error(codes.Unauthenticated, "error generating credentials: token source is nil")
	}

	clientOptions := []option.ClientOption{option.WithTokenSource(creds.TokenSource)}
	clientOptions = append(clientOptions, opts...)

	iamClient, err := admin.NewIamClient(ctx, clientOptions...)
	if err != nil {
		return status.Errorf(codes.Internal, "error creating IAM client: %v", err)
	}

	createServiceAccountKeyRes, err := iamClient.CreateServiceAccountKey(ctx, &adminpb.CreateServiceAccountKeyRequest{
		Name:           fmt.Sprintf("%s/%s", CreateServiceAccountKeyResourceName, c.ClientEmail),
		PrivateKeyType: adminpb.ServiceAccountPrivateKeyType_TYPE_GOOGLE_CREDENTIALS_FILE,
		KeyAlgorithm:   adminpb.ServiceAccountKeyAlgorithm_KEY_ALG_RSA_2048,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "error creating service account key: %v", err)
	}

	privateKeyId, err := getPrivateKeyIdFromName(createServiceAccountKeyRes.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "error parsing private key ID: %v", err)
	}

	// Clone the config, update the private key and private key ID with the new key.
	newConfig := c.clone()
	newConfig.PrivateKey = string(createServiceAccountKeyRes.PrivateKeyData)
	newConfig.PrivateKeyId = privateKeyId

	newCreds, err := newConfig.GenerateCredentials(ctx)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "error generating credentials: %v", err)
	}
	if newCreds.TokenSource == nil {
		return status.Error(codes.Unauthenticated, "error generating credentials: token source is nil")
	}
	clientOptions = []option.ClientOption{option.WithTokenSource(newCreds.TokenSource)}
	clientOptions = append(clientOptions, opts...)

	// Validate that the new credentials have the necessary permissions.
	_, err = newConfig.ValidateIamPermissions(ctx, permissions, clientOptions...)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "error testing IAM permissions with rotated service account key: %v", err)
	}

	iamClient, err = admin.NewIamClient(ctx, clientOptions...)
	if err != nil {
		return status.Errorf(codes.Internal, "error creating IAM client with rotated service account key: %v", err)
	}

	err = iamClient.DeleteServiceAccountKey(ctx, &adminpb.DeleteServiceAccountKeyRequest{
		Name: fmt.Sprintf("%s/%s/keys/%s", CreateServiceAccountKeyResourceName, c.ClientEmail, c.PrivateKeyId),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "error deleting service account key: %v", err)
	}

	c.PrivateKey = newConfig.PrivateKey
	c.PrivateKeyId = newConfig.PrivateKeyId

	return nil
}

// ValidateIamPermissions tests the IAM permissions for the credentials.
// It returns the granted permissions if successful.
func (c *Config) ValidateIamPermissions(ctx context.Context, permissions []string, opts ...option.ClientOption) ([]string, error) {
	if len(permissions) == 0 {
		return nil, status.Error(codes.InvalidArgument, "permissions are required")
	}

	creds, err := c.GenerateCredentials(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "error generating credentials: %v", err)
	}
	if creds.TokenSource == nil {
		return nil, status.Error(codes.Unauthenticated, "error generating credentials: token source is nil")
	}

	clientOptions := []option.ClientOption{option.WithTokenSource(creds.TokenSource)}
	clientOptions = append(clientOptions, opts...)

	rmClient, err := resourcemanager.NewProjectsClient(ctx, clientOptions...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create Resource Manager client: %v", err)
	}

	resp, err := rmClient.TestIamPermissions(ctx, &iampb.TestIamPermissionsRequest{
		Resource:    "projects/" + c.ProjectId,
		Permissions: permissions,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to validate IAM permissions: %v", err)
	}

	if len(resp.Permissions) == 0 {
		return nil, status.Error(codes.PermissionDenied, "no permissions granted")
	}

	if len(resp.Permissions) != len(permissions) {
		missingPermissions := make([]string, 0, len(permissions))
		for _, permission := range permissions {
			found := slices.Contains(resp.Permissions, permission)
			if !found {
				missingPermissions = append(missingPermissions, permission)
			}
		}
		return nil, status.Errorf(codes.PermissionDenied, "missing permissions: %v", missingPermissions)
	}

	return resp.Permissions, nil
}

// getPrivateKeyIdFromName extracts the private key ID from the name of a service account key.
func getPrivateKeyIdFromName(input string) (string, error) {
	lastSlashIndex := strings.LastIndex(input, "/")
	if lastSlashIndex != -1 {
		return input[lastSlashIndex+1:], nil
	}
	return "", fmt.Errorf("could not find private key ID in %s", input)
}
