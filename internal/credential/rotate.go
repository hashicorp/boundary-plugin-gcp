// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	admin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// ComputeInstancesListPermission is the IAM permission required
	// to list compute instances.
	ComputeInstancesListPermission = "compute.instances.list"
	// IAMServiceAccountKeysCreatePermission is the IAM permission
	// required to create a service account key.
	// This permission is required to rotate service account keys.
	IAMServiceAccountKeysCreatePermission = "iam.serviceAccountKeys.create"
	// IAMServiceAccountKeysDeletePermission is the IAM permission
	// required to delete a service account key.
	// This permission is required to rotate service account keys.
	IAMServiceAccountKeysDeletePermission = "iam.serviceAccountKeys.delete"
)

// ServiceAccountPrivateKey represents a decoded PrivateKeyData
// from a Service Account Key.
// https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys#ServiceAccountKey
type ServiceAccountPrivateKey struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

// ValidateCredsCallback is called to validate the credentials after rotating the service account key.
// The callback should return an error if the credentials are invalid.
type ValidateCredsCallback func(*Config, ...option.ClientOption) error

// RotateServiceAccountKey takes the private key from this credentials config
// and first creates a new private key and private key id, then deletes the
// old private key.
//
// If deletion of the old private key is successful, the new private key and
// private key id are written into the credentials config and nil is returned.
// On any error, the old credentials are not overwritten.
func (c *Config) RotateServiceAccountKey(
	ctx context.Context,
	permissions []string,
	validateCredsCallback ValidateCredsCallback,
	opts ...option.ClientOption,
) error {
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
		Name:           fmt.Sprintf("projects/%s/serviceAccounts/%s", c.ProjectId, c.ClientEmail),
		PrivateKeyType: adminpb.ServiceAccountPrivateKeyType_TYPE_GOOGLE_CREDENTIALS_FILE,
		KeyAlgorithm:   adminpb.ServiceAccountKeyAlgorithm_KEY_ALG_RSA_2048,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "error creating service account key: %v", err)
	}

	var serviceAccountKey ServiceAccountPrivateKey
	err = json.Unmarshal(createServiceAccountKeyRes.PrivateKeyData, &serviceAccountKey)
	if err != nil {
		return status.Errorf(codes.Internal, "error unmarshalling service account key: %v", err)
	}

	// Clone the config, update the private key and private key ID with the new key.
	newConfig := c.clone()
	newConfig.PrivateKey = serviceAccountKey.PrivateKey
	newConfig.PrivateKeyId = serviceAccountKey.PrivateKeyID

	newCreds, err := newConfig.GenerateCredentials(ctx)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "error generating credentials: %v", err)
	}
	if newCreds.TokenSource == nil {
		return status.Error(codes.Unauthenticated, "error generating credentials: token source is nil")
	}
	clientOptions = []option.ClientOption{option.WithTokenSource(newCreds.TokenSource)}
	clientOptions = append(clientOptions, opts...)

	// Validate the new service account key
	err = newConfig.ValidateServiceAccountKey(ctx, permissions, validateCredsCallback, clientOptions...)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "error validating rotated service account key: %v", err)
	}

	iamClient, err = admin.NewIamClient(ctx, clientOptions...)
	if err != nil {
		return status.Errorf(codes.Internal, "error creating IAM client with rotated service account key: %v", err)
	}

	err = iamClient.DeleteServiceAccountKey(ctx, &adminpb.DeleteServiceAccountKeyRequest{
		Name: fmt.Sprintf("projects/%s/serviceAccounts/%s/keys/%s", c.ProjectId, c.ClientEmail, c.PrivateKeyId),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "error deleting service account key: %v", err)
	}

	c.PrivateKey = newConfig.PrivateKey
	c.PrivateKeyId = newConfig.PrivateKeyId

	return nil
}

// ValidateServiceAccountKey validates the service account key by checking the IAM permissions
// and calling the validation callback.
// The function will retry validation until the timeout is reached.
func (c *Config) ValidateServiceAccountKey(
	ctx context.Context,
	permissions []string,
	validateCredsCallback ValidateCredsCallback,
	opts ...option.ClientOption) error {
	var validatePermissionsErr error
	var validationCallbackErr error

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	ctx, cancel := context.WithTimeout(ctx, c.validateServiceAccountKeyTimeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("failed to validate service account key before timeout: %w", errors.Join(validatePermissionsErr, validationCallbackErr))
			}
			return ctx.Err()
		case <-ticker.C:
			_, validatePermissionsErr = c.ValidateIamPermissions(ctx, permissions, opts...)

			if validateCredsCallback != nil {
				validationCallbackErr = validateCredsCallback(c, opts...)
			}

			if validatePermissionsErr == nil && validationCallbackErr == nil {
				return nil
			}
		}
	}
}

func (c *Config) DeletePrivateKey(ctx context.Context, opts ...option.ClientOption) error {
	if c.PrivateKey == "" {
		return status.Error(codes.InvalidArgument, "cannot delete credentials when private key is not set")
	}
	if c.PrivateKeyId == "" {
		return status.Error(codes.InvalidArgument, "cannot delete credentials when private key ID is not set")
	}
	if c.ClientEmail == "" {
		return status.Error(codes.InvalidArgument, "cannot delete credentials when client email is not set")
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

	err = iamClient.DeleteServiceAccountKey(ctx, &adminpb.DeleteServiceAccountKeyRequest{
		Name: fmt.Sprintf("projects/%s/serviceAccounts/%s/keys/%s", c.ProjectId, c.ClientEmail, c.PrivateKeyId),
	})
	if err != nil {
		return status.Errorf(codes.Unknown, "error deleting service account key: %v", err)
	}

	return nil
}

// ValidateIamPermissions tests the IAM permissions for the credentials.
// It returns the granted permissions if successful.
func (c *Config) ValidateIamPermissions(ctx context.Context, permissions []string, opts ...option.ClientOption) ([]string, error) {
	if len(permissions) == 0 {
		return nil, status.Error(codes.InvalidArgument, "permissions are required")
	}

	rmClient, err := resourcemanager.NewProjectsClient(ctx, opts...)
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
