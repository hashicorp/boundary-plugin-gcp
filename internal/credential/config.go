// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
	googleOption "google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// impersonateServiceAccount is a function variable that creates a TokenSource
var impersonateServiceAccountFn = func(
	ctx context.Context,
	config impersonate.CredentialsConfig,
	opts ...googleOption.ClientOption,
) (oauth2.TokenSource, error) {
	return impersonate.CredentialsTokenSource(ctx, config, opts...)
}

// findDefaultCredentialsFn is a function variable that finds the default credentials
var findDefaultCredentialsFn = func(ctx context.Context, scopes ...string) (*google.Credentials, error) {
	return google.FindDefaultCredentials(ctx, scopes...)
}

// Config is the configuration for the GCP credential.
type Config struct {
	ProjectId              string
	PrivateKey             string
	PrivateKeyId           string
	ClientEmail            string
	TargetServiceAccountId string
	Scopes                 []string
	Client                 *http.Client
}

// credentials represents a simplified version of the GCP credentials file format.
type credentials struct {
	ClientEmail  string `json:"client_email"`
	Type         string `json:"type"`
	ProjectId    string `json:"project_id"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyId string `json:"private_key_id"`
}

// toCredentials converts the config to credentials.
func (c *Config) toCredentials() *credentials {
	return &credentials{
		Type:         "service_account",
		ProjectId:    c.ProjectId,
		PrivateKey:   c.PrivateKey,
		PrivateKeyId: c.PrivateKeyId,
		ClientEmail:  c.ClientEmail,
	}
}

// GetClient returns the client for the configuration.
// The client is a *http.Client which is created with GCP credentials.
// The returned client is not valid beyond the lifetime of the context.
//
// If the client is not set, it will generate the client.
func (c *Config) GetClient(ctx context.Context) (*http.Client, error) {
	if c.Client == nil {
		creds, err := c.generateCredentials(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "error getting credentials: %v", err)
		}
		c.Client = oauth2.NewClient(ctx, creds.TokenSource)
	}
	return c.Client, nil
}

// generateCredentials generates GCP credentials based on the provided configuration.
// It supports Service Account Key, Service Account Impersonation, and ADC.
func (c *Config) generateCredentials(ctx context.Context) (*google.Credentials, error) {
	var creds *google.Credentials
	var err error

	switch {
	case c.PrivateKey != "" && c.ClientEmail != "" && c.TargetServiceAccountId != "":
		creds, err = c.credentialsFromImpersonation(ctx)
	case c.PrivateKey != "" && c.ClientEmail != "":
		creds, err = c.credentialsFromServiceAccountKey(ctx)
	default:
		creds, err = c.credentialsFromADC(ctx)
	}

	if err != nil {
		return nil, err
	}

	return creds, nil
}

// credentialsFromServiceAccountKey generates the credentials from the service account key.
func (c *Config) credentialsFromServiceAccountKey(ctx context.Context) (*google.Credentials, error) {
	if c.PrivateKey == "" {
		return nil, status.Error(codes.InvalidArgument, "private_key is required")
	}
	if c.ClientEmail == "" {
		return nil, status.Error(codes.InvalidArgument, "client_email is required")
	}

	credBytes, err := json.Marshal(c.toCredentials())
	if err != nil {
		return nil, status.Error(codes.Internal, "error marshaling credentials")
	}
	creds, err := google.CredentialsFromJSON(ctx, credBytes, c.Scopes...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse credentials: %v", err)
	}
	return creds, nil
}

// credentialsFromImpersonation generates the credentials from the impersonation.
func (c *Config) credentialsFromImpersonation(ctx context.Context) (*google.Credentials, error) {
	if c.PrivateKey == "" {
		return nil, status.Error(codes.InvalidArgument, "private_key is required")
	}
	if c.ClientEmail == "" {
		return nil, status.Error(codes.InvalidArgument, "client_email is required")
	}
	if c.TargetServiceAccountId == "" {
		return nil, status.Error(codes.InvalidArgument, "target_service_account_id is required")
	}

	credBytes, err := json.Marshal(c.toCredentials())
	if err != nil {
		return nil, status.Error(codes.Internal, "error marshaling credentials")
	}
	creds, err := impersonateServiceAccount(ctx, c.ProjectId, credBytes, c.TargetServiceAccountId, c.Scopes)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error impersonating service account: %v", err)
	}
	return creds, nil
}

// credentialsFromADC generates the credentials from the Application Default Credentials (ADC).
func (c *Config) credentialsFromADC(ctx context.Context) (*google.Credentials, error) {
	creds, err := findDefaultCredentialsFn(ctx, c.Scopes...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to find default credentials: %v", err)
	}
	return creds, nil
}

// impersonateServiceAccount impersonates the service account.
// This is used to impersonate the service account to generate an access token.
func impersonateServiceAccount(
	ctx context.Context,
	projectId string,
	baseCredentialsJSON []byte,
	targetServiceAccountId string,
	scopes []string,
) (*google.Credentials, error) {
	if baseCredentialsJSON == nil {
		return nil, status.Error(codes.InvalidArgument, "base_service_account is required")
	}
	if targetServiceAccountId == "" {
		return nil, status.Error(codes.InvalidArgument, "target_service_account_id is required")
	}
	if len(scopes) == 0 {
		return nil, status.Error(codes.InvalidArgument, "scope is required")
	}

	ts, err := impersonateServiceAccountFn(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: targetServiceAccountId,
		Scopes:          scopes,
		Lifetime:        time.Hour,
	}, googleOption.WithCredentialsJSON(baseCredentialsJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create impersonated token source: %v", err)
	}

	return &google.Credentials{
		ProjectID:   projectId,
		TokenSource: ts,
	}, nil
}
