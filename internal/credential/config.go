// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
	googleOption "google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Type int

const (
	// StaticGCP denotes the presence of an Private Key and Client Email.
	StaticGCP Type = iota

	// DynamicGCP denotes the presence of a Target Service Account Id.
	DynamicGCP

	// Unknown is a catch-all for everything else.
	Unknown
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

// serviceAccountTokenLifetime is the lifetime of the generated GCP authentication token.
// The token is valid for 1 hour.
const serviceAccountTokenLifetime = time.Hour

// Config is the configuration for the GCP credential.
type Config struct {
	ProjectId              string
	PrivateKey             string
	PrivateKeyId           string
	Zone                   string
	ClientEmail            string
	TargetServiceAccountId string
	Scopes                 []string
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

// clone returns a copy of the configuration.
func (c *Config) clone() *Config {
	return &Config{
		ProjectId:              c.ProjectId,
		PrivateKey:             c.PrivateKey,
		PrivateKeyId:           c.PrivateKeyId,
		ClientEmail:            c.ClientEmail,
		TargetServiceAccountId: c.TargetServiceAccountId,
		Scopes:                 c.Scopes,
	}
}

// GenerateCredentials generates GCP credentials based on the provided configuration.
// It supports Service Account Key, Service Account Impersonation, and ADC.
// If the credentials are already generated, it will return the cached credentials.
func (c *Config) GenerateCredentials(ctx context.Context) (*google.Credentials, error) {
	var creds *google.Credentials
	var err error

	switch {
	case c.PrivateKey != "" && c.ClientEmail != "" && c.TargetServiceAccountId != "":
		creds, err = c.credentialsFromImpersonation(ctx)
		if err != nil {
			return nil, status.Errorf(
				codes.Internal,
				"failed to generate credentials from service account impersonation: %v", err,
			)
		}
	case c.PrivateKey != "" && c.ClientEmail != "":
		creds, err = c.credentialsFromServiceAccountKey(ctx)
		if err != nil {
			return nil, status.Errorf(
				codes.Internal,
				"failed to generate credentials from service account key: %v", err,
			)
		}
	default:
		creds, err = c.credentialsFromADC(ctx)
		if err != nil {
			return nil, status.Errorf(
				codes.Internal,
				"failed to generate credentials from Application Default Credentials: %v", err,
			)
		}
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

// GetType returns the credential type based on the given
// current config.
func (c *Config) GetType() Type {
	if c == nil {
		return Unknown
	}

	switch {
	case len(c.TargetServiceAccountId) > 0 && len(c.PrivateKey) > 0 && len(c.ClientEmail) > 0:
		return DynamicGCP
	case len(c.PrivateKey) > 0 && len(c.ClientEmail) > 0:
		return StaticGCP
	default:
		return Unknown
	}
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
		Lifetime:        serviceAccountTokenLifetime,
	}, googleOption.WithCredentialsJSON(baseCredentialsJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create impersonated token source: %v", err)
	}

	return &google.Credentials{
		ProjectID:   projectId,
		TokenSource: ts,
	}, nil
}
