// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
	googleOption "google.golang.org/api/option"
)

func TestGenerateCredentials(t *testing.T) {
	ctx := context.Background()

	testImpersonateServiceFn := func(ctx context.Context, config impersonate.CredentialsConfig, opts ...googleOption.ClientOption) (oauth2.TokenSource, error) {
		return oauth2.StaticTokenSource(&oauth2.Token{}), nil
	}
	impersonateServiceAccountFn = testImpersonateServiceFn

	const fakePrivateKey = `-----BEGIN PRIVATE KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA1y+Vmxg1hK6j0ef6
-----END PRIVATE KEY-----`

	tests := []struct {
		name        string
		config      *Config
		wantErr     bool
		expectedErr string
	}{
		{
			name: "Service Account Key Authentication",
			config: &Config{
				PrivateKey:   fakePrivateKey,
				ClientEmail:  "test_email@example.com",
				ProjectId:    "test_project",
				PrivateKeyId: "test_key_id",
			},
			wantErr: false,
		},
		{
			name: "Service Account Impersonation",
			config: &Config{
				PrivateKey:             fakePrivateKey,
				ClientEmail:            "test_email@example.com",
				ProjectId:              "test_project",
				PrivateKeyId:           "test_key_id",
				TargetServiceAccountId: "target_service_account@example.com",
				Scopes:                 []string{"test_scope"},
			},
			wantErr: false,
		},
		{
			name:        "Application Default Credentials",
			config:      &Config{},
			wantErr:     true, // Since ADC might not be available in test environment
			expectedErr: "failed to find default credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := tt.config.generateCredentials(ctx)
			if tt.wantErr {
				require.ErrorContains(t, err, tt.expectedErr)
				require.Nil(t, creds)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, creds)
			require.Equal(t, tt.config.ProjectId, creds.ProjectID)
		})
	}
}

func TestGetClient(t *testing.T) {
	ctx := context.Background()

	config := &Config{
		PrivateKey:   "test_private_key",
		ClientEmail:  "test_email@example.com",
		ProjectId:    "test_project",
		PrivateKeyId: "test_key_id",
	}

	client, err := config.GetClient(ctx)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Call GetClient again to ensure the cached client is returned
	cachedClient, err := config.GetClient(ctx)
	require.NoError(t, err)
	require.Equal(t, client, cachedClient)
}

func TestCredentialsFromServiceAccountKey(t *testing.T) {
	ctx := context.Background()

	// Define a fake but correctly formatted PEM-encoded private key.
	const fakePrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
-----END PRIVATE KEY-----`

	// Test cases
	tests := []struct {
		name        string
		config      *Config
		wantErr     bool
		expectedErr string
	}{
		{
			name: "Successful Credential Generation",
			config: &Config{
				PrivateKey:   fakePrivateKey,
				ClientEmail:  "test-email@example.com",
				ProjectId:    "test-project-id",
				PrivateKeyId: "test-private-key-id",
			},
			wantErr: false,
		},
		{
			name: "Missing Private Key",
			config: &Config{
				ClientEmail:  "test-email@example.com",
				ProjectId:    "test-project-id",
				PrivateKeyId: "test-private-key-id",
			},
			wantErr:     true,
			expectedErr: "private_key is required",
		},
		{
			name: "Missing Client Email",
			config: &Config{
				PrivateKey:   fakePrivateKey,
				ProjectId:    "test-project-id",
				PrivateKeyId: "test-private-key-id",
			},
			wantErr:     true,
			expectedErr: "client_email is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := tt.config.credentialsFromServiceAccountKey(ctx)
			if tt.wantErr {
				require.ErrorContains(t, err, tt.expectedErr)
				require.Nil(t, creds)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, creds)
		})
	}
}

func TestCredentialsFromADC(t *testing.T) {
	ctx := context.Background()

	mockTokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "mock_access_token",
	})

	tests := []struct {
		name                string
		mockFindDefaultCred func(ctx context.Context, scopes ...string) (*google.Credentials, error)
		wantErr             bool
		expectedErr         string
	}{
		{
			name: "Successful ADC Retrieval",
			mockFindDefaultCred: func(ctx context.Context, scopes ...string) (*google.Credentials, error) {
				return &google.Credentials{
					ProjectID:   "test-project-id",
					TokenSource: mockTokenSource,
				}, nil
			},
			wantErr: false,
		},
		{
			name: "ADC Not Available",
			mockFindDefaultCred: func(ctx context.Context, scopes ...string) (*google.Credentials, error) {
				return nil, errors.New("ADC not available")
			},
			wantErr:     true,
			expectedErr: "failed to find default credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Override findDefaultCredentials with the mock implementation.
			findDefaultCredentialsFn = tt.mockFindDefaultCred

			config := &Config{}

			creds, err := config.credentialsFromADC(ctx)
			if tt.wantErr {
				require.ErrorContains(t, err, tt.expectedErr)
				require.Nil(t, creds)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, creds)
			require.Equal(t, "test-project-id", creds.ProjectID, "Expected the project ID to be 'test-project-id'")
			require.Equal(t, mockTokenSource, creds.TokenSource, "Expected the mock token source")
		})
	}
}

func TestCredentialsFromImpersonation(t *testing.T) {
	ctx := context.Background()

	// Define a fake but correctly formatted PEM-encoded private key.
	const fakePrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
-----END PRIVATE KEY-----`

	testImpersonateServiceFn := func(ctx context.Context, config impersonate.CredentialsConfig, opts ...googleOption.ClientOption) (oauth2.TokenSource, error) {
		return oauth2.StaticTokenSource(&oauth2.Token{}), nil
	}
	impersonateServiceAccountFn = testImpersonateServiceFn

	tests := []struct {
		name                            string
		config                          *Config
		mockImpersonateServiceAccountFn func(ctx context.Context, config impersonate.CredentialsConfig, opts ...googleOption.ClientOption) (oauth2.TokenSource, error)
		wantErr                         bool
		expectedErr                     string
	}{
		{
			name: "Successful Impersonation",
			config: &Config{
				PrivateKey:             fakePrivateKey,
				ClientEmail:            "test-email@example.com",
				ProjectId:              "test-project-id",
				PrivateKeyId:           "test-private-key-id",
				TargetServiceAccountId: "target-service-account@example.com",
				Scopes:                 []string{"test-scope"},
			},
			mockImpersonateServiceAccountFn: func(ctx context.Context, config impersonate.CredentialsConfig, opts ...googleOption.ClientOption) (oauth2.TokenSource, error) {
				return oauth2.StaticTokenSource(&oauth2.Token{}), nil
			},
			wantErr: false,
		},
		{
			name: "Error during Impersonation",
			config: &Config{
				PrivateKey:             fakePrivateKey,
				ClientEmail:            "test-email@example.com",
				ProjectId:              "test-project-id",
				PrivateKeyId:           "test-private-key-id",
				TargetServiceAccountId: "target-service-account@example.com",
				Scopes:                 []string{"test-scope"},
			},
			mockImpersonateServiceAccountFn: func(ctx context.Context, config impersonate.CredentialsConfig, opts ...googleOption.ClientOption) (oauth2.TokenSource, error) {
				return nil, errors.New("mock impersonation error")
			},
			wantErr:     true,
			expectedErr: "failed to create impersonated token source",
		},
		{
			name: "Missing Private Key",
			config: &Config{
				ClientEmail:            "test-email@example.com",
				ProjectId:              "test-project-id",
				PrivateKeyId:           "test-private-key-id",
				TargetServiceAccountId: "target-service-account@example.com",
			},
			wantErr:     true,
			expectedErr: "private_key is required",
		},
		{
			name: "Missing Client Email",
			config: &Config{
				PrivateKey:             fakePrivateKey,
				ProjectId:              "test-project-id",
				PrivateKeyId:           "test-private-key-id",
				TargetServiceAccountId: "target-service-account@example.com",
			},
			mockImpersonateServiceAccountFn: nil,
			wantErr:                         true,
			expectedErr:                     "client_email is required",
		},
		{
			name: "Missing Target Service Account ID",
			config: &Config{
				PrivateKey:   fakePrivateKey,
				ClientEmail:  "test-email@example.com",
				ProjectId:    "test-project-id",
				PrivateKeyId: "test-private-key-id",
			},
			mockImpersonateServiceAccountFn: nil,
			wantErr:                         true,
			expectedErr:                     "target_service_account_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockImpersonateServiceAccountFn != nil {
				impersonateServiceAccountFn = tt.mockImpersonateServiceAccountFn
			}

			creds, err := tt.config.credentialsFromImpersonation(ctx)
			if tt.wantErr {
				require.ErrorContains(t, err, tt.expectedErr)
				require.Nil(t, creds)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, creds)
			require.Equal(t, tt.config.ProjectId, creds.ProjectID)

			token, err := creds.TokenSource.Token()
			require.NoError(t, err)
			require.NotNil(t, token)
		})
	}
}
