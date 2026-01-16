// Copyright IBM Corp. 2024, 2025
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
			creds, err := tt.config.GenerateCredentials(ctx)
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

func TestClone(t *testing.T) {
	originalConfig := &Config{
		ProjectId:              "original-project-id",
		PrivateKey:             "original-private-key",
		PrivateKeyId:           "original-private-key-id",
		ClientEmail:            "original-client-email@example.com",
		TargetServiceAccountId: "original-target-service-account-id",
		Scopes:                 []string{"scope1", "scope2"},
	}

	clonedConfig := originalConfig.clone()

	require.NotNil(t, clonedConfig)
	require.Equal(t, originalConfig.ProjectId, clonedConfig.ProjectId)
	require.Equal(t, originalConfig.PrivateKey, clonedConfig.PrivateKey)
	require.Equal(t, originalConfig.PrivateKeyId, clonedConfig.PrivateKeyId)
	require.Equal(t, originalConfig.ClientEmail, clonedConfig.ClientEmail)
	require.Equal(t, originalConfig.TargetServiceAccountId, clonedConfig.TargetServiceAccountId)
	require.Equal(t, originalConfig.Scopes, clonedConfig.Scopes)

	// Ensure that modifying the cloned config does not affect the original config
	clonedConfig.ProjectId = "modified-project-id"
	clonedConfig.PrivateKey = "modified-private-key"
	clonedConfig.PrivateKeyId = "modified-private-key-id"
	clonedConfig.ClientEmail = "modified-client-email@example.com"
	clonedConfig.TargetServiceAccountId = "modified-target-service-account-id"
	clonedConfig.Scopes = []string{"modified-scope1", "modified-scope2"}

	require.NotEqual(t, originalConfig.ProjectId, clonedConfig.ProjectId)
	require.NotEqual(t, originalConfig.PrivateKey, clonedConfig.PrivateKey)
	require.NotEqual(t, originalConfig.PrivateKeyId, clonedConfig.PrivateKeyId)
	require.NotEqual(t, originalConfig.ClientEmail, clonedConfig.ClientEmail)
	require.NotEqual(t, originalConfig.TargetServiceAccountId, clonedConfig.TargetServiceAccountId)
	require.NotEqual(t, originalConfig.Scopes, clonedConfig.Scopes)
}

func TestIsRotatable(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{
			name:   "Nil Config",
			config: nil,
			want:   false,
		},
		{
			name: "Service Account Impersonation Config",
			config: &Config{
				PrivateKey:             "fake-private-key",
				ClientEmail:            "test-email@example.com",
				TargetServiceAccountId: "target-service-account@example.com",
			},
			want: true,
		},
		{
			name: "Static GCP Config",
			config: &Config{
				PrivateKey:  "fake-private-key",
				ClientEmail: "test-email@example.com",
			},
			want: true,
		},
		{
			name:   "Default Config",
			config: &Config{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.IsRotatable()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNewConfig(t *testing.T) {
	tests := []struct {
		name        string
		options     []Option
		expected    *Config
		expectError bool
	}{
		{
			name: "Valid Options",
			options: []Option{
				WithProjectId("test-project-id"),
				WithPrivateKey("test-private-key"),
				WithPrivateKeyId("test-private-key-id"),
				WithClientEmail("test-email@example.com"),
				WithTargetServiceAccountId("target-service-account@example.com"),
				WithZone("test-zone"),
				WithScopes([]string{"scope1", "scope2"}),
			},
			expected: &Config{
				ProjectId:                        "test-project-id",
				PrivateKey:                       "test-private-key",
				PrivateKeyId:                     "test-private-key-id",
				ClientEmail:                      "test-email@example.com",
				TargetServiceAccountId:           "target-service-account@example.com",
				Zone:                             "test-zone",
				Scopes:                           []string{"scope1", "scope2"},
				validateServiceAccountKeyTimeout: defaultValidateServiceAccountKeyTimeout,
			},
			expectError: false,
		},
		{
			name:    "No Options",
			options: []Option{},
			expected: &Config{
				Scopes:                           []string{defaultGCPScope},
				validateServiceAccountKeyTimeout: defaultValidateServiceAccountKeyTimeout,
			},
			expectError: false,
		},
		{
			name: "Invalid Option",
			options: []Option{
				func(opts *Options) error {
					return errors.New("invalid option")
				},
			},
			expected:    nil,
			expectError: true,
		},
		{
			name: "no scope set",
			options: []Option{
				WithProjectId("test-project-id"),
				WithPrivateKey("test-private-key"),
				WithPrivateKeyId("test-private-key-id"),
				WithClientEmail("test-email@example.com"),
				WithTargetServiceAccountId("target-service-account@example.com"),
				WithZone("test-zone"),
			},
			expected: &Config{
				ProjectId:                        "test-project-id",
				PrivateKey:                       "test-private-key",
				PrivateKeyId:                     "test-private-key-id",
				ClientEmail:                      "test-email@example.com",
				TargetServiceAccountId:           "target-service-account@example.com",
				Zone:                             "test-zone",
				Scopes:                           []string{defaultGCPScope},
				validateServiceAccountKeyTimeout: defaultValidateServiceAccountKeyTimeout,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewConfig(tt.options...)
			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, config)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, config)
			require.Equal(t, tt.expected, config)
		})
	}
}
