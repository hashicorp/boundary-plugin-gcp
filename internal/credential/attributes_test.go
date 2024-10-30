// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetCredentialAttributes(t *testing.T) {
	cases := []struct {
		name                string
		in                  map[string]any
		expected            *CredentialAttributes
		expectedErrContains string
	}{
		{
			name:                "missing project",
			in:                  map[string]any{},
			expectedErrContains: "missing required value \"project_id\"",
		},
		{
			name:                "missing zone",
			in:                  map[string]any{},
			expectedErrContains: "missing required value \"zone\"",
		},
		{
			name: "valid project and zone",
			in: map[string]any{
				ConstProjectId: "test-project",
				ConstZone:      "us-central-1",
			},
			expected: &CredentialAttributes{
				ProjectId:                 "test-project",
				Zone:                      "us-central-1",
				DisableCredentialRotation: false,
			},
		},
		{
			name: "with disable_credential_rotation",
			in: map[string]any{
				ConstDisableCredentialRotation: true,
				ConstProjectId:                 "test-project",
				ConstZone:                      "us-central-1",
			},
			expected: &CredentialAttributes{
				DisableCredentialRotation: true,
				ProjectId:                 "test-project",
				Zone:                      "us-central-1",
			},
		},
		{
			name: "with client_email",
			in: map[string]any{
				ConstClientEmail: "test@test.com",
				ConstProjectId:   "test-project",
				ConstZone:        "us-central-1",
			},
			expected: &CredentialAttributes{
				ClientEmail: "test@test.com",
				ProjectId:   "test-project",
				Zone:        "us-central-1",
			},
		},
		{
			name: "with target_service_account_id",
			in: map[string]any{
				ConstTargetServiceAccountID: "test-target-service-account",
				ConstProjectId:              "test-project",
				ConstZone:                   "us-central-1",
			},
			expected: &CredentialAttributes{
				TargetServiceAccountId: "test-target-service-account",
				ProjectId:              "test-project",
				Zone:                   "us-central-1",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			actual, err := GetCredentialAttributes(input)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err), codes.InvalidArgument)
				return
			}

			require.NoError(err)
			require.EqualValues(tc.expected.ProjectId, actual.ProjectId)
			require.EqualValues(tc.expected.Zone, actual.Zone)
		})
	}
}

func TestGetCredentialsConfig(t *testing.T) {
	cases := []struct {
		name                string
		secrets             map[string]any
		attrs               *CredentialAttributes
		expected            *Config
		expectedErrContains string
	}{
		{
			name: "nil secrets",
			attrs: &CredentialAttributes{
				Zone: "us-central-1a",
			},
			expected: &Config{
				Zone:   "us-central-1a",
				Scopes: []string{defaultGCPScope},
			},
		},
		{
			name:  "nil attributes",
			attrs: nil,
			expected: &Config{
				Scopes: []string{defaultGCPScope},
			},
		},
		{
			name: "unknown fields in secrets",
			secrets: map[string]any{
				"unknown_field": "value",
			},
			attrs: &CredentialAttributes{
				ProjectId: "test-project",
				Zone:      "us-central-1a",
			},
			expectedErrContains: "secrets.unknown_field: unrecognized field",
		},
		{
			name: "valid ignore creds_last_rotated_time",
			secrets: map[string]any{
				ConstPrivateKeyId:         "test-private-key-id",
				ConstPrivateKey:           "test-private-key",
				ConstCredsLastRotatedTime: "2006-01-02T15:04:05+07:00",
			},
			attrs: &CredentialAttributes{
				ProjectId:   "test-project",
				Zone:        "us-central-1a",
				ClientEmail: "test@test.com",
			},
			expected: &Config{
				ProjectId:    "test-project",
				Zone:         "us-central-1a",
				ClientEmail:  "test@test.com",
				PrivateKey:   "test-private-key",
				PrivateKeyId: "test-private-key-id",
				Scopes:       []string{defaultGCPScope},
			},
		},
		{
			name: "missing private key with target service account id",
			secrets: map[string]any{
				ConstClientEmail: "test@test.com",
			},
			attrs: &CredentialAttributes{
				ProjectId:              "test-project",
				Zone:                   "us-central-1a",
				TargetServiceAccountId: "test-target-service-account",
			},
			expectedErrContains: "must not be empty when target service account id is set",
		},
		{
			name: "missing client email with target service account id",
			secrets: map[string]any{
				ConstPrivateKey: "private-key",
			},
			attrs: &CredentialAttributes{
				ProjectId:              "test-project",
				Zone:                   "us-central-1a",
				TargetServiceAccountId: "test-target-service-account",
			},
			expectedErrContains: "must not be empty when target service account id is set",
		},
		{
			name: "missing client email with private key",
			secrets: map[string]any{
				ConstPrivateKeyId: "test-private-key-id",
				ConstPrivateKey:   "test-private-key",
			},
			attrs: &CredentialAttributes{
				ProjectId: "test-project",
				Zone:      "us-central-1a",
			},
			expectedErrContains: "must not be empty when private key is set",
		},
		{
			name:    "missing private key with client email",
			secrets: map[string]any{},
			attrs: &CredentialAttributes{
				ClientEmail: "test@test.com",
				ProjectId:   "test-project",
				Zone:        "us-central-1a",
			},
			expectedErrContains: "must not be empty when client email is set",
		},
		{
			name: "valid static credentials",
			secrets: map[string]any{
				ConstPrivateKeyId: "test-private-key-id",
				ConstPrivateKey:   "test-private-key",
			},
			attrs: &CredentialAttributes{
				ClientEmail: "test@test.com",
				ProjectId:   "test-project",
				Zone:        "us-central-1a",
			},
			expected: &Config{
				ProjectId:    "test-project",
				Zone:         "us-central-1a",
				PrivateKey:   "test-private-key",
				PrivateKeyId: "test-private-key-id",
				ClientEmail:  "test@test.com",
				Scopes:       []string{defaultGCPScope},
			},
		},
		{
			name: "valid dynamic credentials",
			secrets: map[string]any{
				ConstPrivateKeyId: "test-private-key-id",
				ConstPrivateKey:   "test-private-key",
			},
			attrs: &CredentialAttributes{
				ClientEmail:            "test@test.com",
				ProjectId:              "test-project",
				Zone:                   "us-central-1a",
				TargetServiceAccountId: "test-target-service-account",
			},
			expected: &Config{
				ProjectId:              "test-project",
				Zone:                   "us-central-1a",
				PrivateKey:             "test-private-key",
				PrivateKeyId:           "test-private-key-id",
				ClientEmail:            "test@test.com",
				TargetServiceAccountId: "test-target-service-account",
				Scopes:                 []string{defaultGCPScope},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			secrets, err := structpb.NewStruct(tc.secrets)
			require.NoError(err)

			actual, err := GetCredentialsConfig(secrets, tc.attrs)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err), codes.InvalidArgument)
				return
			}

			require.NoError(err)
			require.EqualValues(tc.expected, actual)
		})
	}
}
