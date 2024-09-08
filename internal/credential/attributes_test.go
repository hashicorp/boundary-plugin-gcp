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
