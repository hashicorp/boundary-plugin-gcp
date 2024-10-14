// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestNewGCPCredentialPersistedState(t *testing.T) {
	staticTime := time.Now()

	cases := []struct {
		name        string
		opts        []Option
		expected    *PersistedState
		expectedErr string
	}{
		{
			name: "error",
			opts: []Option{
				func(s *Options) error {
					return errors.New("option error")
				},
			},
			expectedErr: "option error",
		},
		{
			name: "with credentials config",
			opts: []Option{
				WithCredentialsConfig(
					&Config{
						ProjectId:   "test-project",
						ClientEmail: "test-email",
					},
				),
			},
			expected: &PersistedState{
				CredentialsConfig: &Config{
					ProjectId:   "test-project",
					ClientEmail: "test-email",
				},
			},
		},
		{
			name: "rotation time",
			opts: []Option{
				WithCredsLastRotatedTime(staticTime),
			},
			expected: &PersistedState{
				CredsLastRotatedTime: staticTime,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := NewPersistedState(tc.opts...)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected.CredsLastRotatedTime, actual.CredsLastRotatedTime)
			if tc.expected.CredentialsConfig != nil {
				require.NotNil(actual.CredentialsConfig)
				require.Equal(tc.expected.CredentialsConfig.ProjectId, actual.CredentialsConfig.ProjectId)
				require.Equal(tc.expected.CredentialsConfig.ClientEmail, actual.CredentialsConfig.ClientEmail)
			}
		})
	}
}
func TestPersistedStateFromProto(t *testing.T) {
	staticTime := time.Now()

	cases := []struct {
		name        string
		secrets     *structpb.Struct
		attrs       *CredentialAttributes
		opts        []Option
		expected    *PersistedState
		expectedErr string
	}{
		{
			name:        "missing credential attributes",
			expectedErr: "missing credential attributes",
		},
		{
			name:        "missing credential attributes",
			secrets:     &structpb.Struct{},
			attrs:       nil,
			expectedErr: "missing credential attributes",
		},
		{
			name: "with static credentials",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
					ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
					ConstCredsLastRotatedTime: structpb.NewStringValue(staticTime.Format(time.RFC3339Nano)),
				},
			},
			attrs: &CredentialAttributes{
				Zone:        "us-central1-a",
				ProjectId:   "test-project",
				ClientEmail: "test-email",
			},
			expected: &PersistedState{
				CredentialsConfig: &Config{
					PrivateKeyId: "test-private-key-id",
					PrivateKey:   "test-private-key",
					Zone:         "us-central1-a",
					ProjectId:    "test-project",
					ClientEmail:  "test-email",
				},
				CredsLastRotatedTime: func() time.Time {
					t, err := time.Parse(time.RFC3339Nano, staticTime.Format(time.RFC3339Nano))
					if err != nil {
						panic(err)
					}
					return t
				}(),
			},
		},
		{
			name: "with dynamic credentials",
			secrets: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					ConstPrivateKeyId:         structpb.NewStringValue("test-private-key-id"),
					ConstPrivateKey:           structpb.NewStringValue("test-private-key"),
					ConstCredsLastRotatedTime: structpb.NewStringValue((time.Time{}).Format(time.RFC3339Nano)),
				},
			},
			attrs: &CredentialAttributes{
				Zone:                   "us-central1-a",
				ProjectId:              "test-project",
				ClientEmail:            "test-email",
				TargetServiceAccountId: "test-service-account-id",
			},
			expected: &PersistedState{
				CredentialsConfig: &Config{
					PrivateKeyId:           "test-private-key-id",
					PrivateKey:             "test-private-key",
					Zone:                   "us-central1-a",
					ProjectId:              "test-project",
					ClientEmail:            "test-email",
					TargetServiceAccountId: "test-service-account-id",
				},
				CredsLastRotatedTime: time.Time{},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := PersistedStateFromProto(tc.secrets, tc.attrs, tc.opts...)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected.CredsLastRotatedTime, actual.CredsLastRotatedTime)
			if tc.expected.CredentialsConfig != nil {
				require.NotNil(actual.CredentialsConfig)
				require.Equal(tc.expected.CredentialsConfig.PrivateKeyId, actual.CredentialsConfig.PrivateKeyId)
				require.Equal(tc.expected.CredentialsConfig.PrivateKey, actual.CredentialsConfig.PrivateKey)
				require.Equal(tc.expected.CredentialsConfig.Zone, actual.CredentialsConfig.Zone)
				require.Equal(tc.expected.CredentialsConfig.ProjectId, actual.CredentialsConfig.ProjectId)
				require.Equal(tc.expected.CredentialsConfig.ClientEmail, actual.CredentialsConfig.ClientEmail)
				require.Equal(tc.expected.CredentialsConfig.TargetServiceAccountId, actual.CredentialsConfig.TargetServiceAccountId)
			}
		})
	}
}
