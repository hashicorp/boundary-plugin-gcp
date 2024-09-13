// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewGCPCredentialPersistedState(t *testing.T) {
	staticTime := time.Now()

	cases := []struct {
		name        string
		opts        []Option
		expected    *GCPCredentialPersistedState
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
					&GCPConfig{
						ProjectId:   "test-project",
						ClientEmail: "test-email",
					},
				),
			},
			expected: &GCPCredentialPersistedState{
				CredentialsConfig: &GCPConfig{
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
			expected: &GCPCredentialPersistedState{
				CredsLastRotatedTime: staticTime,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := NewGCPCredentialPersistedState(tc.opts...)
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
