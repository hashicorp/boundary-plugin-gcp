// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"time"
)

type CredentialType int

// PersistedState is the persisted state for the GCP credential.
type PersistedState struct {
	// CredentialsConfig is the credential configuration for the GCP credential.
	CredentialsConfig *Config
	// CredsLastRotatedTime is the last rotation of service account key for the GCP credential.
	CredsLastRotatedTime time.Time
}

// NewPersistedState - create a new PersistedState
func NewPersistedState(opt ...Option) (*PersistedState, error) {
	s := new(PersistedState)
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}
	s.CredentialsConfig = opts.WithCredentialsConfig
	s.CredsLastRotatedTime = opts.WithCredsLastRotatedTime
	return s, nil
}

// ToMap returns a map of the credentials stored in the persisted state.
// ToMap will return a map for long-term credentials with following keys:
// private_key_id, private_key & creds_last_rotated_time
func (s *PersistedState) ToMap() map[string]any {
	return map[string]any{
		ConstPrivateKey:           s.CredentialsConfig.PrivateKey,
		ConstPrivateKeyId:         s.CredentialsConfig.PrivateKeyId,
		ConstCredsLastRotatedTime: s.CredsLastRotatedTime.Format(time.RFC3339Nano),
	}
}
