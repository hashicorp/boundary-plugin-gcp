// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"time"
)

type CredentialType int

// GoogleCredentialPersistedState is the persisted state for the GCP credential.
type GCPCredentialPersistedState struct {
	// CredentialsConfig is the credential configuration for the GCP credential.
	CredentialsConfig *Config
	// CredsLastRotatedTime is the last rotation of service account key for the GCP credential.
	CredsLastRotatedTime time.Time
}

// NewGCPCredentialPersistedState - create a new GoogleCredentialPersistedState
func NewGCPCredentialPersistedState(opt ...Option) (*GCPCredentialPersistedState, error) {
	s := new(GCPCredentialPersistedState)
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}
	s.CredentialsConfig = opts.WithCredentialsConfig
	s.CredsLastRotatedTime = opts.WithCredsLastRotatedTime
	return s, nil
}
