// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary-plugin-gcp/internal/values"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
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

// RotateCreds rotates the credentials for the GCP catalog and updates the last rotated time.
func (s *PersistedState) RotateCreds(ctx context.Context, permissions []string, opts ...option.ClientOption) error {
	if s.CredentialsConfig == nil {
		return status.Error(codes.InvalidArgument, "missing credentials config")
	}
	if !s.CredentialsConfig.IsRotatable() {
		return status.Error(codes.InvalidArgument, "cannot rotate non-rotatable credentials")
	}

	err := s.CredentialsConfig.RotateServiceAccountKey(ctx, permissions, opts...)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to rotate credentials: %v", err)
	}
	s.CredsLastRotatedTime = time.Now()

	return nil
}

// ReplaceCreds replaces the private key in the state with a new key.
// If the existing key was rotated at any point in time, it is
// deleted first, otherwise it's left alone. This method returns a
// status error with PluginError details.
func (s *PersistedState) ReplaceCreds(ctx context.Context, newCreds *Config, opts ...option.ClientOption) error {
	if newCreds == nil {
		return status.Errorf(codes.InvalidArgument, "missing new credentials")
	}
	if s.CredentialsConfig == nil {
		return status.Errorf(codes.InvalidArgument, "missing existing credentials")
	}

	// Delete old/existing credentials.
	// This is done with the same credentials to ensure that it has the proper permissions to do it.
	if !s.CredsLastRotatedTime.IsZero() && s.CredentialsConfig.IsRotatable() {
		if err := s.DeleteCreds(ctx, opts...); err != nil {
			return err
		}
	}

	// Set the new attributes and clear the rotated time.
	s.CredentialsConfig = newCreds
	s.CredsLastRotatedTime = time.Time{}
	return nil
}

// DeleteCreds deletes the credentials in the state. The access key
// ID, secret access key, and rotation time fields are zeroed out in
// the state just to ensure that they cannot be re-used after. This
// method returns a status error with PluginError details.
func (s *PersistedState) DeleteCreds(ctx context.Context, opts ...option.ClientOption) error {
	if s.CredentialsConfig == nil {
		return status.Errorf(codes.InvalidArgument, "missing credentials config")
	}
	if !s.CredentialsConfig.IsRotatable() {
		return status.Errorf(codes.InvalidArgument, "cannot delete credentials for non-rotatable credentials")
	}

	err := s.CredentialsConfig.DeletePrivateKey(ctx, opts...)
	if err != nil {
		return err
	}

	s.CredentialsConfig = nil
	s.CredsLastRotatedTime = time.Time{}
	return nil
}

// ToMap returns a map of the credentials stored in the persisted state.
// ToMap will return a map for long-term credentials with following keys:
// private_key_id, private_key & creds_last_rotated_time
func (s *PersistedState) ToMap() map[string]any {
	if !s.CredentialsConfig.IsRotatable() {
		return map[string]any{}
	}
	return map[string]any{
		ConstPrivateKey:           s.CredentialsConfig.PrivateKey,
		ConstPrivateKeyId:         s.CredentialsConfig.PrivateKeyId,
		ConstCredsLastRotatedTime: s.CredsLastRotatedTime.Format(time.RFC3339Nano),
	}
}

// PersistedStateFromProto parses values out of a protobuf struct input
// and returns a PersistedState used for GCP authentication.
func PersistedStateFromProto(secrets *structpb.Struct, attrs *CredentialAttributes, opts ...Option) (*PersistedState, error) {
	if secrets == nil {
		secrets = &structpb.Struct{
			Fields: map[string]*structpb.Value{},
		}
	}

	if attrs == nil {
		return nil, fmt.Errorf("missing credential attributes")
	}

	privateKeyId, err := values.GetStringValue(secrets, ConstPrivateKeyId, false)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	privateKey, err := values.GetStringValue(secrets, ConstPrivateKey, false)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	credsLastRotatedTime, err := values.GetTimeValue(secrets, ConstCredsLastRotatedTime)
	if err != nil {
		return nil, fmt.Errorf("persisted state integrity error: %w", err)
	}

	s, err := NewPersistedState(opts...)
	if err != nil {
		return nil, err
	}

	cfgOpts := []Option{}
	if privateKeyId != "" && privateKey != "" {
		cfgOpts = append(cfgOpts,
			WithPrivateKey(privateKey),
			WithPrivateKeyId(privateKeyId))
	}

	if attrs.Zone != "" {
		cfgOpts = append(cfgOpts, WithZone(attrs.Zone))
	}
	if attrs.ProjectId != "" {
		cfgOpts = append(cfgOpts, WithProjectId(attrs.ProjectId))
	}
	if attrs.ClientEmail != "" {
		cfgOpts = append(cfgOpts, WithClientEmail(attrs.ClientEmail))
	}
	if attrs.TargetServiceAccountId != "" {
		cfgOpts = append(cfgOpts, WithTargetServiceAccountId(attrs.TargetServiceAccountId))
	}
	credentialsConfig, err := NewConfig(cfgOpts...)
	if err != nil {
		return nil, err
	}
	s.CredentialsConfig = credentialsConfig
	s.CredsLastRotatedTime = credsLastRotatedTime

	return s, nil
}
