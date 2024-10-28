// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"time"
)

// options = how options are represented
type Options struct {
	WithCredentialsConfig      *Config
	WithCredsLastRotatedTime   time.Time
	WithClientEmail            string
	WithProjectId              string
	WithTargetServiceAccountId string
	WithZone                   string
	WithPrivateKeyId           string
	WithPrivateKey             string
	WithScopes                 []string
}

// getOpts - iterate the inbound Options and return a struct
func getOpts(opts ...Option) (*Options, error) {
	defaultOptions := getDefaultOptions()
	for _, opt := range opts {
		if err := opt(defaultOptions); err != nil {
			return nil, err
		}
	}
	return defaultOptions, nil
}

// Option - how Options are passed as arguments
type Option func(*Options) error

func getDefaultOptions() *Options {
	return &Options{
		WithCredentialsConfig: &Config{},
	}
}

// WithCredentialsConfig - set the credentials config
func WithCredentialsConfig(c *Config) Option {
	return func(o *Options) error {
		o.WithCredentialsConfig = c
		return nil
	}
}

// WithCredsLastRotatedTime - The last time the service account key was
// rotated
func WithCredsLastRotatedTime(t time.Time) Option {
	return func(o *Options) error {
		o.WithCredsLastRotatedTime = t
		return nil
	}
}

// WithClientEmail - The email address associated with the service account.
// The email address used to uniquely identify the service account
func WithClientEmail(email string) Option {
	return func(o *Options) error {
		o.WithClientEmail = email
		return nil
	}
}

// WithProjectId - The project ID associated with the service account
func WithProjectId(id string) Option {
	return func(o *Options) error {
		o.WithProjectId = id
		return nil
	}
}

// WithTargetServiceAccountId - The account that will be impersonated.
// This account has permission to perform actions that the base service
// account does not have.
func WithTargetServiceAccountId(id string) Option {
	return func(o *Options) error {
		o.WithTargetServiceAccountId = id
		return nil
	}
}

// WithZone - The zone where the GCP resources are located
func WithZone(zone string) Option {
	return func(o *Options) error {
		o.WithZone = zone
		return nil
	}
}

// WithPrivateKeyId - The private key ID
// of the GCP service account
func WithPrivateKeyId(id string) Option {
	return func(o *Options) error {
		o.WithPrivateKeyId = id
		return nil
	}
}

// WithPrivateKey - set the GCP service account
// private key which is used to authentication
func WithPrivateKey(key string) Option {
	return func(o *Options) error {
		o.WithPrivateKey = key
		return nil
	}
}

// WithScopes - set the GCP scope that defines the level
// of access that the requested access token will have.
// This option is required when authenticating with
// Service Account Impersonation.
func WithScopes(scopes []string) Option {
	return func(o *Options) error {
		o.WithScopes = scopes
		return nil
	}
}
