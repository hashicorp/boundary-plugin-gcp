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

// WithCredsLastRotatedTime - set the last rotated time
func WithCredsLastRotatedTime(t time.Time) Option {
	return func(o *Options) error {
		o.WithCredsLastRotatedTime = t
		return nil
	}
}

// WithClientEmail - set the client email
func WithClientEmail(email string) Option {
	return func(o *Options) error {
		o.WithClientEmail = email
		return nil
	}
}

// WithProjectId - set the project ID
func WithProjectId(id string) Option {
	return func(o *Options) error {
		o.WithProjectId = id
		return nil
	}
}

// WithTargetServiceAccountId - set the target service account ID
func WithTargetServiceAccountId(id string) Option {
	return func(o *Options) error {
		o.WithTargetServiceAccountId = id
		return nil
	}
}

// WithZone - set the zone
func WithZone(zone string) Option {
	return func(o *Options) error {
		o.WithZone = zone
		return nil
	}
}

// WithPrivateKeyId - set the private key ID
func WithPrivateKeyId(id string) Option {
	return func(o *Options) error {
		o.WithPrivateKeyId = id
		return nil
	}
}

// WithPrivateKey - set the private key
func WithPrivateKey(key string) Option {
	return func(o *Options) error {
		o.WithPrivateKey = key
		return nil
	}
}

// WithScopes - set the scopes
func WithScopes(scopes []string) Option {
	return func(o *Options) error {
		o.WithScopes = scopes
		return nil
	}
}
