// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import "time"

// options = how options are represented
type Options struct {
	WithCredentialsConfig    *Config
	WithCredsLastRotatedTime time.Time
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

func WithCredentialsConfig(c *Config) Option {
	return func(o *Options) error {
		o.WithCredentialsConfig = c
		return nil
	}
}

func WithCredsLastRotatedTime(t time.Time) Option {
	return func(o *Options) error {
		o.WithCredsLastRotatedTime = t
		return nil
	}
}
