// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_getOpts(t *testing.T) {
	t.Parallel()

	t.Run("WithCredentialsConfig", func(t *testing.T) {
		c := &GCPConfig{
			ProjectId:   "test",
			ClientEmail: "test",
		}
		opts, err := getOpts(WithCredentialsConfig(c))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithCredentialsConfig = c
		require.Equal(t, opts, testOpts)
	})
	t.Run("WithCredsLastRotatedTime", func(t *testing.T) {
		tm := time.Now()
		opts, err := getOpts(WithCredsLastRotatedTime(tm))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithCredsLastRotatedTime = tm
		require.Equal(t, opts, testOpts)
	})
}
