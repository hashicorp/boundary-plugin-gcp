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
		c := &Config{
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
	t.Run("WithClientEmail", func(t *testing.T) {
		email := "test"
		opts, err := getOpts(WithClientEmail(email))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithClientEmail = email
		require.Equal(t, opts, testOpts)
	})
	t.Run("WithProjectId", func(t *testing.T) {
		projectID := "test"
		opts, err := getOpts(WithProjectId(projectID))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithProjectId = projectID
		require.Equal(t, opts, testOpts)
	})
	t.Run("WithTargetServiceAccountId", func(t *testing.T) {
		serviceAccountID := "test"
		opts, err := getOpts(WithTargetServiceAccountId(serviceAccountID))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithTargetServiceAccountId = serviceAccountID
		require.Equal(t, opts, testOpts)
	})
	t.Run("WithZone", func(t *testing.T) {
		zone := "test"
		opts, err := getOpts(WithZone(zone))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithZone = zone
		require.Equal(t, opts, testOpts)
	})
	t.Run("WithPrivateKey", func(t *testing.T) {
		privateKey := "test"
		opts, err := getOpts(WithPrivateKey(privateKey))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithPrivateKey = privateKey
		require.Equal(t, opts, testOpts)
	})
	t.Run("WithPrivateKeyId", func(t *testing.T) {
		privateKeyID := "test"
		opts, err := getOpts(WithPrivateKeyId(privateKeyID))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithPrivateKeyId = privateKeyID
		require.Equal(t, opts, testOpts)
	})
	t.Run("WithScopes", func(t *testing.T) {
		scopes := []string{"test"}
		opts, err := getOpts(WithScopes(scopes))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.WithScopes = scopes
		require.Equal(t, opts, testOpts)
	})
}
