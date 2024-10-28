// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary-plugin-gcp/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestWithCredentials(t *testing.T) {
	cred := &credential.PersistedState{}
	opt := withCredentials(cred)

	state := &gcpCatalogPersistedState{}
	err := opt(state)
	require.NoError(t, err)
	assert.Equal(t, cred, state.PersistedState)

	// Test setting credentials again should return an error
	err = opt(state)
	assert.Error(t, err)
	assert.Equal(t, "gcp credentials already set", err.Error())
}

func TestNewGCPCatalogPersistedState(t *testing.T) {
	cred := &credential.PersistedState{}
	opt := withCredentials(cred)

	state, err := newGCPCatalogPersistedState(opt)
	require.NoError(t, err)
	assert.Equal(t, cred, state.PersistedState)
}

func TestToProto(t *testing.T) {
	lastRotatedTime := time.Now()
	state := &gcpCatalogPersistedState{PersistedState: &credential.PersistedState{
		CredentialsConfig: &credential.Config{
			PrivateKey:   "test-private-key",
			PrivateKeyId: "test-private-key-id",
			ClientEmail:  "test@test.com",
		},
		CredsLastRotatedTime: lastRotatedTime,
	},
	}

	proto, err := state.toProto()
	require.NoError(t, err)

	expectedData, err := structpb.NewStruct(map[string]any{
		"private_key":             "test-private-key",
		"private_key_id":          "test-private-key-id",
		"creds_last_rotated_time": lastRotatedTime.Format(time.RFC3339Nano),
	})
	require.NoError(t, err)
	assert.Equal(t, expectedData, proto.Secrets)
}

func TestInstancesClient(t *testing.T) {
	ctx := context.Background()
	cred := &credential.PersistedState{
		CredentialsConfig: &credential.Config{},
	}
	state := &gcpCatalogPersistedState{PersistedState: cred}

	t.Run("GenerateCredentials error", func(t *testing.T) {
		_, err := state.InstancesClient(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error generation GCP credentials")
	})

	t.Run("NewInstancesRESTClient error", func(t *testing.T) {
		state.CredentialsConfig = &credential.Config{
			ProjectId:   "test-project-id",
			PrivateKey:  "test-private-key",
			ClientEmail: "test@example.com",
		}
		_, err := state.InstancesClient(ctx, option.WithoutAuthentication())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error creating instances client")
	})
}
