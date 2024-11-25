// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary-plugin-gcp/internal/credential"
	"github.com/hashicorp/boundary-plugin-gcp/plugin/service/host"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	expectedInstanceCount = 3
	expectedTagsCount     = 3
	expectedLabelsCount   = 3
)

// All the tests in this test depend on each other
// to run in order. This is because the tests are
// testing the same plugin instance and the same
// persisted state. The tests are designed to run
// in order to test the plugin's ability to rotate
// credentials and manage the state of the plugin
// instance.
// To run the tests you need the following
// environment variables set:
// GOOGLE_APPLICATION_CREDENTIALS: This should be
// the path to the service account key. This can also
// be automatically set after authenticating with gcloud
// using `gcloud auth application-default login`.
//
// TF_VAR_project_id: The project_id of the project.
//
// TF_VAR_region: The region the resources should be
// deployed in.
//
// TF_VAR_zone: The zone the resources should be
// deployed in.
func TestHostPlugin(t *testing.T) {
	creds := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if creds == "" {
		t.Skip("set GOOGLE_APPLICATION_CREDENTIALS to use this test")
	}
	projectId := os.Getenv("TF_VAR_project_id")
	if projectId == "" {
		t.Skip("set TF_VAR_project_id to use this test")
	}
	region := os.Getenv("TF_VAR_region")
	if region == "" {
		t.Skip("set TF_VAR_region to use this test")
	}
	zone := os.Getenv("TF_VAR_zone")
	if zone == "" {
		t.Skip("set TF_VAR_zone to use this test")
	}

	require := require.New(t)
	tf, err := NewTestTerraformer("testdata/host")
	require.NoError(err)
	require.NotNil(tf)

	t.Log("===== deploying test Terraform workspace =====")
	err = tf.Deploy()
	require.NoError(err)

	defer func() {
		t.Log("===== destroying test Terraform workspace =====")
		if err := tf.Destroy(); err != nil {
			t.Logf("WARNING: could not run Terraform destroy: %s", err)
		}
	}()

	clientEmail, err := tf.GetOutput("client_email")
	require.NoError(err)
	require.NotNil(clientEmail)

	instanceIds, err := tf.GetOutputSlice("instance_ids")
	require.NoError(err)
	require.Len(instanceIds, expectedInstanceCount)

	instanceTags, err := tf.GetOutputMap("instance_tags")
	require.NoError(err)
	require.Len(instanceTags, expectedInstanceCount)

	instanceLabels, err := tf.GetOutputMap("instance_labels")
	require.NoError(err)
	require.Len(instanceLabels, expectedLabelsCount)

	privateKeys, err := tf.GetOutputSlice("private_keys")
	require.NoError(err)
	require.Len(privateKeys, expectedServiceAccountKeys)

	privateKeyIds, err := tf.GetOutputSlice("private_key_ids")
	require.NoError(err)
	require.Len(privateKeyIds, expectedServiceAccountKeys)

	p := new(host.HostPlugin)
	ctx := context.Background()

	var keyId, secret string

	t.Run("OnCreateCatalog", func(t *testing.T) {
		t.Run("Test non-rotation", func(t *testing.T) {
			keyId, secret = testPluginOnCreateCatalog(
				ctx,
				t,
				p,
				zone,
				projectId,
				clientEmail.(string),
				privateKeyIds[0].(string),
				privateKeys[0].(string),
				false,
			)
			require.NotNil(keyId)
			require.NotNil(secret)
		})

		t.Run("Test rotation", func(t *testing.T) {
			keyId, secret = testPluginOnCreateCatalog(
				ctx,
				t,
				p,
				zone,
				projectId,
				clientEmail.(string),
				keyId,
				secret,
				true,
			)
			require.NotNil(keyId)
			require.NotNil(secret)
		})
	})

	t.Run("OnUpdateCatalog", func(t *testing.T) {
		t.Run("Test no-op non-rotation", func(t *testing.T) {
			keyId, secret = testPluginOnUpdateCatalog(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, "", "", false, false)
			require.NotNil(keyId)
			require.NotNil(secret)
		})

		t.Run("Switch to rotation", func(t *testing.T) {
			keyId, secret = testPluginOnUpdateCatalog(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, "", "", false, true)
			require.NotNil(keyId)
			require.NotNil(secret)
		})

		t.Run("Test no-op with rotation", func(t *testing.T) {
			keyId, secret = testPluginOnUpdateCatalog(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, "", "", true, true)
			require.NotNil(keyId)
			require.NotNil(secret)
		})

		t.Run("Switch credentials to next service account key. Don't rotate", func(t *testing.T) {
			keyId, secret = testPluginOnUpdateCatalog(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, privateKeyIds[1].(string), privateKeys[1].(string), true, false)
			require.NotNil(keyId)
			require.NotNil(secret)
		})

		t.Run("Switch credentials to next service account key. Add rotation", func(t *testing.T) {
			keyId, secret = testPluginOnUpdateCatalog(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, privateKeyIds[2].(string), privateKeys[2].(string), false, true)
			require.NotNil(keyId)
			require.NotNil(secret)
		})

		t.Run("Switch to next service account key, with rotation disabled", func(t *testing.T) {
			keyId, secret = testPluginOnUpdateCatalog(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, privateKeyIds[3].(string), privateKeys[3].(string), true, false)
			require.NotNil(keyId)
			require.NotNil(secret)
		})

		t.Run("Switch to another service account key and keep rotation off", func(t *testing.T) {
			keyId, secret = testPluginOnUpdateCatalog(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, privateKeyIds[4].(string), privateKeys[4].(string), false, false)
			require.NotNil(keyId)
			require.NotNil(secret)
		})
	})

	t.Run("OnDeleteCatalog", func(t *testing.T) {
		t.Run("Test non-rotated", func(t *testing.T) {
			testPluginOnDeleteCatalog(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, false)
		})

		t.Run("Test as if we had rotated these credentials.", func(t *testing.T) {
			testPluginOnDeleteCatalog(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, true)
		})
	})

	t.Run("HostSet", func(t *testing.T) {
		keyId, secret := privateKeyIds[5].(string), privateKeys[5].(string)
		expectedLabelInstancesMap := make(map[string][]string)
		for instanceId, instanceLabel := range instanceLabels {
			for tagKey := range instanceLabel.(map[string]any) {
				for _, expectedTag := range instanceLabels {
					if tagKey == expectedTag {
						expectedLabelInstancesMap[tagKey] = append(expectedLabelInstancesMap[tagKey], instanceId)
					}
				}
			}
		}

		cases := map[string][]string{
			"label-1": {"foo"},
			"label-2": {"bar"},
			"label-3": {"baz"},
			"label-4": {"foo", "bar"},
			"label-5": {"foo", "baz"},
			"label-6": {"bar", "baz"},
			"label-7": {"foo", "bar", "baz"},
		}

		for key, tc := range cases {
			t.Run(fmt.Sprintf("Label=%s", key), func(t *testing.T) {
				labels := make([]string, 0, len(tc))
				for _, label := range tc {
					labels = append(labels, fmt.Sprintf("labels.%s=%s", key, label))
				}
				testPluginOnCreateUpdateSet(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, labels)
				testPluginListHosts(ctx, t, p, zone, projectId, clientEmail.(string), keyId, secret, labels, expectedLabelInstancesMap)
			})
		}
	})
}

func testPluginOnCreateCatalog(
	ctx context.Context,
	t *testing.T,
	p *host.HostPlugin,
	zone string,
	projectId string,
	clientEmail string,
	privateKeyId string,
	privateKey string,
	rotate bool) (string, string) {
	t.Helper()
	t.Logf("testing OnCreateCatalog (zone=%s, rotate=%t)", zone, rotate)
	require := require.New(t)

	reqAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstClientEmail:               clientEmail,
		credential.ConstProjectId:                 projectId,
		credential.ConstZone:                      zone,
		credential.ConstDisableCredentialRotation: !rotate,
	})
	require.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstPrivateKeyId: privateKeyId,
		credential.ConstPrivateKey:   privateKey,
	})
	require.NoError(err)
	request := &pb.OnCreateCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: reqAttrs,
			},
			Secrets: reqSecrets,
		},
	}
	response, err := p.OnCreateCatalog(ctx, request)
	require.NoError(err)
	require.NotNil(response)
	persisted := response.GetPersisted()
	require.NotNil(persisted)
	return validatePersistedSecrets(t, persisted.GetSecrets(), projectId, clientEmail, privateKeyId, privateKey, rotate)
}

func testPluginOnUpdateCatalog(
	ctx context.Context,
	t *testing.T,
	p *host.HostPlugin,
	zone string,
	projectId string,
	clientEmail string,
	currentPrivateKeyId string,
	currentPrivateKey string,
	newPrivateKeyId string,
	newPrivateKey string,
	rotated bool,
	rotate bool,
) (string, string) {
	t.Helper()
	t.Logf("testing OnUpdateCatalog (zone=%s, newcreds=%t, rotated=%t, rotate=%t)", zone, newPrivateKeyId != "" && newPrivateKey != "", rotated, rotate)
	require := require.New(t)

	// Take a timestamp of the current time to get a point in time to
	// reference, ensuring that we are updating credential rotation
	// timestamps.
	currentCredsLastRotatedTime := time.Now()

	reqCurrentAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstProjectId:                 projectId,
		credential.ConstClientEmail:               clientEmail,
		credential.ConstZone:                      zone,
		credential.ConstDisableCredentialRotation: !rotated,
	})
	require.NoError(err)
	reqNewAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstProjectId:                 projectId,
		credential.ConstClientEmail:               clientEmail,
		credential.ConstZone:                      zone,
		credential.ConstDisableCredentialRotation: !rotate,
	})
	require.NoError(err)
	var reqSecrets *structpb.Struct
	if newPrivateKeyId != "" && newPrivateKey != "" {
		reqSecrets, err = structpb.NewStruct(map[string]any{
			credential.ConstPrivateKeyId: newPrivateKeyId,
			credential.ConstPrivateKey:   newPrivateKey,
		})
		require.NoError(err)
	}
	reqPersistedSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstPrivateKeyId: currentPrivateKeyId,
		credential.ConstPrivateKey:   currentPrivateKey,
		credential.ConstCredsLastRotatedTime: func() string {
			if rotated {
				return currentCredsLastRotatedTime.Format(time.RFC3339Nano)
			}

			return (time.Time{}).Format(time.RFC3339Nano)
		}(),
	})
	require.NoError(err)
	require.NotNil(reqPersistedSecrets)
	request := &pb.OnUpdateCatalogRequest{
		CurrentCatalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: reqCurrentAttrs,
			},
		},
		NewCatalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: reqNewAttrs,
			},
			Secrets: reqSecrets,
		},
		Persisted: &pb.HostCatalogPersisted{
			Secrets: reqPersistedSecrets,
		},
	}
	response, err := p.OnUpdateCatalog(ctx, request)
	require.NoError(err)
	require.NotNil(response)
	persisted := response.GetPersisted()
	require.NotNil(persisted)
	return validateUpdateSecrets(
		t,
		projectId,
		clientEmail,
		persisted.GetSecrets(),
		currentCredsLastRotatedTime,
		currentPrivateKeyId,
		currentPrivateKey,
		newPrivateKeyId,
		newPrivateKey,
		rotated,
		rotate,
	)
}

func testPluginOnDeleteCatalog(
	ctx context.Context,
	t *testing.T,
	p *host.HostPlugin,
	zone string,
	projectId string,
	clientEmail string,
	privateKeyId string,
	privateKey string,
	rotated bool) {
	t.Helper()
	t.Logf("testing OnDeleteCatalog (zone=%s, rotated=%t)", zone, rotated)
	require := require.New(t)

	reqAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstProjectId:                 projectId,
		credential.ConstClientEmail:               clientEmail,
		credential.ConstZone:                      zone,
		credential.ConstDisableCredentialRotation: !rotated,
	})
	require.NoError(err)
	reqSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstPrivateKeyId: privateKeyId,
		credential.ConstPrivateKey:   privateKey,
	})
	require.NoError(err)
	reqPersistedSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstPrivateKeyId: privateKeyId,
		credential.ConstPrivateKey:   privateKey,
		credential.ConstCredsLastRotatedTime: func() string {
			if rotated {
				return time.Now().Format(time.RFC3339Nano)
			}

			return (time.Time{}).Format(time.RFC3339Nano)
		}(),
	})
	require.NoError(err)
	request := &pb.OnDeleteCatalogRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: reqAttrs,
			},
			Secrets: reqSecrets,
		},
		Persisted: &pb.HostCatalogPersisted{
			Secrets: reqPersistedSecrets,
		},
	}
	response, err := p.OnDeleteCatalog(ctx, request)
	require.NoError(err)
	require.NotNil(response)

	// We want to test the validity of the credentials post-deletion.
	if rotated {
		// The credentials should no longer be valid.
		requireCredentialsInvalid(t, projectId, clientEmail, privateKeyId, privateKey)
	} else {
		// The credentials should still be valid. Sleep 10s first just to
		// be sure, since we're not rotating.
		time.Sleep(time.Second * 10)
		requireCredentialsValid(t, projectId, clientEmail, privateKeyId, privateKey)
	}
}

func testPluginOnCreateUpdateSet(
	ctx context.Context,
	t *testing.T,
	p *host.HostPlugin,
	zone string,
	projectId string,
	clientEmail string,
	privateKeyId string,
	privateKey string,
	labels []string) {
	t.Helper()
	t.Logf("testing OnCreateSet (zone=%s, labels=%v)", zone, labels)
	require := require.New(t)
	catalogAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstProjectId:                 projectId,
		credential.ConstClientEmail:               clientEmail,
		credential.ConstZone:                      zone,
		credential.ConstDisableCredentialRotation: true, // Note that this does nothing in sets, but just noting for tests
	})
	require.NoError(err)
	setAttrs, err := structpb.NewStruct(map[string]any{
		host.ConstListInstancesFilter: []any{strings.Join(labels, " AND ")},
	})
	require.NoError(err)
	reqPersistedSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstPrivateKeyId:         privateKeyId,
		credential.ConstPrivateKey:           privateKey,
		credential.ConstCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
	})
	require.NoError(err)
	createRequest := &pb.OnCreateSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: catalogAttrs,
			},
		},
		Set: &hostsets.HostSet{
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: setAttrs,
			},
		},
		Persisted: &pb.HostCatalogPersisted{
			Secrets: reqPersistedSecrets,
		},
	}
	createResponse, err := p.OnCreateSet(ctx, createRequest)
	require.NoError(err)
	require.NotNil(createResponse)

	// Do an update test in the same function, as it's pretty much the
	// same function right now.
	t.Logf("testing OnUpdateSet (zone=%s, labels=%v)", zone, labels)
	updateRequest := &pb.OnUpdateSetRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: catalogAttrs,
			},
		},
		CurrentSet: &hostsets.HostSet{
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: setAttrs,
			},
		},
		NewSet: &hostsets.HostSet{
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: setAttrs,
			},
		},
		Persisted: &pb.HostCatalogPersisted{
			Secrets: reqPersistedSecrets,
		},
	}
	updateResponse, err := p.OnUpdateSet(ctx, updateRequest)
	require.NoError(err)
	require.NotNil(updateResponse)
}

func testPluginListHosts(
	ctx context.Context,
	t *testing.T,
	p *host.HostPlugin,
	zone string,
	projectId string,
	clientEmail string,
	privateKeyId string,
	privateKey string,
	labels []string,
	expected map[string][]string) {
	t.Helper()
	t.Logf("testing ListHosts (zone=%s, labels=%v)", zone, labels)
	require := require.New(t)
	catalogAttrs, err := structpb.NewStruct(map[string]any{
		credential.ConstProjectId:                 projectId,
		credential.ConstClientEmail:               clientEmail,
		credential.ConstZone:                      zone,
		credential.ConstDisableCredentialRotation: true, // Note that this does nothing in sets, but just noting for tests
	})
	require.NoError(err)
	sets := make([]*hostsets.HostSet, len(labels))
	for i, label := range labels {
		setAttrs, err := structpb.NewStruct(map[string]any{
			host.ConstListInstancesFilter: []any{label},
		})
		require.NoError(err)
		sets[i] = &hostsets.HostSet{
			Id: fmt.Sprintf("hostset-%d", i),
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: setAttrs,
			},
		}
	}
	reqPersistedSecrets, err := structpb.NewStruct(map[string]any{
		credential.ConstPrivateKeyId:         privateKeyId,
		credential.ConstPrivateKey:           privateKey,
		credential.ConstCredsLastRotatedTime: (time.Time{}).Format(time.RFC3339Nano),
	})
	require.NoError(err)
	request := &pb.ListHostsRequest{
		Catalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: catalogAttrs,
			},
		},
		Sets: sets,
		Persisted: &pb.HostCatalogPersisted{
			Secrets: reqPersistedSecrets,
		},
	}
	response, err := p.ListHosts(ctx, request)
	require.NoError(err)
	require.NotNil(response)

	// Validate the returned instances by ID. Assemble the instance
	// details from the expected set.
	expectedInstances := make(map[string][]string)
	for i, label := range labels {
		for _, instanceId := range expected[label] {
			expectedInstances[instanceId] = append(expectedInstances[instanceId], fmt.Sprintf("hostset-%d", i))
		}
	}

	// Take the returned hosts by ID and create the same kind of map.
	actualInstances := make(map[string][]string)
	for _, host := range response.GetHosts() {
		actualInstances[host.ExternalId] = host.SetIds
	}

	// Compare
	require.Equal(expectedInstances, actualInstances)
	// Success
	t.Logf("testing ListHosts: success (region=%s, tags=%v, expected/actual=(len=%d, ids=%s))", zone, labels, len(actualInstances), actualInstances)
}
