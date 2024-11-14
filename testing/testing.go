// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary-plugin-gcp/internal/credential"
	"github.com/hashicorp/boundary-plugin-gcp/internal/values"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// expectedServiceAccountKeys is the number of service account keys
	// expected to be created in the Terraform project.
	expectedServiceAccountKeys = 6
)

// TestTerraformer is an object representing the lifecycle of a
// particular Terraform project.
//
// Note that Terraform must be installed in the system PATH (not to
// be confused with the working directory below). This object does
// not manage anything with regards to installation or version
// management.
type TestTerraformer struct {
	// The full path to the Terraform binary, set during initialization
	// to the binary found in the system path.
	tfPath string

	// The working directory for Terraform commands.
	workDir string

	// The Terraform state. Use the Output method to look up particular
	// outputs from the Terraform state.
	state *tfjson.State

	// Keeps track of whether or not we have run the init command
	// during this run of Terraform. This only needs to be done once.
	// Do not use initErr directly; it stores the init error if one was
	// encountered on init.
	initOnce sync.Once
	initErr  error
}

// NewTestTerraformer initializes a Terraform directory. It just
// returns an initialized project, it does not perform any actions on
// it.
func NewTestTerraformer(workDir string) (*TestTerraformer, error) {
	tfPath, err := exec.LookPath("terraform")
	if err != nil {
		return nil, fmt.Errorf("LookPath error: %w", err)
	}

	if workDir == "" {
		return nil, errors.New("workDir is empty")
	}

	return &TestTerraformer{
		tfPath:  tfPath,
		workDir: workDir,
	}, nil
}

// Deploy runs the following commands, in order: init, apply, plan,
// json. The output of the JSON command is then imported to the
// internal state.
func (t *TestTerraformer) Deploy() error {
	if err := t.init(); err != nil {
		return fmt.Errorf("error running Terraform init: %w", err)
	}

	if err := t.apply(); err != nil {
		return fmt.Errorf("error running Terraform apply: %w", err)
	}

	if err := t.plan(); err != nil {
		return fmt.Errorf("error running Terraform plan: %w", err)
	}

	output, err := t.showJson()
	if err != nil {
		return fmt.Errorf("error getting Terraform plan JSON data: %w", err)
	}

	newState := new(tfjson.Plan)
	if err := json.Unmarshal(output, newState); err != nil {
		return fmt.Errorf("error reading new Terraform plan JSON data: %w", err)
	}

	t.state = newState.PriorState
	return nil
}

// Destroy runs the following commands, in order: init, destroy. The
// state is also cleared.
func (t *TestTerraformer) Destroy() error {
	if err := t.init(); err != nil {
		return fmt.Errorf("error running Terraform init: %w", err)
	}

	if err := t.destroy(); err != nil {
		return fmt.Errorf("error running Terraform destroy: %w", err)
	}

	t.state = nil
	return nil
}

// GetOutput returns the value of the output located at key.
//
// Outputs for the root module are supported only. It's an error to
// run this when no state exists.
func (t *TestTerraformer) GetOutput(key string) (any, error) {
	if key == "" {
		return nil, errors.New("key must not be empty")
	}

	if t.state == nil {
		return nil, errors.New("state is nil")
	}

	if t.state.Values == nil {
		return nil, errors.New("state integrity error: no state values")
	}

	if t.state.Values.Outputs == nil {
		return nil, errors.New("state integrity error: outputs is nil")
	}

	output, ok := t.state.Values.Outputs[key]
	if !ok {
		return nil, fmt.Errorf("output with key %q not found", key)
	}

	if output == nil {
		return nil, fmt.Errorf("state integrity error: output at key %q is nil", key)
	}

	return output.Value, nil
}

// GetOutputString wraps GetOutput and returns the value as a string. It's an
// error if the return value is actually not a string.
func (t *TestTerraformer) GetOutputString(key string) (string, error) {
	value, err := t.GetOutput(key)
	if err != nil {
		return "", err
	}

	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("expected output value at key %q to be string, got %T", key, value)
	}

	return str, nil
}

// GetOutputMap wraps GetOutput and returns the value as a map. It's an
// error if the return value is actually not a map.
func (t *TestTerraformer) GetOutputMap(key string) (map[string]any, error) {
	value, err := t.GetOutput(key)
	if err != nil {
		return nil, err
	}

	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected output value at key %q to be map, got %T", key, value)
	}

	return m, nil
}

// GetOutputSlice wraps GetOutput and returns the value as a slice. It's an
// error if the return value is actually not a slice.
func (t *TestTerraformer) GetOutputSlice(key string) ([]any, error) {
	value, err := t.GetOutput(key)
	if err != nil {
		return nil, err
	}

	m, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("expected output value at key %q to be slice, got %T", key, value)
	}

	return m, nil
}

// init runs "terraform init" in the project's working directory.
//
// This is only ever done once.
func (t *TestTerraformer) init() error {
	t.initOnce.Do(func() {
		cmd := exec.Command(t.tfPath, "init")
		cmd.Dir = t.workDir
		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			t.initErr = fmt.Errorf("%s\n%s", stdoutStderr, err)
		}
	})

	return t.initErr
}

// apply runs "terraform apply" in the project's working directory.
func (t *TestTerraformer) apply() error {
	cmd := exec.Command(t.tfPath, "apply", "-input=false", "-auto-approve")
	cmd.Dir = t.workDir
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\n%s", stdoutStderr, err)
	}

	return nil
}

// destroy runs "terraform destroy" in the project's working directory.
func (t *TestTerraformer) destroy() error {
	cmd := exec.Command(t.tfPath, "destroy", "-input=false", "-auto-approve")
	cmd.Dir = t.workDir
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\n%s", stdoutStderr, err)
	}

	return nil
}

// plan runs "terraform plan" in the project's working directory.
//
// Note that plan is not run as part of the apply workflow; rather,
// it's run to get the data for for importing the state via
// terraform-json. The apply method ignores the plan generated here.
func (t *TestTerraformer) plan() error {
	cmd := exec.Command(t.tfPath, "plan", "-input=false", "-out=plan.tfplan")
	cmd.Dir = t.workDir
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\n%s", stdoutStderr, err)
	}

	return nil
}

// showJson runs "terraform show -json". The output is returned along
// with any error.
//
// Output is only the results of stdout and should be suitable for
// parsing.
//
// This method expects the plan.tfplan file to be generated in the
// working directory already. This can be done with the plan method.
func (t *TestTerraformer) showJson() ([]byte, error) {
	cmd := exec.Command(t.tfPath, "show", "-json", "plan.tfplan")
	cmd.Dir = t.workDir
	output, err := cmd.Output()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return nil, err
		}

		return nil, fmt.Errorf("%s\n%s", exitErr.Stderr, exitErr)
	}

	return output, nil
}

func requireCredentialsInvalid(
	t *testing.T,
	projectId string,
	clientEmail string,
	privateKeyId string,
	privateKey string) {
	t.Helper()
	require := require.New(t)

	c, err := credential.NewConfig(
		credential.WithProjectId(projectId),
		credential.WithClientEmail(clientEmail),
		credential.WithPrivateKeyId(privateKeyId),
		credential.WithPrivateKey(privateKey))
	require.NoError(err)

	creds, err := c.GenerateCredentials(context.Background())
	require.NoError(err)

	// We need to wait for invalidation as while gcp waits for
	// credential creation, deletion of the old credentials returns
	// immediately.
	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
waitErr:
	for {
		_, err = c.ValidateIamPermissions(timeoutCtx, []string{credential.ComputeInstancesListPermission}, option.WithTokenSource(creds.TokenSource))
		if err != nil {
			break
		}

		select {
		case <-time.After(time.Second):
			// pass

		case <-timeoutCtx.Done():
			break waitErr
		}
	}

	require.Error(err)
	require.Contains(err.Error(), "failed to validate IAM permissions")
}

func requireCredentialsValid(
	t *testing.T,
	projectId string,
	clientEmail string,
	privateKeyId string,
	privateKey string) {
	t.Helper()
	require := require.New(t)

	c, err := credential.NewConfig(
		credential.WithProjectId(projectId),
		credential.WithClientEmail(clientEmail),
		credential.WithPrivateKeyId(privateKeyId),
		credential.WithPrivateKey(privateKey))
	require.NoError(err)

	creds, err := c.GenerateCredentials(context.Background())
	require.NoError(err)

	_, err = c.ValidateIamPermissions(context.Background(), []string{credential.ComputeInstancesListPermission}, option.WithTokenSource(creds.TokenSource))
	require.NoError(err)
}

func validatePersistedSecrets(
	t *testing.T,
	persistedSecrets *structpb.Struct,
	projectId string,
	clientEmail string,
	privateKeyId string,
	privateKey string,
	rotate bool) (string, string) {
	t.Helper()
	require := require.New(t)

	require.NotNil(persistedSecrets)
	persistedPrivateKeyId, err := values.GetStringValue(persistedSecrets, credential.ConstPrivateKeyId, true)
	require.NoError(err)
	require.NotZero(persistedPrivateKeyId)
	if rotate {
		require.NotEqual(privateKeyId, persistedPrivateKeyId)
	} else {
		require.Equal(privateKeyId, persistedPrivateKeyId)
	}

	persistedPrivateKey, err := values.GetStringValue(persistedSecrets, credential.ConstPrivateKey, true)
	require.NoError(err)
	require.NotZero(persistedPrivateKey)
	if rotate {
		require.NotEqual(privateKey, persistedPrivateKey)
	} else {
		require.Equal(privateKey, persistedPrivateKey)
	}

	persistedCredsLastRotatedTime, err := values.GetTimeValue(persistedSecrets, credential.ConstCredsLastRotatedTime)
	require.NoError(err)
	if rotate {
		require.NotZero(persistedCredsLastRotatedTime)
		requireCredentialsInvalid(t, projectId, clientEmail, privateKeyId, privateKey)
	} else {
		require.Zero(persistedCredsLastRotatedTime)
	}

	return persistedPrivateKeyId, persistedPrivateKey
}

func validateUpdateSecrets(
	t *testing.T,
	projectId string,
	clientEmail string,
	persistedSecrets *structpb.Struct,
	currentCredsLastRotatedTime time.Time,
	currentPrivateKeyId string,
	currentPrivateKey string,
	newPrivateKeyId string,
	newPrivateKey string,
	rotated bool,
	rotate bool) (string, string) {
	t.Helper()
	require := require.New(t)

	// Complex checks based on the scenarios.
	persistedPrivateKeyId, err := values.GetStringValue(persistedSecrets, credential.ConstPrivateKeyId, true)
	require.NoError(err)
	require.NotZero(persistedPrivateKeyId)
	persistedPrivateKey, err := values.GetStringValue(persistedSecrets, credential.ConstPrivateKey, true)
	require.NoError(err)
	require.NotZero(persistedPrivateKey)
	persistedCredsLastRotatedTime, err := values.GetTimeValue(persistedSecrets, credential.ConstCredsLastRotatedTime)
	require.NoError(err)

	// Our test scenarios are complex due the multi-dimensional nature
	// of criteria, so we lay them out in a switch below.
	switch {
	case newPrivateKeyId != "" && rotated && rotate:
		// The new private key ID was provided, we had previously rotated
		// the credentials before, and the new credential set is to be
		// rotated as well. In this case, the old credentials should have
		// been deleted, and the new credentials should have been rotated,
		// hence, should not match the new credentials initially
		// provided. Rotation time should be non-zero and updated.
		requireCredentialsInvalid(t, projectId, clientEmail, currentPrivateKeyId, currentPrivateKey)
		require.NotEqual(persistedPrivateKeyId, newPrivateKeyId)
		require.NotEqual(persistedPrivateKey, newPrivateKey)
		require.NotZero(persistedCredsLastRotatedTime)
		require.True(persistedCredsLastRotatedTime.After(currentCredsLastRotatedTime))

	case newPrivateKeyId != "" && rotated && !rotate:
		// The new private key ID was provided, we had previously rotated
		// the credentials before, and the new credential is *not*
		// rotated. In this case, the old credentials should have
		// been deleted, But the new credentials should have not been
		// rotated, and hence should be the same. Rotation time should be
		// zero.
		requireCredentialsInvalid(t, projectId, clientEmail, currentPrivateKeyId, currentPrivateKey)
		require.Equal(persistedPrivateKeyId, newPrivateKeyId)
		require.Equal(persistedPrivateKey, newPrivateKey)
		require.Zero(persistedCredsLastRotatedTime)

	case newPrivateKeyId != "" && !rotated && rotate:
		// The new private key was provided, we *have not* previously
		// rotated the credentials, and the new credential set is to be
		// rotated. In this case, the old credentials should have been
		// left alone, and the new credentials should have been rotated,
		// hence, should not match the new credentials initially
		// provided. Rotation time should be non-zero, but updated.
		requireCredentialsValid(t, projectId, clientEmail, currentPrivateKeyId, currentPrivateKey)
		require.NotEqual(persistedPrivateKeyId, newPrivateKeyId)
		require.NotEqual(persistedPrivateKey, newPrivateKey)
		require.NotZero(persistedCredsLastRotatedTime)
		require.True(persistedCredsLastRotatedTime.After(currentCredsLastRotatedTime))

	case newPrivateKeyId != "" && !rotated && !rotate:
		// The new private key was provided, but we have not rotated
		// the credentials previously and we still don't plan on rotating
		// them. In this case, the old credentials should still be valid,
		// and the persisted ones should match the new ones provided.
		// Rotation time should be zero.
		requireCredentialsValid(t, projectId, clientEmail, currentPrivateKeyId, currentPrivateKey)
		require.Equal(persistedPrivateKeyId, newPrivateKeyId)
		require.Equal(persistedPrivateKey, newPrivateKey)
		require.Zero(persistedCredsLastRotatedTime)

	case newPrivateKeyId == "" && rotated && rotate:
		// No new credentials have been provided, but we have previously
		// rotated and are still rotating credentials. This is a no-op.
		// Existing credentials should still be valid and match the ones
		// persisted to state. Rotation time should be identical since
		// no new rotation occurred.
		requireCredentialsValid(t, projectId, clientEmail, currentPrivateKeyId, currentPrivateKey)
		require.Equal(persistedPrivateKeyId, currentPrivateKeyId)
		require.Equal(persistedPrivateKey, currentPrivateKey)
		require.NotZero(persistedCredsLastRotatedTime)
		require.True(currentCredsLastRotatedTime.Equal(persistedCredsLastRotatedTime))

	case newPrivateKeyId == "" && rotated && !rotate:
		// No new credentials have been provided, and we have previously
		// rotated the credentials. This is actually an error, but we
		// don't test it here; it's covered in unit testing (see
		// plugin_test.go).
		require.FailNow("testing rotated-to-not-rotated scenario not implemented by this helper")

	case newPrivateKeyId == "" && !rotated && rotate:
		// No new credentials have been provided, and while we did not
		// rotate before, we want to switch to rotation. In this case,
		// the existing persisted credentials should have been rotated,
		// with a new non-zero timestamp.
		requireCredentialsInvalid(t, projectId, clientEmail, currentPrivateKeyId, currentPrivateKey)
		require.NotEqual(persistedPrivateKeyId, currentPrivateKeyId)
		require.NotEqual(persistedPrivateKey, currentPrivateKey)
		require.NotZero(persistedCredsLastRotatedTime)

	case newPrivateKeyId == "" && !rotated && !rotate:
		// No new credentials have been provided and we have not, nor do
		// not, plan on rotating the credentials. This is a no-op.
		// Existing credentials should still be valid and match the ones
		// persisted to state. Rotation time should remain at zero.
		requireCredentialsValid(t, projectId, clientEmail, currentPrivateKeyId, currentPrivateKey)
		require.Equal(persistedPrivateKeyId, currentPrivateKeyId)
		require.Equal(persistedPrivateKey, currentPrivateKey)
		require.Zero(persistedCredsLastRotatedTime)

	default:
		// Scenario was reached that was not covered by this function.
		require.FailNow("unknown test scenario")
	}

	return persistedPrivateKeyId, persistedPrivateKey
}
