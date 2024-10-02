// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"fmt"

	"github.com/hashicorp/boundary-plugin-gcp/internal/errors"
	"github.com/hashicorp/boundary-plugin-gcp/internal/values"
	"google.golang.org/protobuf/types/known/structpb"
)

// CredentialAttributes contain attributes used for authenticating to GCP
// and accessing a list of instances
type CredentialAttributes struct {
	// ProjectId is the project id associated with the GCP credentials
	ProjectId string

	// Zone is the zone  associated with the GCP credentials
	Zone string

	// DisableCredentialRotation disables the rotation of GCP service account key associated with the plugin
	DisableCredentialRotation bool

	// ClientEmail is the email associated with the GCP cloud credentials
	ClientEmail string

	// TargetServiceAccount is the unique identifier for the service account that will be impersonated
	TargetServiceAccountId string
}

// GetCredentialAttributes checks attributes required by GCP to access
// a list of instances and populate them into Boundary's host catalog
func GetCredentialAttributes(in *structpb.Struct) (*CredentialAttributes, error) {
	badFields := make(map[string]string)

	projectId, err := values.GetStringValue(in, ConstProjectId, true)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstProjectId)] = err.Error()
	}

	zone, err := values.GetStringValue(in, ConstZone, true)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstZone)] = err.Error()
	}

	disableCredentialRotation, err := values.GetBoolValue(in, ConstDisableCredentialRotation, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstDisableCredentialRotation)] = err.Error()
	}

	clientEmail, err := values.GetStringValue(in, ConstClientEmail, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstClientEmail)] = err.Error()
	}

	targetServiceAccountId, err := values.GetStringValue(in, ConstTargetServiceAccountID, false)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstTargetServiceAccountID)] = err.Error()
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Error in the attributes provider", badFields)
	}

	return &CredentialAttributes{
		ProjectId:                 projectId,
		Zone:                      zone,
		DisableCredentialRotation: disableCredentialRotation,
		ClientEmail:               clientEmail,
		TargetServiceAccountId:    targetServiceAccountId,
	}, nil
}

// GetCredentialsConfig parses values out of a protobuf struct secrets and returns a
// Config used for configuring an GCP session. An status error is returned
// with an InvalidArgument code if any unrecognized fields are found in the protobuf
// struct input.
func GetCredentialsConfig(secrets *structpb.Struct, attrs *CredentialAttributes) (*Config, error) {
	// initialize secrets if it is nil
	// secrets can be nil because static credentials are optional
	if secrets == nil {
		secrets = &structpb.Struct{
			Fields: make(map[string]*structpb.Value),
		}
	}

	unknownFields := values.StructFields(secrets)
	badFields := make(map[string]string)

	privateKeyId, err := values.GetStringValue(secrets, ConstPrivateKeyId, false)
	if err != nil {
		badFields[fmt.Sprintf("secrets.%s", ConstPrivateKeyId)] = err.Error()
	}
	delete(unknownFields, ConstPrivateKeyId)

	privateKey, err := values.GetStringValue(secrets, ConstPrivateKey, false)
	if err != nil {
		badFields[fmt.Sprintf("secrets.%s", ConstPrivateKey)] = err.Error()
	}
	delete(unknownFields, ConstPrivateKey)

	for s := range unknownFields {
		badFields[fmt.Sprintf("secrets.%s", s)] = "unrecognized field"
	}

	switch {
	// dynamic credentials requires the target service account id, cl and private key
	case attrs.TargetServiceAccountId != "" && (privateKey == "" || attrs.ClientEmail == ""):
		badFields[fmt.Sprintf("secrets.%s", ConstPrivateKey)] = "must not be empty when target service account id is set"
		badFields[fmt.Sprintf("secrets.%s", ConstClientEmail)] = "must not be empty when target service account id is set"
	// static credentials requires the private key and client email
	case privateKey != "" && attrs.ClientEmail == "":
		badFields[fmt.Sprintf("secrets.%s", ConstClientEmail)] = "must not be empty when private key is set"
	case attrs.ClientEmail != "" && privateKey == "":
		badFields[fmt.Sprintf("secrets.%s", ConstPrivateKey)] = "must not be empty when client email is set"
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Error in the secrets provided", badFields)
	}

	return &Config{
		ProjectId:              attrs.ProjectId,
		ClientEmail:            attrs.ClientEmail,
		Zone:                   attrs.Zone,
		PrivateKey:             privateKey,
		PrivateKeyId:           privateKeyId,
		TargetServiceAccountId: attrs.TargetServiceAccountId,
	}, nil
}
