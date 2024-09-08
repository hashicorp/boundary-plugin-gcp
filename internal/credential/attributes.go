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
