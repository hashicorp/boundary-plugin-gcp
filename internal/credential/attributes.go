// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

import (
	"fmt"

	"github.com/hashicorp/boundary-plugin-google/internal/errors"
	"github.com/hashicorp/boundary-plugin-google/internal/values"
	"google.golang.org/protobuf/types/known/structpb"
)

type CredentialAttributes struct {
	Project string
	Zone    string
}

func GetCredentialAttributes(in *structpb.Struct) (*CredentialAttributes, error) {
	badFields := make(map[string]string)

	project, err := values.GetStringValue(in, ConstProject, true)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstProject)] = err.Error()
	}

	zone, err := values.GetStringValue(in, ConstZone, true)
	if err != nil {
		badFields[fmt.Sprintf("attributes.%s", ConstZone)] = err.Error()
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Error in the attributes provider", badFields)
	}

	return &CredentialAttributes{
		Project: project,
		Zone:    zone,
	}, nil
}
