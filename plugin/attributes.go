// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"fmt"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	cred "github.com/hashicorp/boundary-plugin-gcp/internal/credential"
	"github.com/hashicorp/boundary-plugin-gcp/internal/errors"
	"github.com/hashicorp/boundary-plugin-gcp/internal/values"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// CatalogAttributes defines a set of attributes for the host catalog
type CatalogAttributes struct {
	*cred.CredentialAttributes
}

func getCatalogAttributes(in *structpb.Struct) (*CatalogAttributes, error) {
	unknownFields := values.StructFields(in)
	badFields := make(map[string]string)

	var err error
	credAttributes, err := cred.GetCredentialAttributes(in)
	if err != nil {
		return nil, err
	}

	for s := range unknownFields {
		switch s {
		// Ignore knownFields from CredentialAttributes
		case cred.ConstProject:
			continue
		case cred.ConstZone:
			continue
		default:
			badFields[fmt.Sprintf("attributes.%s", s)] = "unrecognized field"
		}
	}

	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Invalid arguments in catalog attributes", badFields)
	}

	return &CatalogAttributes{
		CredentialAttributes: credAttributes,
	}, nil
}

// SetAttributes defines attributes fro the host set
type SetAttributes struct {
	Filter        string `mapstructure:"filter"`
	InstanceGroup string `mapstructure:"instance_group"`
}

func getSetAttributes(in *structpb.Struct) (*SetAttributes, error) {
	var setAttrs SetAttributes

	badFields := make(map[string]string)
	unknownFields := values.StructFields(in)

	if _, filter := unknownFields[ConstListInstancesFilter]; filter {
		if _, ig := unknownFields[ConstInstanceGroup]; ig {
			return nil, errors.InvalidArgumentError("Error in the attributes provided, cannot define both filter and instance group", nil)
		}
	}

	delete(unknownFields, ConstListInstancesFilter)
	delete(unknownFields, ConstInstanceGroup)

	for a := range unknownFields {
		badFields[fmt.Sprintf("attributes.%s", a)] = "unrecognized field"
	}
	if len(badFields) > 0 {
		return nil, errors.InvalidArgumentError("Error in the attributes provided", badFields)
	}

	// Mapstructure complains if it expects a slice as output and sees a scalar
	// value. Rather than use WeakDecode and risk unintended consequences, I'm
	// manually making this change if necessary.
	inMap := in.AsMap()
	if filtersRaw, ok := inMap[ConstListInstancesFilter]; ok {
		switch filterVal := filtersRaw.(type) {
		case string:
			inMap[ConstListInstancesFilter] = string(filterVal)
		}
	}

	if instanceGroupRaw, ok := inMap[ConstInstanceGroup]; ok {
		switch instanceGroupValue := instanceGroupRaw.(type) {
		case string:
			inMap[ConstInstanceGroup] = string(instanceGroupValue)
		}
	}

	if err := mapstructure.Decode(inMap, &setAttrs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error decoding set attributes: %s", err)
	}

	return &setAttrs, nil
}

func buildListInstancesRequest(attributes *SetAttributes, catalog *CatalogAttributes) *computepb.ListInstancesRequest {
	request := &computepb.ListInstancesRequest{
		Project: catalog.Project,
		Zone:    catalog.Zone,
	}

	if len(attributes.Filter) > 1 {
		request.Filter = &attributes.Filter
	}

	return request
}

func buildListInstanceGroupsRequest(attributes *SetAttributes, catalog *CatalogAttributes) *computepb.ListInstancesInstanceGroupsRequest {
	request := &computepb.ListInstancesInstanceGroupsRequest{
		InstanceGroup: attributes.InstanceGroup,
		Project:       catalog.Project,
		Zone:          catalog.Zone,
	}

	if len(attributes.Filter) > 1 {
		request.Filter = &attributes.Filter
	}

	return request
}
