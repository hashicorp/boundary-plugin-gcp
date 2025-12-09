// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"fmt"
	"strings"

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
		case cred.ConstProjectId:
			continue
		case cred.ConstZone:
			continue
		case cred.ConstDisableCredentialRotation:
			continue
		case cred.ConstClientEmail:
			continue
		case cred.ConstTargetServiceAccountID:
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
	Filters []string `mapstructure:"filters"`
}

func getSetAttributes(in *structpb.Struct) (*SetAttributes, error) {
	var setAttrs SetAttributes

	badFields := make(map[string]string)
	unknownFields := values.StructFields(in)

	delete(unknownFields, ConstListInstancesFilter)

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
			inMap[ConstListInstancesFilter] = []string{filterVal}
		}
	}

	if err := mapstructure.Decode(inMap, &setAttrs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error decoding set attributes: %s", err)
	}

	return &setAttrs, nil
}

func buildListInstancesRequest(attributes *SetAttributes, catalog *CatalogAttributes) (*computepb.ListInstancesRequest, error) {
	request := &computepb.ListInstancesRequest{
		Project: catalog.ProjectId,
		Zone:    catalog.Zone,
	}

	filters, err := buildFilters(attributes)
	if err != nil {
		return nil, fmt.Errorf("error building filters: %w", err)
	}

	if len(filters) > 0 {
		filters := strings.Join(filters, " AND ")
		request.Filter = &filters
	}

	return request, nil
}
