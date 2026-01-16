// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"testing"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	cred "github.com/hashicorp/boundary-plugin-gcp/internal/credential"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetCatalogAttributes(t *testing.T) {
	cases := []struct {
		name                string
		in                  *structpb.Struct
		expected            *CatalogAttributes
		expectedErrContains string
	}{
		{
			name: "missing project_id and zone",
			in: &structpb.Struct{
				Fields: make(map[string]*structpb.Value),
			},
			expectedErrContains: "attributes.project_id: missing required value \"project_id\", attributes.zone: missing required value \"zone\"",
		},
		{
			name: "unknown fields",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"project_id": structpb.NewStringValue("test-12345"),
					"zone":       structpb.NewStringValue("us-central-1a"),
					"foo":        structpb.NewBoolValue(true),
					"bar":        structpb.NewBoolValue(true),
				},
			},
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
		},
		{
			name: "valid project and zone",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"project_id": structpb.NewStringValue("test-12345"),
					"zone":       structpb.NewStringValue("us-central-1a"),
				},
			},
			expected: &CatalogAttributes{&cred.CredentialAttributes{
				ProjectId: "test-12345",
				Zone:      "us-central-1a",
			}},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			actual, err := getCatalogAttributes(tc.in)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err), codes.InvalidArgument)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestGetSetAttributes(t *testing.T) {
	cases := []struct {
		name                string
		in                  map[string]any
		normalized          map[string]any
		expected            *SetAttributes
		expectedErrContains string
	}{
		{
			name:     "missing",
			in:       map[string]any{},
			expected: &SetAttributes{},
		},
		{
			name: "valid example filter",
			in: map[string]any{
				ConstListInstancesFilter: "tags.items=my-tag AND -tags.items=my-other-tag) OR tags.items=alternative-tag",
			},
			expected: &SetAttributes{
				Filters: []string{"tags.items=my-tag AND -tags.items=my-other-tag) OR tags.items=alternative-tag"},
			},
		},
		{
			name: "unknown fields",
			in: map[string]any{
				"foo": true,
				"bar": true,
			},
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			input, err := structpb.NewStruct(tc.in)
			require.NoError(err)

			actual, err := getSetAttributes(input)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				require.Equal(status.Code(err), codes.InvalidArgument)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestBuildListInstancesRequest(t *testing.T) {
	cases := []struct {
		name                string
		attributes          *SetAttributes
		catalog             *CatalogAttributes
		expected            *computepb.ListInstancesRequest
		expectedErrContains string
	}{
		{
			name: "valid request with single filter",
			attributes: &SetAttributes{
				Filters: []string{"tags.items=my-tag"},
			},
			catalog: &CatalogAttributes{
				CredentialAttributes: &cred.CredentialAttributes{
					ProjectId: "test-12345",
					Zone:      "us-central-1a",
				},
			},
			expected: &computepb.ListInstancesRequest{
				Project: "test-12345",
				Zone:    "us-central-1a",
				Filter:  stringPtr("tags.items=my-tag AND status = running"),
			},
		},
		{
			name: "valid request with multiple filters",
			attributes: &SetAttributes{
				Filters: []string{"tags.items=my-tag", "tags.items=my-other-tag"},
			},
			catalog: &CatalogAttributes{
				CredentialAttributes: &cred.CredentialAttributes{
					ProjectId: "test-12345",
					Zone:      "us-central-1a",
				},
			},
			expected: &computepb.ListInstancesRequest{
				Project: "test-12345",
				Zone:    "us-central-1a",
				Filter:  stringPtr("tags.items=my-tag AND tags.items=my-other-tag AND status = running"),
			},
		},
		{
			name: "error building filters",
			attributes: &SetAttributes{
				Filters: []string{"invalid-filter"},
			},
			catalog: &CatalogAttributes{
				CredentialAttributes: &cred.CredentialAttributes{
					ProjectId: "test-12345",
					Zone:      "us-central-1a",
				},
			},
			expectedErrContains: "error building filters",
		},
		{
			name: "valid request with no filters",
			attributes: &SetAttributes{
				Filters: []string{},
			},
			catalog: &CatalogAttributes{
				CredentialAttributes: &cred.CredentialAttributes{
					ProjectId: "test-12345",
					Zone:      "us-central-1a",
				},
			},
			expected: &computepb.ListInstancesRequest{
				Project: "test-12345",
				Zone:    "us-central-1a",
				Filter:  stringPtr("status = running"),
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			actual, err := buildListInstancesRequest(tc.attributes, tc.catalog)
			if tc.expectedErrContains != "" {
				require.Error(err)
				require.Contains(err.Error(), tc.expectedErrContains)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func stringPtr(s string) *string {
	return &s
}
