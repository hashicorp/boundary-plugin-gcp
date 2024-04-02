// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"testing"

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
			name: "missing project and zone",
			in: &structpb.Struct{
				Fields: make(map[string]*structpb.Value),
			},
			expectedErrContains: "attributes.project: missing required value \"project\", attributes.zone: missing required value \"zone\"",
		},
		{
			name: "unknown fields",
			in: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"project": structpb.NewStringValue("test-12345"),
					"zone":    structpb.NewStringValue("us-central-1a"),
					"foo":     structpb.NewBoolValue(true),
					"bar":     structpb.NewBoolValue(true),
				},
			},
			expectedErrContains: "attributes.bar: unrecognized field, attributes.foo: unrecognized field",
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
			name: "example filter",
			in: map[string]any{
				ConstListInstancesFilter: "tags.items=my-tag AND -tags.items=my-other-tag) OR tags.items=alternative-tag",
			},
			expected: &SetAttributes{
				Filter: "tags.items=my-tag AND -tags.items=my-other-tag) OR tags.items=alternative-tag",
			},
		},
		{
			name: "example instance group",
			in: map[string]any{
				ConstInstanceGroup: "test",
			},
			expected: &SetAttributes{
				InstanceGroup: "test",
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
