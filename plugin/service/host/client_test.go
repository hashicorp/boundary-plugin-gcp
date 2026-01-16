// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/hashicorp/boundary-plugin-gcp/internal/credential"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
)

func TestInstanceToHost(t *testing.T) {
	exampleId := uint64(123456789)
	examplePrivateIp := "10.0.0.1"
	examplePrivateIp2 := "10.0.0.2"
	examplePublicIp := "1.1.1.1"
	examplePublicIp2 := "1.1.1.2"
	exampleIPv6 := "some::fake::address"
	exampleName := "test-instance"

	cases := []struct {
		name        string
		instance    *computepb.Instance
		expected    *pb.ListHostsResponseHost
		expectedErr string
	}{
		{
			name: "missing instance id",
			instance: &computepb.Instance{
				Name: &exampleName,
			},
			expectedErr: "response integrity error: missing instance id",
		},
		{
			name: "missing instance name",
			instance: &computepb.Instance{
				Id: &exampleId,
			},
			expectedErr: "response integrity error: missing instance name",
		},
		{
			name: "good, single private IP with public IP address",
			instance: &computepb.Instance{
				Id:   &exampleId,
				Name: &exampleName,
				NetworkInterfaces: []*computepb.NetworkInterface{
					{
						NetworkIP: &examplePrivateIp,
						AccessConfigs: []*computepb.AccessConfig{
							{
								NatIP: &examplePublicIp,
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:   strconv.FormatUint(exampleId, 10),
				ExternalName: exampleName,
				IpAddresses:  []string{examplePrivateIp, examplePublicIp},
			},
		},
		{
			name: "good, single private IP address",
			instance: &computepb.Instance{
				Id:   &exampleId,
				Name: &exampleName,
				NetworkInterfaces: []*computepb.NetworkInterface{
					{
						NetworkIP:     &examplePrivateIp,
						AccessConfigs: []*computepb.AccessConfig{},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:   strconv.FormatUint(exampleId, 10),
				ExternalName: exampleName,
				IpAddresses:  []string{examplePrivateIp},
			},
		},
		{
			name: "good, multiple interfaces",
			instance: &computepb.Instance{
				Id:   &exampleId,
				Name: &exampleName,
				NetworkInterfaces: []*computepb.NetworkInterface{
					{
						NetworkIP: &examplePrivateIp,
						AccessConfigs: []*computepb.AccessConfig{
							{
								NatIP: &examplePublicIp,
							},
						},
					},
					{
						NetworkIP: &examplePrivateIp2,
						AccessConfigs: []*computepb.AccessConfig{
							{
								NatIP: &examplePublicIp2,
							},
						},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:   strconv.FormatUint(exampleId, 10),
				ExternalName: exampleName,
				IpAddresses:  []string{examplePrivateIp, examplePublicIp, examplePrivateIp2, examplePublicIp2},
			},
		},
		{
			name: "good, single private IP address with IPv6",
			instance: &computepb.Instance{
				Id:   &exampleId,
				Name: &exampleName,
				NetworkInterfaces: []*computepb.NetworkInterface{
					{
						NetworkIP:     &examplePrivateIp,
						Ipv6Address:   &exampleIPv6,
						AccessConfigs: []*computepb.AccessConfig{},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:   strconv.FormatUint(exampleId, 10),
				ExternalName: exampleName,
				IpAddresses:  []string{examplePrivateIp, exampleIPv6},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := instanceToHost(tc.instance)
			if tc.expectedErr != "" {
				require.EqualError(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Equal(tc.expected, actual)
		})
	}
}

func TestGetInstances(t *testing.T) {
	ctx := context.Background()

	exampleId := uint64(123456789)
	exampleName := "test-instance"
	exampleInstance := &computepb.Instance{
		Id:   &exampleId,
		Name: &exampleName,
	}

	cases := []struct {
		name            string
		instancesClient InstancesAPI
		request         *computepb.ListInstancesRequest
		expected        []*computepb.Instance
		expectedErr     string
	}{
		{
			name: "successful retrieval",
			instancesClient: func() InstancesAPI {
				fn := newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{
						Items: []*computepb.Instance{exampleInstance},
					}),
					testMockInstancesWithListInstancesError(nil),
				)
				client, err := fn(&credential.Config{})
				require.NoError(t, err)
				return client
			}(),
			request:  &computepb.ListInstancesRequest{},
			expected: []*computepb.Instance{exampleInstance},
		},
		{
			name: "error during listing",
			instancesClient: func() InstancesAPI {
				fn := newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{}),
					testMockInstancesWithListInstancesError(errors.New("internal error")),
				)
				client, err := fn(&credential.Config{})
				require.NoError(t, err)
				return client
			}(),
			request:     &computepb.ListInstancesRequest{},
			expectedErr: "error listing instances",
		},
		{
			name: "no instances",
			instancesClient: func() InstancesAPI {
				fn := newTestMockInstances(ctx,
					nil,
					testMockInstancesWithListInstancesOutput(&computepb.InstanceList{}),
					testMockInstancesWithListInstancesError(nil),
				)
				client, err := fn(&credential.Config{})
				require.NoError(t, err)
				return client
			}(),
			request:  &computepb.ListInstancesRequest{},
			expected: []*computepb.Instance{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actual, err := getInstances(ctx, tc.instancesClient, tc.request)
			if tc.expectedErr != "" {
				require.ErrorContains(err, tc.expectedErr)
				return
			}

			require.NoError(err)
			require.Len(actual, len(tc.expected))
			if len(actual) > 0 {
				require.Equal(tc.expected[0].Name, actual[0].Name)
				require.Equal(tc.expected[0].Id, actual[0].Id)
			}
		})
	}
}
