// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"testing"

	"cloud.google.com/go/compute/apiv1/computepb"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
)

func TestInstanceToHost(t *testing.T) {
	exampleId := "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances/test-instance"
	examplePrivateIp := "10.0.0.1"
	examplePrivateIp2 := "10.0.0.2"
	examplePublicIp := "1.1.1.1"
	examplePublicIp2 := "1.1.1.2"
	exampleIPv6 := "some::fake::address"

	cases := []struct {
		name        string
		instance    *computepb.Instance
		expected    *pb.ListHostsResponseHost
		expectedErr string
	}{
		{
			name:        "missing instance self-link",
			instance:    &computepb.Instance{},
			expectedErr: "response integrity error: missing instance self-link",
		},
		{
			name: "good, single private IP with public IP address",
			instance: &computepb.Instance{
				SelfLink: &exampleId,
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
				ExternalId:  exampleId,
				IpAddresses: []string{examplePrivateIp, examplePublicIp},
			},
		},
		{
			name: "good, single private IP address",
			instance: &computepb.Instance{
				SelfLink: &exampleId,
				NetworkInterfaces: []*computepb.NetworkInterface{
					{
						NetworkIP:     &examplePrivateIp,
						AccessConfigs: []*computepb.AccessConfig{},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  exampleId,
				IpAddresses: []string{examplePrivateIp},
			},
		},
		{
			name: "good, multiple interfaces",
			instance: &computepb.Instance{
				SelfLink: &exampleId,
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
				ExternalId:  exampleId,
				IpAddresses: []string{examplePrivateIp, examplePublicIp, examplePrivateIp2, examplePublicIp2},
			},
		},
		{
			name: "good, single private IP address with IPv6",
			instance: &computepb.Instance{
				SelfLink: &exampleId,
				NetworkInterfaces: []*computepb.NetworkInterface{
					{
						NetworkIP:     &examplePrivateIp,
						Ipv6Address:   &exampleIPv6,
						AccessConfigs: []*computepb.AccessConfig{},
					},
				},
			},
			expected: &pb.ListHostsResponseHost{
				ExternalId:  exampleId,
				IpAddresses: []string{examplePrivateIp, exampleIPv6},
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
