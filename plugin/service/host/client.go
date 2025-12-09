// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"errors"
	"strconv"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func getInstances(ctx context.Context, instancesClient InstancesAPI, request *computepb.ListInstancesRequest) ([]*computepb.Instance, error) {
	hosts := []*computepb.Instance{}
	it := instancesClient.List(ctx, request)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, status.Errorf(codes.Unknown, "error listing instances: %s", err)
		}
		hosts = append(hosts, resp)
	}
	return hosts, nil
}

func instanceToHost(instance *computepb.Instance) (*pb.ListHostsResponseHost, error) {
	if instance.GetId() == 0 {
		return nil, errors.New("response integrity error: missing instance id")
	}

	if instance.GetName() == "" {
		return nil, errors.New("response integrity error: missing instance name")
	}

	result := new(pb.ListHostsResponseHost)

	result.ExternalId = strconv.FormatUint(instance.GetId(), 10)
	result.ExternalName = instance.GetName()

	// Internal DNS name is the hostname of the instance.
	// https://cloud.google.com/compute/docs/networking/using-internal-dns
	dnsName := instance.GetHostname()
	result.DnsNames = appendDistinct(result.DnsNames, &dnsName)

	// Now go through all of the interfaces and log the IP address of
	// every interface.
	for _, iface := range instance.GetNetworkInterfaces() {
		// Populate default IP addresses name similar to how we do
		// for the entire instance.
		result.IpAddresses = appendDistinct(result.IpAddresses, iface.NetworkIP)

		for _, external := range iface.AccessConfigs {
			result.IpAddresses = appendDistinct(result.IpAddresses, external.NatIP)
			result.IpAddresses = appendDistinct(result.IpAddresses, external.ExternalIpv6)
		}

		// Add the IPv6 addresses.
		result.IpAddresses = appendDistinct(result.IpAddresses, iface.Ipv6Address)
		if iface.Ipv6AccessConfigs != nil {
			for _, external := range iface.Ipv6AccessConfigs {
				result.IpAddresses = appendDistinct(result.IpAddresses, external.ExternalIpv6)
			}
		}
	}

	// Done
	return result, nil
}

// appendDistinct will append the elements to the slice
// if an element is not nil, empty, and does not exist in slice.
func appendDistinct(slice []string, elems ...*string) []string {
	for _, e := range elems {
		if e == nil || *e == "" || stringInSlice(slice, *e) {
			continue
		}
		slice = append(slice, *e)
	}
	return slice
}

func stringInSlice(s []string, x string) bool {
	for _, y := range s {
		if x == y {
			return true
		}
	}
	return false
}
