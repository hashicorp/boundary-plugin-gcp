// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import (
	"context"
	"errors"
	"path"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	NumberMaxResults = uint32(100)
)

// GoogleClient contains clients and attributes for authenticating to Google Cloud
// and finding instances
type GoogleClient struct {
	InstancesClient     *compute.InstancesClient
	InstanceGroupClient *compute.InstanceGroupsClient
	Context             context.Context
	Project             string
	Zone                string
}

func (c *GoogleClient) getInstances(request *computepb.ListInstancesRequest) ([]*computepb.Instance, error) {
	hosts := []*computepb.Instance{}
	it := c.InstancesClient.List(c.Context, request)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error listing instances: %s", err)
		}
		hosts = append(hosts, resp)
	}
	return hosts, nil
}

func (c *GoogleClient) getInstancesForInstanceGroup(request *computepb.ListInstancesInstanceGroupsRequest) ([]*computepb.Instance, error) {
	hosts := []*computepb.Instance{}
	instances := c.InstanceGroupClient.ListInstances(c.Context, request)

	for {
		resp, err := instances.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error listing instances for instance group %s: %s", request.InstanceGroup, err)
		}

		instance, err := c.InstancesClient.Get(c.Context, &computepb.GetInstanceRequest{
			Instance: path.Base(resp.GetInstance()),
			Project:  request.Project,
			Zone:     request.Zone,
		})
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error getting instance %s for instance group %s: %s", resp.GetInstance(), request.InstanceGroup, err)
		}

		hosts = append(hosts, instance)
	}
	return hosts, nil
}

func instanceToHost(instance *computepb.Instance) (*pb.ListHostsResponseHost, error) {
	if instance.GetSelfLink() == "" {
		return nil, errors.New("response integrity error: missing instance self-link")
	}

	if instance.GetName() == "" {
		return nil, errors.New("response integrity error: missing instance name")
	}

	result := new(pb.ListHostsResponseHost)

	result.ExternalId = instance.GetSelfLink()
	result.ExternalName = instance.GetName()

	// Now go through all of the interfaces and log the IP address of
	// every interface.
	for _, iface := range instance.GetNetworkInterfaces() {
		// Populate default IP addresses/DNS name similar to how we do
		// for the entire instance.
		result.IpAddresses = appendDistinct(result.IpAddresses, iface.NetworkIP)

		for _, external := range iface.AccessConfigs {
			result.IpAddresses = appendDistinct(result.IpAddresses, external.NatIP)
		}

		// Add the IPv6 addresses.
		result.IpAddresses = appendDistinct(result.IpAddresses, iface.Ipv6Address)
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
