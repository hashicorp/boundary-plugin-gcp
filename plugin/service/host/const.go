// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

const (
	// ConstListInstancesFilter refers to a Google Cloud SDK filter to search for instances
	ConstListInstancesFilter = "filter"

	// ConstInstanceGroup refers to the name of a Google Cloud instance group
	ConstInstanceGroup = "instance_group"
)

var allowedSetFields = map[string]struct{}{
	ConstListInstancesFilter: {},
	ConstInstanceGroup:       {},
}
