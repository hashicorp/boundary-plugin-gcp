// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

const (
	ConstListInstancesFilter = "filter"
	ConstInstanceGroup       = "instance_group"
)

var allowedSetFields = map[string]struct{}{
	ConstListInstancesFilter: {},
	ConstInstanceGroup:       {},
}
