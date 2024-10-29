// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

const (
	// ConstListInstancesFilter refers to a Google Cloud SDK filter to search for instances
	ConstListInstancesFilter = "filters"
)

var allowedSetFields = map[string]struct{}{
	ConstListInstancesFilter: {},
}
