// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credential

const (
	ConstProject = "project"
	ConstZone    = "zone"
)

var AllowedCatalogFields = map[string]struct{}{
	ConstProject: {},
	ConstZone:    {},
}
