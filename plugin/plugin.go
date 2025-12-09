// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"github.com/hashicorp/boundary-plugin-gcp/plugin/service/host"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// Ensure that HostPlugin implements the following services:
//
//	HostPluginServiceServer
var (
	_ pb.HostPluginServiceServer = (*host.HostPlugin)(nil)
)

// GCPPlugin contains a collection of all GCP plugin services.
type GCPPlugin struct {
	// HostPlugin implements the HostPluginServiceServer interface for
	// supporting dynamically sourcing hosts from GCP Compute Engine.
	*host.HostPlugin
}

func NewGCPPlugin() *GCPPlugin {
	return &GCPPlugin{
		HostPlugin: &host.HostPlugin{},
	}
}
