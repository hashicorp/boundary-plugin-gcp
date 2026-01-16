// Copyright IBM Corp. 2024, 2025
// SPDX-License-Identifier: MPL-2.0

package host

// Package host provides a plugin for Boundary that retrieves host information from (GCP) Google Cloud Platform.
//
// A host catalog is a resource that contains hosts and host sets.
//
// A host is a resource that represents a computing element with a network address reachable from Boundary.
// A host belongs to a host catalog. Hosts can only be associated with host sets from the same host catalog as the host.
//
// A host set is a resource that represents a collection of hosts which are considered equivalent for the purposes of access control.
//
// The plugin supports authentication using GCP service account keys, impersonation of service accounts
// and Application Default Credentials.
//
// Host plugin supports credential rotation for GCP service account keys and impersonation of service accounts (only for base account)
// when the `disable_credential_rotation` attribute is set to false.
//
// The plugin implements Boundary's HostPluginService interface:
// https://github.com/hashicorp/boundary-enterprise/blob/cb9ce07d6907cbda6ce82e82627de372f18ba7e1/internal/proto/plugin/v1/host_plugin_service.proto#L15.
//
// # Filters
// Host Set filters are used to narrow down the list of hosts returned by the plugin.
// The filter string is expected to be in the format "key operator value".
// The operator is expected to be one of =, !=, >, <, <=, >=, :, eq, ne.
// as per GCP API documentation:
// https://cloud.google.com/compute/docs/reference/rest/v1/instances/list#filter
//
// If there is no explicit instance status filter, the default status will be set to
// `status = "running"`. This ensures that we filter on running instances only,
// saving time when processing results.
//
// Host Set filters are represented as a list of strings. When multiple filters are provided,
// the plugin will apply a logical `AND` operation to the filters.
