# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

data "google_client_openid_userinfo" "current" {}

variable "labels" {
  type = map(string)
  default = {
    repository = "boundary-plugin-gcp"
    purpose    = "testing"
  }
}

variable "project_id" {
  type = string
}

variable "region" {
  type    = string
}

variable "zone" {
  type    = string
}

variable "num_instances" {
  type    = number
  default = 3
}

variable "service_account_email" {
  type    = string
  default = null
}

variable "rolesList" {
  type = list(string)
  description = "List of roles to assign to the service account"
  default = ["roles/compute.viewer","roles/iam.serviceAccountKeyAdmin"]
}

variable "user_prefix" {
  type = string
  default = "boundary-gcp-plugin"
}

variable "num_service_account_keys" {
  type    = number
  default = 6
}