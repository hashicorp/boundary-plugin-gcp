# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "labels" {
  type = map(string)
  default = {
    repository = "boundary-plugin-gcp"
    purpose    = "testing"
  }
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "num_instances" {
  type    = number
  default = 3
}

variable "service_account_email" {
  type    = string
  default = null
}

variable "client_cidr_block" {
  type = string
}