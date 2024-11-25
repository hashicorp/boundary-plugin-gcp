# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "client_email" {
  value = google_service_account.test_service_account.email
}

output "private_keys" {
  value = [for key in google_service_account_key.test_service_account_keys : jsondecode(base64decode(key.private_key)).private_key]
  sensitive = true
}

output "private_key_ids" {
  value = [for key in google_service_account_key.test_service_account_keys : chomp(reverse(split("/", key.id))[0])]
  sensitive = true
}

output "instance_ids" {
  value = google_compute_instance.instances.*.id
}

output "instance_tags" {
  value = {
    for instance in google_compute_instance.instances : instance.id => instance.tags
  }
}

output "instance_labels" {
  value = {
    for instance in google_compute_instance.instances : instance.id => instance.labels
  }
}