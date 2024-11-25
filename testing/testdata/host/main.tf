# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "random_id" "service_account_client_email" {
  prefix      = "test-${var.user_prefix}"
  byte_length = 2
}

resource "google_service_account" "test_service_account" {
  project      = var.project_id
  account_id   = random_id.service_account_client_email.dec
  display_name = "test-${var.user_prefix}"
}

resource "google_project_iam_binding" "test_service_account_user" {
  project = var.project_id
  count = length(var.rolesList)
  role =  var.rolesList[count.index]
  members = [
    "serviceAccount:${google_service_account.test_service_account.email}"
  ]
}

resource "google_service_account_key" "test_service_account_key" {
  service_account_id  = google_service_account.test_service_account.name
  public_key_type     = "TYPE_X509_PEM_FILE"
  private_key_type    = "TYPE_GOOGLE_CREDENTIALS_FILE"
  key_algorithm       = "KEY_ALG_RSA_2048"
}

resource "google_service_account_key" "test_service_account_keys" {
  count               = var.num_service_account_keys
  service_account_id  = google_service_account.test_service_account.name
  public_key_type     = "TYPE_X509_PEM_FILE"
  private_key_type    = "TYPE_GOOGLE_CREDENTIALS_FILE"
  key_algorithm       = "KEY_ALG_RSA_2048"
}

resource "google_compute_instance" "instances" {
  project      = var.project_id
  count        = var.num_instances
  name         = "boundary-${count.index}"
  machine_type = "n2-standard-2"
  zone         = var.zone
  labels       = var.labels
  tags         = ["test-instance-${count.index}"]

  boot_disk {
    initialize_params {
      image  = "ubuntu-os-cloud/ubuntu-2204-lts"
      labels = var.labels
    }
  }

  network_interface {
    network = "default"

    access_config {
      // Ephemeral public IP
    }
  }

  metadata = {
    ssh-keys = "ubuntu:${tls_private_key.ssh.public_key_openssh}"
  }

  service_account {
    email  = google_service_account.test_service_account.email
    scopes = ["cloud-platform"]
  }
}

# RSA key of size 4096 bits
resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}