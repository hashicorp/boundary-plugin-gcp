# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

data "google_compute_zones" "available" {}

resource "google_compute_instance" "default" {
  count        = var.num_instances
  name         = "boundary-${count.index}"
  machine_type = "n2-standard-2"
  zone         = data.google_compute_zones.available.names[0]

  labels = var.labels

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

  dynamic "service_account" {
    for_each = var.service_account_email != null ? [var.service_account_email] : []
    content {
      email  = service_account.value
      scopes = ["cloud-platform"]
    }
  }
}

resource "google_compute_instance_group" "webservers" {
  name        = "boundary-servers"
  description = "Boundary server group"

  instances = google_compute_instance.default.*.id

  zone = data.google_compute_zones.available.names[0]
}

# RSA key of size 4096 bits
resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "google_compute_firewall" "rules" {
  name    = "allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = [var.client_cidr_block]
}