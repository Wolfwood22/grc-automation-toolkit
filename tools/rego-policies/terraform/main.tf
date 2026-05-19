# Control Coverage: SC-28, AC-3, CM-6
# Framework: NIST 800-53 Rev 5
  terraform {
    required_version = ">= 1.6"
    required_providers {
      google = { source = "hashicorp/google", version = "~> 5.0" }
    }
  }

  provider "google" {
    project = var.gcp_project
    region  = "us-central1"
  }

  variable "gcp_project" { type = string }

  resource "google_kms_key_ring" "ring" {
    name     = "lab33-ring"
    location = "us-central1"
  }

  resource "google_kms_crypto_key" "key" {
    name     = "lab33-key"
    key_ring = google_kms_key_ring.ring.id
  }

  # COMPLIANT: passes all three policies
  resource "google_storage_bucket" "good" {
    name                        = "${var.gcp_project}-lab33-good"
    location                    = "us-central1"
    uniform_bucket_level_access = true
    public_access_prevention    = "enforced"

    encryption { default_kms_key_name = google_kms_crypto_key.key.id }

    labels = {
      project          = "lab33"
      environment      = "dev"
      managed_by       = "terraform"
      compliance_scope = "cge-p-lab"
    }
  }

  # NON-COMPLIANT: trips SC-28 (no CMEK)
  resource "google_storage_bucket" "bad_no_cmek" {
    name                        = "${var.gcp_project}-lab33-bad-cmek"
    location                    = "us-central1"
    uniform_bucket_level_access = true
    public_access_prevention    = "enforced"

    labels = {
      project          = "lab33"
      environment      = "dev"
      managed_by       = "terraform"
      compliance_scope = "cge-p-lab"
    }
  }

  # NON-COMPLIANT: trips AC-3 (public access not locked down)
  resource "google_storage_bucket" "bad_public" {
    name                        = "${var.gcp_project}-lab33-bad-public"
    location                    = "us-central1"
    uniform_bucket_level_access = false
    public_access_prevention    = "inherited"
  
    encryption { default_kms_key_name = google_kms_crypto_key.key.id }

    labels = {
      project          = "lab33"
      environment      = "dev"
      managed_by       = "terraform"
      compliance_scope = "cge-p-lab"
    }
  }

  # NON-COMPLIANT: trips CM-6 (no labels)
  resource "google_storage_bucket" "bad_no_labels" {
    name                        = "${var.gcp_project}-lab33-bad-labels"
    location                    = "us-central1"
    uniform_bucket_level_access = true
    public_access_prevention    = "enforced"
  
    encryption { default_kms_key_name = google_kms_crypto_key.key.id }
  }

  resource "google_compute_network" "demo" {
    name                    = "lab33-demo"
    auto_create_subnetworks = false
  }

  # NON-COMPLIANT: trips AC-3 (SSH open to the world)
  resource "google_compute_firewall" "open_ssh" {
    name          = "lab33-open-ssh"
    network       = google_compute_network.demo.name
    direction     = "INGRESS"
    source_ranges = ["0.0.0.0/0"]
    allow {
      protocol = "tcp"
      ports    = ["22"]
    }
  }