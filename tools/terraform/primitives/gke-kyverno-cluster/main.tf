# Control Coverage: SC-28, CM-6, AC-3, AU-3
# Framework: NIST 800-53 Rev 5 | FedRAMP Moderate
# Phase 1 of Lab 05: provisions the ephemeral GKE cluster that hosts Kyverno.

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

data "google_project" "current" {
  project_id = var.project_id
}

locals {
  common_labels = {
    framework        = "nist-800-53-rev5"
    compliance_layer = "fedramp-moderate"
    environment      = var.environment
    managed_by       = "terraform"
  }

  control_labels = {
    sc28 = merge(local.common_labels, { control_id = "sc-28" })
    cm6  = merge(local.common_labels, { control_id = "cm-6" })
    ac3  = merge(local.common_labels, { control_id = "ac-3" })
    au3  = merge(local.common_labels, { control_id = "au-3" })
  }
}


# Control: SC-28 (Cryptographic Protection at Rest)
# Application-layer secrets encryption for GKE etcd via customer-managed key.

resource "google_kms_key_ring" "sc28_gke_keyring" {
  name     = "sc28-${var.cluster_name}-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "sc28_gke_secrets" {
  name            = "sc28-${var.cluster_name}-secrets"
  key_ring        = google_kms_key_ring.sc28_gke_keyring.id
  rotation_period = "7776000s" # 90 days

  labels = local.control_labels.sc28
}

resource "google_kms_crypto_key_iam_member" "gke_service_agent_kms" {
  crypto_key_id = google_kms_crypto_key.sc28_gke_secrets.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@container-engine-robot.iam.gserviceaccount.com"
}

# Control: AC-3 (Access Enforcement at the network boundary)
# Custom VPC, dedicated subnet with secondary ranges for VPC-native cluster,
# Cloud NAT so private nodes have egress without public IPs.

resource "google_compute_network" "lab05" {
  name                    = "ac3-${var.cluster_name}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "lab05" {
  name          = "ac3-${var.cluster_name}-subnet"
  ip_cidr_range = "10.10.0.0/20"
  region        = var.region
  network       = google_compute_network.lab05.id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.20.0.0/14"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.24.0.0/20"
  }

  private_ip_google_access = true
}

resource "google_compute_router" "lab05" {
  name    = "ac3-${var.cluster_name}-router"
  region  = var.region
  network = google_compute_network.lab05.id
}

resource "google_compute_router_nat" "lab05" {
  name                               = "ac3-${var.cluster_name}-nat"
  router                             = google_compute_router.lab05.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
# Control: AC-3 (private nodes, master authorized networks, workload identity)
#        + SC-28 (database_encryption with KMS)
#        + CM-6 (STABLE channel, network policy, default pool removed)
#        + AU-3 (logging_config covers control plane components)

resource "google_container_cluster" "ac3_gke_cluster" {
  name     = var.cluster_name
  location = var.zone

  network    = google_compute_network.lab05.id
  subnetwork = google_compute_subnetwork.lab05.id

  remove_default_node_pool = true
  initial_node_count       = 1

  deletion_protection = false

  networking_mode = "VPC_NATIVE"
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  release_channel {
    channel = "STABLE"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = var.authorized_cidr
      display_name = "lab-operator"
    }
  }

  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.sc28_gke_secrets.id
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  addons_config {
    network_policy_config {
      disabled = false
    }
  }

  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
      "APISERVER",
      "CONTROLLER_MANAGER",
      "SCHEDULER",
    ]
  }

  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "APISERVER",
      "CONTROLLER_MANAGER",
      "SCHEDULER",
      "STORAGE",
      "HPA",
      "POD",
      "DAEMONSET",
      "DEPLOYMENT",
      "STATEFULSET",
    ]
  }

  resource_labels = merge(
    local.common_labels,
    { control_id = "ac-3" }
  )

  depends_on = [
    google_kms_crypto_key_iam_member.gke_service_agent_kms,
  ]
}
