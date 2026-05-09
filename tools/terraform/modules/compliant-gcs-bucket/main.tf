terraform {
    required_version = ">=1.6"
    required_providers {
      google = { source = "hashicorp/google", version = "~> 5.0"}
    }
}

locals {
    required_labels = {
        project = var.project_label
        environment = var.environment
        managed_by = "terraform"
        compliance_scope = "cge-p-lab"
    }


effective_labels = merge(var.labels, local.required_labels)
bucket_name = "${var.project_label}-${var.environment}-${var.bucket_name_suffix}"
keyring_id = "${var.bucket_name_suffix}-ring"
key_id = "${var.bucket_name_suffix}-key"
}

data "google_storage_project_service_account" "gcs" {
project = var.gcp_project
}

# SC-12: customer-managed key - GCP does not hold the root key 
resource "google_kms_key_ring" "ring" {
    name = local.keyring_id 
    location = var.kms_location
    project = var.gcp_project 

}

# SC-13 / SC-28 AES at rest via CMEK  90-day automatic rotation 
resource "google_kms_crypto_key" "key" {
    name = local.key_id
    key_ring = google_kms_key_ring.ring.id
    rotation_period = "7776000s" # 90 days

    lifecycle {
    prevent_destroy = false
    }
}

resource "google_kms_crypto_key_iam_member" "gcs_encrypter" {
    crypto_key_id = google_kms_crypto_key.key.id
    role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
    member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}
# AC-3 + SC-28 + CM-6 + AU-11
resource "google_storage_bucket" "bucket" {
    name     = local.bucket_name
    project  = var.gcp_project
    location = var.location

    uniform_bucket_level_access = true
    public_access_prevention    = "enforced"

    versioning { enabled = true }

    encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
    }

    retention_policy {
    retention_period = var.retention_days * 86400
    is_locked        = false
    }

    labels = local.effective_labels
    depends_on = [google_kms_crypto_key_iam_member.gcs_encrypter]
}

terraform {
    required_version = "<= 1.6"
    required_providers {
    google = { source = "hashicorp/google", version = "-> 5.0"}
    }
}

provider "google" {
    project = "project-fdec857e-alf-46d6-b30"
    region = "us-central1"
}
module "data_bucket" {
    source = "../../modules/compliant-gcs-bucket"
gcp_project = "project-fdec857e-alf-46d6-b30"
project_label = "cgep-lab"
environment = "dev"
retention_days = 30
bucket_name_suffix = "dev-data-001"

}

output "attestation" { value = module.data_bucket.compliance.attestation }
output "bucket_url"  { value = module.data_bucket.bucket.url }

