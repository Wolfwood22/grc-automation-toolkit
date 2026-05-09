
terraform {
    required_version = ">= 1.6"
    required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
    }
}

provider "google" {
    project = "project-fdec857e-a12f-46d6-b30"
    region  = "us-central1"
}

# INTENTIONALLY INVALID: prod environment requires retention_days >= 365
module "data_bucket" {
    source = "../../modules/compliant-gcs-bucket"

    gcp_project        = "project-fdec857e-a12f-46d6-b30"
    project_label      = "cgep-lab"
    environment        = "prod"
    retention_days     = 30
    bucket_name_suffix = "should-never-exist"
}
