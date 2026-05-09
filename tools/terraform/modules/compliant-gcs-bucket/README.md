
  # compliant-gcs-bucket

  Terraform module that provisions a CMEK-encrypted, versioned, access-controlled GCS bucket on GCP.
  Encodes six NIST 800-53 controls so consumers cannot weaken them.

  ## Controls Enforced

  | Control | Family | Mechanism |
  |---------|--------|-----------|
  | SC-12   | System & Communications Protection | Customer-managed KMS keyring; GCP does not hold the root key |
  | SC-13   | Cryptographic Protection | CMEK via Cloud KMS, AES-256 |
  | SC-28   | Protection of Information at Rest | `default_kms_key_name` — every object encrypted at write |
  | AC-3    | Access Enforcement | `uniform_bucket_level_access = true`, `public_access_prevention = "enforced"` |
  | CM-6    | Configuration Settings | Four required labels hardcoded in `locals.required_labels`; consumers can add but not remove |
  | AU-11   | Audit Record Retention | `retention_policy.retention_period` enforced; prod-environment validation requires >= 365 days |

  ## Usage

  ```hcl
  module "data_bucket" {
    source = "../../modules/compliant-gcs-bucket"

    gcp_project        = "your-project-id"
    project_label      = "myapp"
    environment        = "dev"
    retention_days     = 30
    bucket_name_suffix = "data-001"
  }

  output "attestation" { value = module.data_bucket.compliance_attestation }

  Inputs

  ┌────────────────────┬─────────────┬──────────┬─────────────┬──────────────────────────────────────────────────────┐
  │        Name        │    Type     │ Required │   Default   │                     Description                      │
  ├────────────────────┼─────────────┼──────────┼─────────────┼──────────────────────────────────────────────────────┤
  │ gcp_project        │ string      │ yes      │ —           │ GCP project ID                                       │
  ├────────────────────┼─────────────┼──────────┼─────────────┼──────────────────────────────────────────────────────┤
  │ project_label      │ string      │ yes      │ —           │ Short project name (used in bucket name + labels)    │
  ├────────────────────┼─────────────┼──────────┼─────────────┼──────────────────────────────────────────────────────┤
  │ environment        │ string      │ yes      │ —           │ dev, staging, or prod                                │
  ├────────────────────┼─────────────┼──────────┼─────────────┼──────────────────────────────────────────────────────┤
  │ retention_days     │ number      │ yes      │ —           │ Object retention; prod requires >= 365               │
  ├────────────────────┼─────────────┼──────────┼─────────────┼──────────────────────────────────────────────────────┤
  │ bucket_name_suffix │ string      │ yes      │ —           │ Globally-unique bucket name suffix                   │
  ├────────────────────┼─────────────┼──────────┼─────────────┼──────────────────────────────────────────────────────┤
  │ location           │ string      │ no       │ us-central1 │ GCS bucket location                                  │
  ├────────────────────┼─────────────┼──────────┼─────────────┼──────────────────────────────────────────────────────┤
  │ kms_location       │ string      │ no       │ us-central1 │ KMS keyring location (must be single-region)         │
  ├────────────────────┼─────────────┼──────────┼─────────────┼──────────────────────────────────────────────────────┤
  │ labels             │ map(string) │ no       │ {}          │ Additional labels; compliance labels take precedence │
  └────────────────────┴─────────────┴──────────┴─────────────┴──────────────────────────────────────────────────────┘

  Outputs

  ┌────────────────────────┬─────────────────────────────────────────────────────────────────────────┐
  │          Name          │                               Description                               │
  ├────────────────────────┼─────────────────────────────────────────────────────────────────────────┤
  │ bucket_url             │ gs:// URL                                                               │
  ├────────────────────────┼─────────────────────────────────────────────────────────────────────────┤
  │ bucket_self_link       │ GCP self-link                                                           │
  ├────────────────────────┼─────────────────────────────────────────────────────────────────────────┤
  │ kms_key_id             │ CMEK resource ID                                                        │
  ├────────────────────────┼─────────────────────────────────────────────────────────────────────────┤
  │ compliance_attestation │ Map of enforced control values (SC-12, SC-13, SC-28, AC-3, CM-6, AU-11) │
  └────────────────────────┴─────────────────────────────────────────────────────────────────────────┘

  Notes

  - KMS keyrings cannot be deleted after creation (GCP limitation). They remain after terraform destroy but incur no cost.
  - KMS crypto keys enter a 30-day soft-delete after terraform destroy.
  - If you set retention_policy.is_locked = true, the bucket cannot be deleted until the retention period expires.
  - kms_location and location must be separate variables — GCS buckets accept multi-region names (US, EU) but KMS keyrings do not.
