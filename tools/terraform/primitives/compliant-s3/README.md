# compliant-s3

Terraform module that provisions an encrypted, versioned, access-logged S3 bucket on AWS. Enforces NIST 800-53 controls SC-28 (encryption at rest via AES-256), AC-3 (full public access block), CM-6 (versioning + compliance tags via default_tags), and AU-3/AU-6 (server access logging to a hardened log bucket). Produces machine-readable evidence via `terraform show -json`.