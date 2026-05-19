# Compliance Policy Library — Lab 3.3

Rego policies for pre-apply Terraform plan validation. Policies run against
`terraform plan -json` output before any `terraform apply`. Three controls,
three policies, zero screenshots.

---

## Policies

| File | Control | Severity | What It Enforces |
|------|---------|----------|-----------------|
| `sc28_encryption.rego` | SC-28 | High | Every `google_storage_bucket` must have CMEK via `encryption { default_kms_key_name }` |
| `ac3_no_public.rego` | AC-3 | Critical | Buckets require `uniform_bucket_level_access=true` and `public_access_prevention=enforced`; firewall rules must not expose ports 22 or 3389 to `0.0.0.0/0` |
| `cm6_required_tags.rego` | CM-6 | Medium | All taggable resources must carry `project`, `environment`, `managed_by`, and `compliance_scope` labels |

---

## Running Tests

```bash
opa test -v policies/
```

Expected: `PASS: 8/8`

---

## Evaluating Against a Real Plan

Generate the plan first:

```bash
cd terraform
terraform init
terraform plan -out=tfplan -var=gcp_project=YOUR_PROJECT_ID
terraform show -json tfplan > plan.json
```

Then evaluate each policy:

```bash
opa eval -d policies -i terraform/plan.json data.compliance.sc28.deny --format=pretty
opa eval -d policies -i terraform/plan.json data.compliance.ac3.deny  --format=pretty
opa eval -d policies -i terraform/plan.json data.compliance.cm6.deny  --format=pretty
```

---

## Remediation

Every deny message includes the resource address and the NIST control ID.
The developer gets the exact fix without filing a GRC ticket.
