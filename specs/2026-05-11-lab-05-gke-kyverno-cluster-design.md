# Lab 05 Design: GKE + Kyverno Compliance Validator

**Date:** 2026-05-11
**Status:** Design approved, implementation pending
**Phase:** 1 of N (Terraform cluster provisioning only)

## Goal

Build an ephemeral Kubernetes policy compliance validator on GCP using GKE and Kyverno. Map enforcement and evidence to FedRAMP Moderate controls AC-3, CM-6, SC-28, AU-3. The cluster stands up for a single lab session, generates auditor-ready evidence via `terraform show -json` and Kyverno policy reports, then tears down.

This document covers Phase 1: minimal FedRAMP-realistic GKE cluster, ready to host Kyverno. Subsequent phases (Kyverno install, policies, validator script, evidence collection) follow in their own specs.

## Repo location

```
tools/terraform/primitives/gke-kyverno-cluster/
├── README.md
├── main.tf
├── variables.tf
├── outputs.tf
├── versions.tf
├── Makefile
└── artifacts/             # gitignored
```

## Resource inventory

All resources live in `us-central1`, zone `us-central1-a`. Zonal cluster (first zonal cluster per billing account has $0 management fee).

1. **Cloud KMS**
   - `google_kms_key_ring.sc28_gke_keyring`
   - `google_kms_crypto_key.sc28_gke_secrets` with 90-day rotation
   - `google_kms_crypto_key_iam_member` granting the GKE service agent `roles/cloudkms.cryptoKeyEncrypterDecrypter`

2. **VPC and networking**
   - `google_compute_network.lab05` with `auto_create_subnetworks = false`
   - `google_compute_subnetwork.lab05` with primary CIDR plus two secondary ranges named `pods` and `services` for VPC-native cluster
   - `google_compute_router.lab05`
   - `google_compute_router_nat.lab05` for private-node egress

3. **GKE cluster** `ac3-gke-cluster`
   - Zonal, release channel `STABLE`
   - `remove_default_node_pool = true`, `initial_node_count = 1`
   - `private_cluster_config { enable_private_nodes = true, enable_private_endpoint = false, master_ipv4_cidr_block = "172.16.0.0/28" }`
   - `master_authorized_networks_config` locked to `var.authorized_cidr`
   - `database_encryption { state = "ENCRYPTED", key_name = <KMS key id> }`
   - `workload_identity_config { workload_pool = "<project>.svc.id.goog" }`
   - `network_policy { enabled = true, provider = "CALICO" }`
   - `logging_config` and `monitoring_config` with all components enabled
   - `addons_config.network_policy_config.disabled = false`

4. **Node pool** `cm6-gke-node-pool`
   - Two `e2-small` nodes, autoscaling disabled
   - `shielded_instance_config { enable_secure_boot = true, enable_integrity_monitoring = true }`
   - `workload_metadata_config { mode = "GKE_METADATA" }`
   - `oauth_scopes` restricted to `cloud-platform`, `logging.write`, `monitoring.write`
   - `disk_size_gb = 20`, `disk_type = "pd-standard"`

5. **Audit logging** `au3-audit-config`
   - `google_project_iam_audit_config` for service `container.googleapis.com` covering `DATA_READ`, `DATA_WRITE`, `ADMIN_READ`. `ADMIN_WRITE` is always on and cannot be disabled.

## Control coverage (Phase 1)

| Control | Family | Mechanism | Evidence in terraform show -json |
|---|---|---|---|
| SC-28 | System and Communications Protection | KMS-backed application-layer secrets encryption | `database_encryption.state` and `key_name` on the cluster |
| CM-6 | Configuration Management | STABLE release channel, shielded nodes, secure boot, workload identity, network policy enabled, default node pool removed, restricted OAuth scopes | cluster and node pool config blocks |
| AC-3 | Access Control | Private nodes, master authorized networks, workload identity, network policy, least-scope node service account | `private_cluster_config` and `master_authorized_networks_config` |
| AU-3 | Audit and Accountability | Cluster logging_config + project-level audit_config for container.googleapis.com | `logging_config.enable_components` and the separate audit_config resource |

Kyverno phases will layer pod-level enforcement on top of these cluster-level guarantees.

## Labels standard

Every taggable resource carries:

```hcl
labels = {
  control_id       = "<lead-control>"
  framework        = "nist-800-53-rev5"
  compliance_layer = "fedramp-moderate"
  environment      = var.environment
  managed_by       = "terraform"
}
```

GCP labels disallow uppercase and several punctuation characters, so values use lowercase hyphenated form. Lead control prefixes on resource names: `sc28-`, `ac3-`, `cm6-`, `au3-`.

## Variables

| Name | Type | Default | Notes |
|---|---|---|---|
| `project_id` | string | none | GCP project (reuse Lab 2.4 project) |
| `region` | string | `us-central1` | |
| `zone` | string | `us-central1-a` | |
| `environment` | string | `lab` | Labels and naming suffix |
| `authorized_cidr` | string | none | User's public `/32`, supplied via `TF_VAR_authorized_cidr` |
| `cluster_name` | string | `lab05-gke` | |
| `node_count` | number | `2` | |
| `machine_type` | string | `e2-small` | |

## Outputs

- `cluster_name`
- `cluster_endpoint`
- `cluster_location`
- `kms_key_id`
- `kubeconfig_command` (the `gcloud container clusters get-credentials …` invocation)
- `artifact_paths` (object pointing at `artifacts/plan.json` and `artifacts/terraform-state.json`)

## State backend

Local state. Single-session ephemeral lab, no team collaboration, no need for remote locking. State file is removed as part of `make destroy`.

## Lifecycle: Makefile targets

| Target | Action |
|---|---|
| `init` | `terraform init` |
| `plan` | `terraform plan -out=tfplan` then `terraform show -json tfplan > artifacts/plan.json` |
| `apply` | Requires `TF_VAR_authorized_cidr`. Runs `terraform apply tfplan` then writes `artifacts/terraform-state.json` from `terraform show -json` |
| `kubeconfig` | Runs `gcloud container clusters get-credentials $(cluster_name) --zone $(zone) --project $(project_id)` |
| `destroy` | `terraform destroy -auto-approve` then `rm -rf .terraform terraform.tfstate* artifacts/` |
| `clean` | `rm -rf .terraform terraform.tfstate* artifacts/` only, no destroy |

README documents the full session flow: export `TF_VAR_authorized_cidr=$(curl -s https://api.ipify.org)/32`, `make init plan apply kubeconfig`, then `make destroy` at end of session.

## .gitignore additions

Already covered by repo-wide gitignore for `.terraform/`, `*.tfstate`, `*.tfstate.*`. Add `artifacts/` to the primitive's local scope if not already inherited.

## Cost

GCP bills per second of actual runtime. There is no minimum session length. The cluster is destroyed as soon as the lab is done, so total cost is bounded by your actual runtime rather than a fixed window.

| Component | Hourly rate |
|---|---|
| 2x e2-small | $0.054 combined |
| Cloud NAT | $0.044 + minor egress |
| KMS | <$0.01 per month, effectively zero per session |
| Zonal control plane | $0 (first zonal cluster per billing account is free) |

Approximate total: ~$0.10/hr while running. A 45-minute lab is roughly $0.075. A 2-hour lab is roughly $0.20.

## Out of scope (Phase 1)

- Kyverno install and configuration
- Kyverno policies for pod-level controls
- Validator script (Python or shell) that consumes Kyverno PolicyReports
- Evidence collection beyond `terraform show -json` and `plan.json`
- GCS backend for state
- Bastion or IAP tunnel (control plane endpoint stays public, locked by authorized networks)
- Multi-region or regional cluster
- Autoscaling

## Pre-flight checklist (from grc-automation skill)

- [ ] Control coverage comment block at top of `main.tf`
- [ ] Resource names carry lead-control prefix
- [ ] Every resource has the five required labels
- [ ] `terraform show -json` produces the audit artifact (no separate evidence script needed in Phase 1)
- [ ] Artifacts written to `artifacts/`
- [ ] README control coverage table present

## Next step

Hand off to writing-plans skill to break this into an ordered implementation plan with verifiable checkpoints.
