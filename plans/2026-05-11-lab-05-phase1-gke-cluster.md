# Lab 05 Phase 1: GKE Cluster Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **User authoring convention:** The user pastes all `.tf`, `Makefile`, and `README.md` content themselves. The assistant supplies the exact snippet inline at each step. The assistant does not write infrastructure files directly.

**Goal:** Stand up an ephemeral, FedRAMP-realistic GKE cluster in `us-central1-a` (one zonal cluster, two e2-small nodes) that hosts Kyverno in a later phase. Map four controls (SC-28, CM-6, AC-3, AU-3) to concrete Terraform resources and prove coverage via `terraform show -json`.

**Architecture:** Single primitive folder at `tools/terraform/primitives/gke-kyverno-cluster/`. Local state, Makefile-driven lifecycle (`init` / `plan` / `apply` / `kubeconfig` / `destroy` / `clean`). Cloud KMS provides application-layer secrets encryption; a custom VPC with Cloud NAT supports private nodes; the control plane stays publicly reachable but locked to the operator's `/32` via master authorized networks. Project-level audit log config captures all log types for `container.googleapis.com`.

**Tech Stack:** Terraform >= 1.6.0, `hashicorp/google` provider ~> 5.40, gcloud SDK, kubectl, GNU make, jq.

**Spec reference:** `specs/2026-05-11-lab-05-gke-kyverno-cluster-design.md`

**Verification model:** Terraform has no native TDD loop. The plan substitutes a compliance-as-test pattern: each task that adds a resource ends with `terraform validate` plus a `terraform plan -out=tfplan` followed by a `jq` assertion that the expected control attributes appear in the planned state. The final task runs an end-to-end apply, verifies the cluster is reachable, then runs `make destroy` and confirms teardown.

**Prerequisites before starting:**

- `gcloud auth application-default login` completed against the Lab 2.4 project.
- `terraform`, `kubectl`, `make`, `jq`, `curl` on PATH.
- The Lab 2.4 GCP project ID known (export as `TF_VAR_project_id` once at the start of Task 2 and leave it set for the whole session).
- Workstation public CIDR known (export as `TF_VAR_authorized_cidr=$(curl -s https://api.ipify.org)/32` once at the start of Task 2).

---

## Task 1: Bootstrap the primitive directory

**Files:**
- Create: `tools/terraform/primitives/gke-kyverno-cluster/versions.tf`
- Create: `tools/terraform/primitives/gke-kyverno-cluster/.gitignore`

- [ ] **Step 1: Create the directory**

Run from repo root:

```bash
mkdir -p tools/terraform/primitives/gke-kyverno-cluster
cd tools/terraform/primitives/gke-kyverno-cluster
```

Stay in this directory for the rest of the plan.

- [ ] **Step 2: Paste this snippet into `versions.tf`**

```hcl
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
  }
}
```

- [ ] **Step 3: Paste this snippet into `.gitignore`**

```
.terraform/
terraform.tfstate
terraform.tfstate.*
*.tfstate.backup
tfplan
artifacts/
```

The `.terraform.lock.hcl` is intentionally not ignored. Terraform reproducible-build convention is to commit it; the existing Lab 2.4 primitives leave it untracked, so the decision is yours.

- [ ] **Step 4: Initialise**

Run:

```bash
terraform init
```

Expected: `Terraform has been successfully initialized!` and a `.terraform/` directory appears.

- [ ] **Step 5: Commit**

```bash
git add tools/terraform/primitives/gke-kyverno-cluster/versions.tf \
        tools/terraform/primitives/gke-kyverno-cluster/.gitignore
git commit -m "feat(lab-05): scaffold gke-kyverno-cluster primitive"
```

---

## Task 2: Define input variables

**Files:**
- Create: `tools/terraform/primitives/gke-kyverno-cluster/variables.tf`

- [ ] **Step 1: Paste this snippet into `variables.tf`**

```hcl
variable "project_id" {
  description = "GCP project ID for Lab 05 (reuse Lab 2.4 project)."
  type        = string
}

variable "region" {
  description = "GCP region for regional resources."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone for the zonal GKE cluster and node pool."
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment label suffix (lab, dev, etc)."
  type        = string
  default     = "lab"
}

variable "authorized_cidr" {
  description = "Public CIDR allowed to reach the GKE control plane (your /32). Supplied via TF_VAR_authorized_cidr."
  type        = string

  validation {
    condition     = can(regex("^[0-9.]+/[0-9]+$", var.authorized_cidr))
    error_message = "authorized_cidr must be a CIDR like 203.0.113.5/32."
  }
}

variable "cluster_name" {
  description = "GKE cluster name."
  type        = string
  default     = "lab05-gke"
}

variable "node_count" {
  description = "Number of nodes in the primary node pool."
  type        = number
  default     = 2
}

variable "machine_type" {
  description = "GCE machine type for nodes."
  type        = string
  default     = "e2-small"
}
```

- [ ] **Step 2: Export the required env vars for the rest of the session**

```bash
export TF_VAR_project_id="<your-lab-project-id>"
export TF_VAR_authorized_cidr="$(curl -s https://api.ipify.org)/32"
```

Confirm with `echo "$TF_VAR_project_id" && echo "$TF_VAR_authorized_cidr"`. The CIDR must end in `/32`.

- [ ] **Step 3: Format and validate**

```bash
terraform fmt
terraform validate
```

Expected: `Success! The configuration is valid.`

`terraform validate` does not require variable values; it only checks syntax and references.

- [ ] **Step 4: Commit**

```bash
git add variables.tf
git commit -m "feat(lab-05): add variables for gke-kyverno-cluster primitive"
```

---

## Task 3: main.tf header (provider, project lookup, label locals)

**Files:**
- Create: `tools/terraform/primitives/gke-kyverno-cluster/main.tf`

- [ ] **Step 1: Paste this snippet into `main.tf`**

```hcl
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
```

GCP labels disallow uppercase and dots, so values are lowercase hyphenated.

- [ ] **Step 2: Format and validate**

```bash
terraform fmt
terraform validate
```

Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Commit**

```bash
git add main.tf
git commit -m "feat(lab-05): add provider block and label locals"
```

---

## Task 4: Cloud KMS (SC-28)

**Files:**
- Modify: `tools/terraform/primitives/gke-kyverno-cluster/main.tf` (append)

- [ ] **Step 1: Append this snippet to `main.tf`**

```hcl
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
```

The IAM member uses the GKE service agent email format; the agent exists in the project after the Container Engine API has been enabled. If you have not used GKE in this project before, enable the API once with:

```bash
gcloud services enable container.googleapis.com --project="$TF_VAR_project_id"
```

- [ ] **Step 2: Format and validate**

```bash
terraform fmt
terraform validate
```

Expected: success.

- [ ] **Step 3: Plan and verify SC-28 evidence appears**

```bash
mkdir -p artifacts
terraform plan -out=tfplan
terraform show -json tfplan > artifacts/plan.json

jq '[.planned_values.root_module.resources[]
  | select(.type=="google_kms_crypto_key")
  | {name: .name, rotation: .values.rotation_period, labels: .values.labels}]' \
  artifacts/plan.json
```

Expected: one entry with `name = "sc28_gke_secrets"`, `rotation = "7776000s"`, labels including `control_id: "sc-28"`.

- [ ] **Step 4: Commit**

```bash
git add main.tf
git commit -m "feat(lab-05): add KMS keyring and key for SC-28 secrets encryption"
```

---

## Task 5: VPC, subnet, Cloud Router, Cloud NAT (network plumbing for AC-3)

**Files:**
- Modify: `tools/terraform/primitives/gke-kyverno-cluster/main.tf` (append)

- [ ] **Step 1: Append this snippet to `main.tf`**

```hcl
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
```

Compute network and subnet resources do not accept GCP labels; the control coverage comment block is the audit trail.

- [ ] **Step 2: Format and validate**

```bash
terraform fmt
terraform validate
```

Expected: success.

- [ ] **Step 3: Plan and verify network resources appear**

```bash
terraform plan -out=tfplan
terraform show -json tfplan > artifacts/plan.json

jq '[.planned_values.root_module.resources[]
  | select(.type | test("google_compute_(network|subnetwork|router|router_nat)"))
  | {type: .type, name: .name}]' \
  artifacts/plan.json
```

Expected: four entries (network, subnetwork, router, router_nat) with `ac3-`-prefixed names.

- [ ] **Step 4: Commit**

```bash
git add main.tf
git commit -m "feat(lab-05): add VPC, subnet, router, and Cloud NAT"
```

---

## Task 6: GKE cluster (AC-3 private + SC-28 binding + CM-6 + AU-3 logging)

**Files:**
- Modify: `tools/terraform/primitives/gke-kyverno-cluster/main.tf` (append)

- [ ] **Step 1: Append this snippet to `main.tf`**

```hcl
# Control: AC-3 (private nodes, master authorized networks, workload identity)
#        + SC-28 (database_encryption with KMS)
#        + CM-6 (STABLE channel, network policy, default pool removed)
#        + AU-3 (logging_config covers control plane components)

resource "google_container_cluster" "ac3_gke_cluster" {
  name     = var.cluster_name
  location = var.zone # zonal cluster

  network    = google_compute_network.lab05.id
  subnetwork = google_compute_subnetwork.lab05.id

  remove_default_node_pool = true
  initial_node_count       = 1

  deletion_protection = false # ephemeral lab; allow terraform destroy

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
```

`deletion_protection = false` is required for `terraform destroy` to succeed on provider 5.x; without it the destroy fails and the cluster has to be unprotected with a follow-up apply. Setting it explicitly avoids that footgun.

- [ ] **Step 2: Format and validate**

```bash
terraform fmt
terraform validate
```

Expected: success.

- [ ] **Step 3: Plan and verify all four controls show up in the cluster block**

```bash
terraform plan -out=tfplan
terraform show -json tfplan > artifacts/plan.json

jq '.planned_values.root_module.resources[]
  | select(.type=="google_container_cluster")
  | {
      private_nodes: .values.private_cluster_config[0].enable_private_nodes,
      authorized_cidr: .values.master_authorized_networks_config[0].cidr_blocks[0].cidr_block,
      encryption_state: .values.database_encryption[0].state,
      key_name: .values.database_encryption[0].key_name,
      release_channel: .values.release_channel[0].channel,
      workload_pool: .values.workload_identity_config[0].workload_pool,
      network_policy_enabled: .values.network_policy[0].enabled,
      logging_components: .values.logging_config[0].enable_components,
      labels: .values.resource_labels
    }' \
  artifacts/plan.json
```

Expected: `private_nodes = true`, encryption_state `ENCRYPTED`, release_channel `STABLE`, network_policy_enabled `true`, logging_components including `APISERVER`, labels including `control_id: "ac-3"`. The `authorized_cidr` should match your `/32`.

- [ ] **Step 4: Commit**

```bash
git add main.tf
git commit -m "feat(lab-05): add GKE cluster with AC-3, SC-28, CM-6, AU-3 config"
```

---

## Task 7: Primary node pool (CM-6 hardening + AC-3 least-scope SA)

**Files:**
- Modify: `tools/terraform/primitives/gke-kyverno-cluster/main.tf` (append)

- [ ] **Step 1: Append this snippet to `main.tf`**

```hcl
# Control: CM-6 (shielded VM, secure boot, integrity monitoring, GKE_METADATA)
#        + AC-3 (least-privilege node OAuth scopes)

resource "google_container_node_pool" "cm6_gke_node_pool" {
  name       = "cm6-primary"
  location   = var.zone
  cluster    = google_container_cluster.ac3_gke_cluster.name
  node_count = var.node_count

  node_config {
    machine_type = var.machine_type
    disk_size_gb = 20
    disk_type    = "pd-standard"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
    ]

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    labels = {
      compliance_layer = "fedramp-moderate"
      control_family   = "cm-6"
    }
  }
}
```

`labels` on `node_config` are Kubernetes node labels (kubelet), not GCP resource labels. They are useful as selectors for Kyverno policies and network policies in Phase 2. The GCP-level audit story for this resource lives in the cluster's `resource_labels` and the control-coverage comment.

- [ ] **Step 2: Format and validate**

```bash
terraform fmt
terraform validate
```

Expected: success.

- [ ] **Step 3: Plan and verify node pool hardening attributes**

```bash
terraform plan -out=tfplan
terraform show -json tfplan > artifacts/plan.json

jq '.planned_values.root_module.resources[]
  | select(.type=="google_container_node_pool")
  | {
      node_count: .values.node_count,
      machine_type: .values.node_config[0].machine_type,
      secure_boot: .values.node_config[0].shielded_instance_config[0].enable_secure_boot,
      integrity: .values.node_config[0].shielded_instance_config[0].enable_integrity_monitoring,
      workload_mode: .values.node_config[0].workload_metadata_config[0].mode,
      oauth_scopes: .values.node_config[0].oauth_scopes
    }' \
  artifacts/plan.json
```

Expected: `node_count = 2`, `machine_type = "e2-small"`, `secure_boot = true`, `integrity = true`, `workload_mode = "GKE_METADATA"`, oauth_scopes restricted to cloud-platform + logging.write + monitoring.write.

- [ ] **Step 4: Commit**

```bash
git add main.tf
git commit -m "feat(lab-05): add hardened primary node pool for CM-6"
```

---

## Task 8: Project audit log config (AU-3)

**Files:**
- Modify: `tools/terraform/primitives/gke-kyverno-cluster/main.tf` (append)

- [ ] **Step 1: Append this snippet to `main.tf`**

```hcl
# Control: AU-3 (Content of Audit Records)
# Project-level audit logging for container.googleapis.com. ADMIN_WRITE is
# always on and cannot be disabled; the other three types must be turned on
# explicitly.

resource "google_project_iam_audit_config" "au3_container_audit" {
  project = var.project_id
  service = "container.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
```

This is a project-level IAM resource and does not accept labels. The comment block is the audit trail.

- [ ] **Step 2: Format and validate**

```bash
terraform fmt
terraform validate
```

Expected: success.

- [ ] **Step 3: Plan and verify all three audit log types appear**

```bash
terraform plan -out=tfplan
terraform show -json tfplan > artifacts/plan.json

jq '.planned_values.root_module.resources[]
  | select(.type=="google_project_iam_audit_config")
  | {
      service: .values.service,
      log_types: [.values.audit_log_config[].log_type]
    }' \
  artifacts/plan.json
```

Expected: `service = "container.googleapis.com"`, `log_types = ["ADMIN_READ", "DATA_READ", "DATA_WRITE"]` (order may differ).

- [ ] **Step 4: Commit**

```bash
git add main.tf
git commit -m "feat(lab-05): add project audit log config for AU-3"
```

---

## Task 9: outputs.tf

**Files:**
- Create: `tools/terraform/primitives/gke-kyverno-cluster/outputs.tf`

- [ ] **Step 1: Paste this snippet into `outputs.tf`**

```hcl
output "project_id" {
  description = "GCP project ID used for the cluster."
  value       = var.project_id
}

output "cluster_name" {
  description = "GKE cluster name."
  value       = google_container_cluster.ac3_gke_cluster.name
}

output "cluster_endpoint" {
  description = "GKE control plane endpoint."
  value       = google_container_cluster.ac3_gke_cluster.endpoint
  sensitive   = true
}

output "cluster_location" {
  description = "Cluster zone."
  value       = google_container_cluster.ac3_gke_cluster.location
}

output "kms_key_id" {
  description = "Cloud KMS key used for application-layer secrets encryption (SC-28)."
  value       = google_kms_crypto_key.sc28_gke_secrets.id
}

output "kubeconfig_command" {
  description = "Run this to fetch kubectl credentials for the cluster."
  value       = "gcloud container clusters get-credentials ${google_container_cluster.ac3_gke_cluster.name} --zone ${google_container_cluster.ac3_gke_cluster.location} --project ${var.project_id}"
}

output "artifact_paths" {
  description = "Paths to generated audit artifacts."
  value = {
    plan_json  = "artifacts/plan.json"
    state_json = "artifacts/terraform-state.json"
  }
}
```

- [ ] **Step 2: Format and validate**

```bash
terraform fmt
terraform validate
```

Expected: success.

- [ ] **Step 3: Commit**

```bash
git add outputs.tf
git commit -m "feat(lab-05): add cluster and artifact outputs"
```

---

## Task 10: Makefile

**Files:**
- Create: `tools/terraform/primitives/gke-kyverno-cluster/Makefile`

- [ ] **Step 1: Paste this snippet into `Makefile`**

Tabs, not spaces, on recipe lines.

```make
.PHONY: help init plan apply kubeconfig destroy clean

ARTIFACTS := artifacts

help:
	@echo "Targets:"
	@echo "  init        terraform init"
	@echo "  plan        terraform plan + write artifacts/plan.json"
	@echo "  apply       terraform apply tfplan + write artifacts/terraform-state.json"
	@echo "  kubeconfig  fetch kubectl credentials for the cluster"
	@echo "  destroy     terraform destroy + remove state and artifacts"
	@echo "  clean       remove state and artifacts (no destroy)"
	@echo ""
	@echo "Required env vars for apply:"
	@echo "  TF_VAR_project_id        Lab GCP project ID"
	@echo "  TF_VAR_authorized_cidr   Your /32 public CIDR"
	@echo ""
	@echo "Quick start:"
	@echo "  export TF_VAR_project_id=<your-project>"
	@echo "  export TF_VAR_authorized_cidr=\$$(curl -s https://api.ipify.org)/32"

init:
	terraform init

$(ARTIFACTS):
	mkdir -p $(ARTIFACTS)

plan: $(ARTIFACTS)
	@if [ -z "$$TF_VAR_project_id" ] || [ -z "$$TF_VAR_authorized_cidr" ]; then \
		echo "ERROR: TF_VAR_project_id and TF_VAR_authorized_cidr must be set."; \
		exit 1; \
	fi
	terraform plan -out=tfplan
	terraform show -json tfplan > $(ARTIFACTS)/plan.json
	@echo "Plan JSON written to $(ARTIFACTS)/plan.json"

apply: $(ARTIFACTS)
	@if [ ! -f tfplan ]; then \
		echo "ERROR: tfplan does not exist. Run 'make plan' first."; \
		exit 1; \
	fi
	terraform apply tfplan
	terraform show -json > $(ARTIFACTS)/terraform-state.json
	@echo "State JSON written to $(ARTIFACTS)/terraform-state.json"

kubeconfig:
	@CLUSTER=$$(terraform output -raw cluster_name); \
	ZONE=$$(terraform output -raw cluster_location); \
	PROJECT=$$(terraform output -raw project_id); \
	gcloud container clusters get-credentials $$CLUSTER --zone $$ZONE --project $$PROJECT

destroy:
	terraform destroy -auto-approve
	rm -rf .terraform terraform.tfstate terraform.tfstate.* tfplan $(ARTIFACTS)

clean:
	rm -rf .terraform terraform.tfstate terraform.tfstate.* tfplan $(ARTIFACTS)
```

- [ ] **Step 2: Verify the Makefile parses**

```bash
make help
```

Expected: the help block prints.

- [ ] **Step 3: Verify `make plan` works**

With `TF_VAR_project_id` and `TF_VAR_authorized_cidr` already exported from Task 2:

```bash
make plan
```

Expected: terraform produces a plan, `artifacts/plan.json` is written, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -m "feat(lab-05): add Makefile for lifecycle and artifact generation"
```

---

## Task 11: README with control coverage table

**Files:**
- Create: `tools/terraform/primitives/gke-kyverno-cluster/README.md`

- [ ] **Step 1: Paste this snippet into `README.md`**

````markdown
# Lab 05 Phase 1: GKE Cluster (Compliant Primitive)

Ephemeral, FedRAMP-realistic GKE cluster in `us-central1-a`. Two `e2-small` nodes, private nodes with Cloud NAT egress, public control plane locked to your `/32`, application-layer secrets encryption with Cloud KMS. Built for a single lab session and torn down with `make destroy`.

Phase 2 of this lab installs Kyverno on this cluster and adds pod-level compliance policies. Phase 1 stops at the cluster.

## Control Coverage

| Control | Mechanism | Evidence in `artifacts/plan.json` / `artifacts/terraform-state.json` |
|---------|-----------|----------------------------------------------------------------------|
| SC-28   | KMS-backed application-layer secrets encryption (90-day rotation) | `google_container_cluster.database_encryption[].state` + `key_name` |
| CM-6    | STABLE release channel, shielded nodes, secure boot, integrity monitoring, network policy (Calico), default node pool removed, restricted OAuth scopes, GKE_METADATA | cluster + node_pool config blocks |
| AC-3    | Private nodes, master authorized networks locked to operator `/32`, workload identity, network policy, least-scope node OAuth | `private_cluster_config`, `master_authorized_networks_config`, `workload_identity_config` |
| AU-3    | Cluster `logging_config` (5 components) + project audit log config for `container.googleapis.com` (ADMIN_READ, DATA_READ, DATA_WRITE) | `logging_config.enable_components`, separate `google_project_iam_audit_config` |

## Prerequisites

- Authenticated against the Lab GCP project: `gcloud auth application-default login`
- `terraform >= 1.6.0`, `kubectl`, `make`, `jq`, `curl` on PATH
- Container API enabled once per project: `gcloud services enable container.googleapis.com --project=<your-project>`

## Session Flow

```bash
export TF_VAR_project_id=<your-lab-project-id>
export TF_VAR_authorized_cidr=$(curl -s https://api.ipify.org)/32

make init
make plan
make apply
make kubeconfig

kubectl get nodes
# Expect two Ready nodes.

# ... lab work ...

make destroy
```

## Cost

GCP bills per second. Approximate burn rate while running:

| Component        | Rate |
|------------------|------|
| 2x e2-small      | $0.054 / hr combined |
| Cloud NAT        | $0.044 / hr + minor egress |
| Cloud KMS        | <$0.01 / month, effectively zero per session |
| Zonal control plane | $0 (first zonal cluster per billing account is free) |

Roughly $0.10/hr while running. A 45-minute lab is ~$0.075; a 2-hour lab is ~$0.20. `make destroy` ends billing immediately.

## Files

| File          | Purpose |
|---------------|---------|
| `versions.tf` | Terraform and provider version pins |
| `variables.tf` | Inputs (project, zone, authorized CIDR, cluster shape) |
| `main.tf`     | Provider, KMS, VPC + NAT, GKE cluster, node pool, audit log config |
| `outputs.tf`  | Cluster identifiers, kubeconfig command, artifact paths |
| `Makefile`    | `init` / `plan` / `apply` / `kubeconfig` / `destroy` / `clean` |
| `artifacts/`  | Generated evidence (gitignored): `plan.json`, `terraform-state.json` |

## Out of Scope (this phase)

Kyverno install, Kyverno policies, validator script, GCS state backend, bastion or IAP tunnel, regional cluster, autoscaling. Each lands in a follow-up phase or a separate lab.
````

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs(lab-05): add README with control coverage and run flow"
```

---

## Task 12: End-to-end verification (apply, kubectl, destroy)

This task spends real money (a few cents). Read every step before running it.

**Files:**
- No new files. Generates and removes `artifacts/terraform-state.json`.

- [ ] **Step 1: Confirm env vars are set**

```bash
echo "project: $TF_VAR_project_id"
echo "cidr:    $TF_VAR_authorized_cidr"
```

Both must be populated. The CIDR should end in `/32`.

- [ ] **Step 2: Apply**

```bash
make apply
```

Expected: cluster + node pool + supporting resources create. Takes roughly 6-10 minutes for the cluster, plus 1-2 minutes for the node pool. Total wall time around 10 minutes. `artifacts/terraform-state.json` is written at the end.

- [ ] **Step 3: Verify the cluster is reachable**

```bash
make kubeconfig
kubectl get nodes
```

Expected: two nodes, both `Ready`. If `kubectl get nodes` hangs, your `authorized_cidr` no longer matches your current IP (mobile network, VPN flap, etc). Re-export `TF_VAR_authorized_cidr` and run `terraform apply` again to update the authorized network.

- [ ] **Step 4: Sanity-check control evidence in the live state**

```bash
jq '.values.root_module.resources[]
  | select(.type=="google_container_cluster")
  | {
      private_nodes: .values.private_cluster_config[0].enable_private_nodes,
      encryption_state: .values.database_encryption[0].state,
      release_channel: .values.release_channel[0].channel,
      workload_pool: .values.workload_identity_config[0].workload_pool,
      logging_components: .values.logging_config[0].enable_components
    }' \
  artifacts/terraform-state.json
```

Expected: same shape as the Task 6 plan check, but now read out of the post-apply state.

- [ ] **Step 5: Destroy**

```bash
make destroy
```

Expected: every resource is destroyed, then `.terraform/`, `terraform.tfstate*`, `tfplan`, and `artifacts/` are removed. Takes roughly 5-7 minutes.

- [ ] **Step 6: Confirm teardown in the GCP console (optional)**

Open the project in the GCP console and confirm there are no leftover GKE clusters, Cloud NAT gateways, or KMS keyrings tagged `lab05`. KMS keyrings cannot be deleted, but the crypto keys should be marked for destruction with a 24-hour pending window. That is expected and free.

- [ ] **Step 7: Final commit (if anything changed)**

If Task 12 did not modify any tracked files, skip this step. Otherwise:

```bash
git status
git add <changed files>
git commit -m "chore(lab-05): post end-to-end verification"
```

---

## Done

Phase 1 is complete. The primitive provisions, exposes auditor-grade evidence via `artifacts/plan.json` + `artifacts/terraform-state.json`, and tears down cleanly.

**Next phases (separate plans):**

1. Kyverno install via Helm + a small set of FedRAMP-aligned policies (pod security, image provenance, required labels).
2. Validator script that reads Kyverno `PolicyReport` objects and writes a JSON + Markdown evidence pair matching the grc-automation skill's evidence packaging standard.
3. GRC Project Log entry summarising the lab for interview use.
