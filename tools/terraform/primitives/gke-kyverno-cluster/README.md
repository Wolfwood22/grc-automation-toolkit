  # Lab 05 Phase 1: GKE Cluster (Compliant Primitive)

  Ephemeral, FedRAMP-realistic GKE cluster in `us-central1-a`. Two `e2-small` nodes,
   private nodes with Cloud NAT egress, public control plane locked to your `/32`,
  application-layer secrets encryption with Cloud KMS. Built for a single lab
  session and torn down with `make destroy`.

  Phase 2 of this lab installs Kyverno on this cluster and adds pod-level compliance
   policies. Phase 1 stops at the cluster.

  ## Control Coverage

  | Control | Mechanism | Evidence in `artifacts/plan.json` /
  `artifacts/terraform-state.json` |
  |---------|-----------|-----------------------------------------------------------
  -----------|
  | SC-28   | KMS-backed application-layer secrets encryption (90-day rotation) |
  `google_container_cluster.database_encryption[].state` + `key_name` |
  | CM-6    | STABLE release channel, shielded nodes, secure boot, integrity
  monitoring, network policy (Calico), default node pool removed, restricted OAuth
  scopes, GKE_METADATA | cluster + node_pool config blocks |
  | AC-3    | Private nodes, master authorized networks locked to operator `/32`,
  workload identity, network policy, least-scope node OAuth |
  `private_cluster_config`, `master_authorized_networks_config`,
  `workload_identity_config` |
  | AU-3    | Cluster `logging_config` (5 components) + project audit log config for
   `container.googleapis.com` (ADMIN_READ, DATA_READ, DATA_WRITE) | 
  `logging_config.enable_components`, separate `google_project_iam_audit_config` |

  ## Prerequisites

  - Authenticated against the Lab GCP project: `gcloud auth application-default 
  login`
  - `terraform >= 1.6.0`, `kubectl`, `make`, `jq`, `curl` on PATH
  - Container API enabled once per project: `gcloud services enable 
  container.googleapis.com --project=<your-project>`

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

  Roughly $0.10/hr while running. A 45-minute lab is ~$0.075; a 2-hour lab is 
  ~$0.20. `make destroy` ends billing immediately.

  ## Files
  
  | File          | Purpose |
  |---------------|---------|
  | `versions.tf` | Terraform and provider version pins |
  | `variables.tf` | Inputs (project, zone, authorized CIDR, cluster shape) |
  | `main.tf`     | Provider, KMS, VPC + NAT, GKE cluster, node pool, audit log 
  config |
  | `outputs.tf`  | Cluster identifiers, kubeconfig command, artifact paths |
  | `Makefile`    | `init` / `plan` / `apply` / `kubeconfig` / `destroy` / `clean` |
  | `artifacts/`  | Generated evidence (gitignored): `plan.json`, 
  `terraform-state.json` |

  ## Out of Scope (this phase)

  Kyverno install, Kyverno policies, validator script, GCS state backend, bastion or
   IAP tunnel, regional cluster, autoscaling. Each lands in a follow-up phase or a 
  separate lab.

  ---

