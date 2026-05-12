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

