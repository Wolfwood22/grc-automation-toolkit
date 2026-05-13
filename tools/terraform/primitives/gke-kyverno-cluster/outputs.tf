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
  value = format(
    "gcloud container clusters get-credentials %s --zone %s --project %s",
    google_container_cluster.ac3_gke_cluster.name,
    google_container_cluster.ac3_gke_cluster.location,
    var.project_id
  )
}

output "artifact_paths" {
  description = "Paths to generated audit artifacts."
  value = {
    plan_json  = "artifacts/plan.json"
    state_json = "artifacts/terraform-state.json"
  }
}
