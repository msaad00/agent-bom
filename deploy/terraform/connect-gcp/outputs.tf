output "service_account_email" {
  description = "Email of the read-only service account. Hand this to the agent-bom connector / hosted scanner to impersonate."
  value       = google_service_account.this.email
}

output "service_account_name" {
  description = "Fully-qualified resource name of the read-only service account."
  value       = google_service_account.this.name
}

output "granted_roles" {
  description = "Predefined read-only roles bound to the service account at the configured scope."
  value = [
    "roles/viewer",
    "roles/iam.securityReviewer",
    "roles/cloudasset.viewer",
    "roles/serviceusage.serviceUsageConsumer",
  ]
}

output "iam_binding_scope" {
  description = "Where the read-only roles were bound: project, organization, or folder."
  value       = var.iam_binding_scope
}

output "workload_identity_pool_name" {
  description = "Resource name of the Workload Identity Pool (empty when WIF is disabled)."
  value       = var.enable_workload_identity_federation ? google_iam_workload_identity_pool.this[0].name : ""
}

output "workload_identity_provider_name" {
  description = "Resource name of the Workload Identity Pool Provider, for the external credential config (empty when WIF is disabled)."
  value       = var.enable_workload_identity_federation ? google_iam_workload_identity_pool_provider.this[0].name : ""
}
