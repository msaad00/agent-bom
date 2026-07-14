output "cluster_name" {
  description = "Name of the EKS cluster the platform runs on."
  value       = local.cluster_name
}

output "namespace" {
  description = "Kubernetes namespace the control plane is installed into."
  value       = var.namespace
}

output "helm_release_status" {
  description = "Status of the control-plane Helm release."
  value       = helm_release.control_plane.status
}

output "ui_url" {
  description = "URL to reach the agent-bom UI. Uses the ingress domain when set; otherwise a port-forward hint."
  value = (
    var.domain != ""
    ? "https://${var.domain}"
    : "Run: kubectl -n ${var.namespace} port-forward svc/${var.name}-ui 3000:3000  →  http://localhost:3000"
  )
}

output "api_endpoint" {
  description = "Base URL for the agent-bom API. Uses the ingress domain when set; otherwise a port-forward hint."
  value = (
    var.domain != ""
    ? "https://${var.domain}/api"
    : "Run: kubectl -n ${var.namespace} port-forward svc/${var.name}-api 8422:8422  →  http://localhost:8422"
  )
}

output "db_endpoint" {
  description = "Control-plane Postgres endpoint provisioned by the baseline module."
  value       = module.baseline.db_endpoint
}

output "scanner_role_arn" {
  description = "IRSA role ARN bound to the scanner service account."
  value       = module.baseline.scanner_role_arn
}

output "backup_bucket_name" {
  description = "S3 bucket used by the packaged Postgres backup job."
  value       = module.baseline.backup_bucket_name
}

output "scanner_assume_connect_policy_arn" {
  description = "IAM policy ARN letting the scanner identity assume read-only connection roles cross-account (empty when connect_role_arns = [])."
  value       = module.baseline.scanner_assume_connect_policy_arn
}

output "connect_role_arn" {
  description = "Read-only IAM role ARN the scanner assumes to inventory this AWS account (empty unless create_aws_connect_role = true)."
  value       = var.create_aws_connect_role ? module.connect_aws[0].role_arn : ""
}

output "report_export_role_arn" {
  description = "IRSA role ARN bound to the API service account for S3 report export (empty unless report_export_bucket is set)."
  value       = local.report_export_enabled ? aws_iam_role.report_export[0].arn : ""
}

locals {
  reach_with_domain = <<-EOT
    Platform is reachable at https://${var.domain} once DNS resolves to your
    ingress controller and certificates are issued.
      UI:  https://${var.domain}
      API: https://${var.domain}/api
  EOT

  reach_port_forward = <<-EOT
    No domain was set, so no Ingress was created. Reach the platform locally:
      kubectl -n ${var.namespace} port-forward svc/${var.name}-ui 3000:3000
      kubectl -n ${var.namespace} port-forward svc/${var.name}-api 8422:8422
    Then open http://localhost:3000 (UI) and http://localhost:8422 (API).
  EOT
}

output "how_to_reach_it" {
  description = "Quickstart for reaching the freshly-applied platform."
  value       = var.domain != "" ? local.reach_with_domain : local.reach_port_forward
}
