locals {
  db_secret_name = var.create_rds ? split(":", aws_db_instance.this[0].master_user_secret[0].secret_arn)[6] : null
}

output "scanner_role_arn" {
  description = "IRSA role ARN for the scanner service account."
  value       = aws_iam_role.scanner.arn
}

output "scanner_assume_connect_policy_arn" {
  description = "Deprecated: connect assume is an inline role policy (PutRolePolicy); no managed policy ARN. Empty string retained for callers."
  value       = ""
}

output "backup_role_arn" {
  description = "IRSA role ARN for the Postgres backup CronJob service account."
  value       = var.create_backup_bucket ? aws_iam_role.backup[0].arn : null
}

output "backup_bucket_name" {
  description = "S3 bucket used by the packaged Postgres backup job."
  value       = var.create_backup_bucket ? aws_s3_bucket.backups[0].bucket : null
}

output "db_endpoint" {
  description = "Postgres endpoint for the control plane."
  value       = var.create_rds ? aws_db_instance.this[0].address : null
}

output "db_secret_arn" {
  description = "Secrets Manager ARN containing the generated RDS master password."
  value       = var.create_rds ? aws_db_instance.this[0].master_user_secret[0].secret_arn : null
}

output "db_secret_name" {
  description = "Secrets Manager name for the generated RDS master password secret."
  value       = local.db_secret_name
}

output "db_url_secret_name" {
  description = "Secrets Manager name that should contain AGENT_BOM_POSTGRES_URL for ExternalSecrets."
  value       = var.create_db_url_secret ? aws_secretsmanager_secret.db_url[0].name : null
}

output "auth_secret_name" {
  description = "Secrets Manager name for the control-plane auth settings secret container."
  value       = var.create_auth_secret ? aws_secretsmanager_secret.auth[0].name : null
}

output "helm_values_hint" {
  description = "Workload-only Helm wiring. Pre-create the four referenced Kubernetes Secrets before installing it."
  value       = <<-EOT
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: ${aws_iam_role.scanner.arn}

scanner:
  serviceAccount:
    annotations:
      eks.amazonaws.com/role-arn: ${aws_iam_role.scanner.arn}

controlPlane:
  externalSecrets:
    enabled: false
    syncOnly: false
  postgresSecrets:
    enabled: true
    appSecretRef:
      name: ${var.release_name}-control-plane-db
    maintenanceSecretRef:
      name: ${var.release_name}-control-plane-maintenance
    adminSecretRef:
      name: ${var.release_name}-control-plane-admin
  api:
    envFrom:
      - secretRef:
          name: ${var.release_name}-control-plane-auth

  backup:
    enabled: ${var.create_backup_bucket ? "true" : "false"}
    serviceAccount:
      annotations:
        eks.amazonaws.com/role-arn: ${var.create_backup_bucket ? aws_iam_role.backup[0].arn : "REPLACE_ME_BACKUP_ROLE_ARN"}
    destination:
      bucket: ${var.create_backup_bucket ? aws_s3_bucket.backups[0].bucket : "REPLACE_ME_BACKUP_BUCKET"}
      prefix: agent-bom/postgres
      bucketRegion: ${data.aws_region.current.name}
  EOT
}

output "db_name" {
  description = "Database name created on the control-plane instance."
  value       = var.db_name
}

output "db_port" {
  description = "Postgres port for the control plane."
  value       = var.create_rds ? aws_db_instance.this[0].port : null
}
