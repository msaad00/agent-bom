locals {
  db_secret_name = var.create_rds ? split(":", aws_db_instance.this[0].master_user_secret[0].secret_arn)[6] : null
}

output "scanner_role_arn" {
  description = "IRSA role ARN for the scanner service account."
  value       = aws_iam_role.scanner.arn
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
  description = "Copy/paste baseline wiring for the packaged Helm chart."
  value = <<-EOT
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: ${aws_iam_role.scanner.arn}

scanner:
  serviceAccount:
    annotations:
      eks.amazonaws.com/role-arn: ${aws_iam_role.scanner.arn}

controlPlane:
  externalSecrets:
    enabled: true
    secretStoreRef:
      kind: ClusterSecretStore
      name: aws-secrets-manager
    secrets:
      - nameSuffix: control-plane-db
        target:
          name: agent-bom-control-plane-db
        data:
          - secretKey: AGENT_BOM_POSTGRES_URL
            remoteRef:
              key: ${coalesce(var.create_db_url_secret ? aws_secretsmanager_secret.db_url[0].name : null, "REPLACE_ME_DB_URL_SECRET_NAME")}
              property: AGENT_BOM_POSTGRES_URL
      - nameSuffix: control-plane-auth
        target:
          name: agent-bom-control-plane-auth
        data:
          - secretKey: AGENT_BOM_OIDC_ISSUER
            remoteRef:
              key: ${coalesce(var.create_auth_secret ? aws_secretsmanager_secret.auth[0].name : null, "REPLACE_ME_AUTH_SECRET_NAME")}
              property: OIDC_ISSUER

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
