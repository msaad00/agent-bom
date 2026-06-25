output "role_arn" {
  description = "ARN of the read-only role agent-bom assumes (empty in user mode). Hand this to the agent-bom connector / hosted scanner."
  value       = local.use_role ? aws_iam_role.this[0].arn : ""
}

output "role_name" {
  description = "Name of the read-only role (empty in user mode)."
  value       = local.use_role ? aws_iam_role.this[0].name : ""
}

output "user_arn" {
  description = "ARN of the read-only IAM user (empty in role mode)."
  value       = local.use_role ? "" : aws_iam_user.this[0].arn
}

output "user_name" {
  description = "Name of the read-only IAM user (empty in role mode)."
  value       = local.use_role ? "" : aws_iam_user.this[0].name
}

output "attached_managed_policy_arns" {
  description = "AWS-managed read-only policy ARNs attached to the principal."
  value       = local.managed_policy_arns
}

output "external_id" {
  description = "ExternalId required on assume-role, if configured (empty otherwise)."
  value       = var.external_id
}
