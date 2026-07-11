output "role_arn" {
  description = "ARN of the deploy role. Paste this into the repo secret DEMO_DEPLOY_ROLE_ARN."
  value       = aws_iam_role.demo_deploy.arn
}

output "role_name" {
  description = "Name of the deploy role."
  value       = aws_iam_role.demo_deploy.name
}

output "oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC provider (created or looked up)."
  value       = local.oidc_provider_arn
}

output "trusted_oidc_sub" {
  description = "The exact OIDC sub the trust policy allows. Only a workflow run in this repo's protected environment presents this subject; forks/PRs cannot."
  value       = local.github_sub
}
