variable "github_repo" {
  description = "GitHub \"owner/repo\" allowed to assume the deploy role. The trust policy pins the OIDC sub to repo:<github_repo>:environment:<github_environment>, so ONLY this repo's protected environment can assume the role — forks and pull-request runs (which get a different sub) cannot."
  type        = string
  default     = "msaad00/agent-bom"

  validation {
    condition     = can(regex("^[^/]+/[^/]+$", var.github_repo))
    error_message = "github_repo must be in \"owner/repo\" form."
  }
}

variable "github_environment" {
  description = "GitHub Actions Environment the deploy job runs in. Must match `environment:` in .github/workflows/demo-redeploy.yml. Create this environment in the repo with a required reviewer (yourself) so every run pauses for approval before touching AWS."
  type        = string
  default     = "demo"
}

variable "create_oidc_provider" {
  description = "Create the GitHub Actions IAM OIDC provider (token.actions.githubusercontent.com). Set to false if the account already has one — the module then looks it up by URL instead of creating a duplicate (AWS allows only one provider per URL per account)."
  type        = bool
  default     = true
}

variable "role_name" {
  description = "Name of the deploy role. Its ARN goes into the repo secret DEMO_DEPLOY_ROLE_ARN."
  type        = string
  default     = "abom-demo-deploy"
}

variable "demo_instance_id" {
  description = "EC2 instance id of the hosted-demo VM (i-...). SendCommand is scoped to exactly this instance's ARN."
  type        = string

  validation {
    condition     = can(regex("^i-[0-9a-f]+$", var.demo_instance_id))
    error_message = "demo_instance_id must look like an EC2 instance id (i-...)."
  }
}

variable "aws_region" {
  description = "Region the demo VM runs in. Used to build the instance ARN that SendCommand is scoped to. Should match vars.AWS_REGION in the workflow."
  type        = string
  default     = "us-east-1"
}

variable "oidc_audience" {
  description = "Expected aud claim on the OIDC token. GitHub's configure-aws-credentials uses sts.amazonaws.com."
  type        = string
  default     = "sts.amazonaws.com"
}

variable "permissions_boundary_arn" {
  description = "Optional IAM permissions boundary ARN to cap the deploy role. The inline policy is already least-privilege (two SSM actions), so this stays well within any sane boundary."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags to apply to created resources."
  type        = map(string)
  default     = {}
}
