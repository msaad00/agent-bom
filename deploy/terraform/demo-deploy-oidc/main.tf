# demo-deploy-oidc — mints the keyless OIDC role the demo-redeploy GitHub
# Actions workflow assumes to redeploy the public hosted demo VM.
#
# The repo is PUBLIC, so the two things a fork/PR contributor must never be able
# to do are (1) trigger the deploy and (2) assume this AWS role. (1) is handled
# in the workflow (release + workflow_dispatch only, gated behind a protected
# `demo` environment with a required reviewer). (2) is handled HERE: the trust
# policy pins the OIDC sub to EXACTLY
#   repo:<github_repo>:environment:<github_environment>
# (StringEquals, no wildcard), which only the owner-approved environment run can
# present. Fork/PR runs get a different sub and are rejected by STS.
#
# The role can do nothing but send one specific SSM shell document to one
# specific instance and read command status — no ec2:*, no broad ssm:*.

locals {
  common_tags = merge(
    {
      "agent-bom.io/managed-by" = "terraform"
      "agent-bom.io/module"     = "demo-deploy-oidc"
      "agent-bom.io/access"     = "deploy"
    },
    var.tags,
  )

  github_oidc_url = "token.actions.githubusercontent.com"

  # The exact sub the trust policy allows. Scoped to the protected environment,
  # NOT "repo:<repo>:*" — a wildcard would let any branch/PR/tag ref assume it.
  github_sub = "repo:${var.github_repo}:environment:${var.github_environment}"

  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn

  # ARNs SendCommand is scoped to: the AWS-managed shell document plus the one
  # demo instance. Both are required for a single ssm:SendCommand call. The
  # instance resource for ssm:SendCommand is the EC2 instance ARN (service
  # `ec2`, not `ssm`) — IAM evaluates SendCommand against arn:aws:ec2:...:instance/...,
  # so an ssm-service instance ARN silently fails closed with AccessDenied.
  run_shell_document_arn = "arn:${data.aws_partition.current.partition}:ssm:*::document/AWS-RunShellScript"
  demo_instance_arn      = "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/${var.demo_instance_id}"
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# GitHub Actions OIDC provider. Created here by default; looked up instead when
# the account already has one (only one provider per URL is allowed per account).
# ---------------------------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.github_oidc_url}"
  client_id_list = [var.oidc_audience]
  # Thumbprints are no longer validated by AWS STS for this IAM OIDC IdP, but the
  # field is still required by the API. GitHub's current Actions root CA thumbprint.
  thumbprint_list = ["1c58a3a8518e8759bf075b76b750d4f2df264fcd"]
  tags            = local.common_tags
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://${local.github_oidc_url}"
}

# ---------------------------------------------------------------------------
# Trust policy: keyless web-identity assume, pinned to this repo's protected
# environment. aud must equal sts.amazonaws.com AND sub must equal the exact
# environment subject — both StringEquals, no wildcards.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_url}:aud"
      values   = [var.oidc_audience]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_url}:sub"
      values   = [local.github_sub]
    }
  }
}

resource "aws_iam_role" "demo_deploy" {
  name                 = var.role_name
  description          = "Keyless OIDC role assumed by the demo-redeploy workflow (scoped to ${local.github_sub}). Can only SSM SendCommand AWS-RunShellScript to the demo instance."
  assume_role_policy   = data.aws_iam_policy_document.assume_role.json
  permissions_boundary = var.permissions_boundary_arn != "" ? var.permissions_boundary_arn : null
  tags                 = local.common_tags
}

# ---------------------------------------------------------------------------
# Least-privilege inline policy. SendCommand is resource-scoped to the specific
# shell document + the specific instance; GetCommandInvocation is read-only
# status and cannot be resource-scoped, so it stays "*".
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy" {
  statement {
    sid     = "SendRunShellToDemoInstance"
    effect  = "Allow"
    actions = ["ssm:SendCommand"]
    resources = [
      local.run_shell_document_arn,
      local.demo_instance_arn,
    ]
  }

  statement {
    sid       = "ReadCommandStatus"
    effect    = "Allow"
    actions   = ["ssm:GetCommandInvocation"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "${var.role_name}-ssm"
  role   = aws_iam_role.demo_deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}
