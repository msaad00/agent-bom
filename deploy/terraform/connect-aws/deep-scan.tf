# Deep-scan content reads.
#
# The AWS-managed SecurityAudit / ViewOnlyAccess policies grant List/Describe/
# Get-*metadata* only — they structurally exclude *content* reads. Without the
# actions below, agent-bom silently returns empty for: Lambda deployment-package
# SCA (lambda:GetFunction), Lambda layer SCA (lambda:GetLayerVersion), ECR image
# SBOM (ecr pull), Inspector findings, CIS account-contact checks, and
# Bedrock-agent inventory. All are read-only Get/List calls; no mutation.
#
# S3 object-content read (DSPM/PII sampling) is the one sensitive grant, so it is
# OPT-IN and scoped to named buckets (empty list = disabled).

data "aws_iam_policy_document" "deep_scan" {
  count = var.enable_deep_scan_reads ? 1 : 0

  statement {
    sid       = "LambdaCodeRead"
    effect    = "Allow"
    actions   = ["lambda:GetFunction", "lambda:GetLayerVersion"]
    resources = ["*"]
  }

  statement {
    sid    = "EcrImagePull"
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:DescribeImageScanFindings",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "InspectorSbom"
    effect    = "Allow"
    actions   = ["inspector2:ListFindings"]
    resources = ["*"]
  }

  statement {
    sid       = "CisAccountContacts"
    effect    = "Allow"
    actions   = ["account:GetContactInformation", "account:GetAlternateContact"]
    resources = ["*"]
  }

  statement {
    sid       = "BedrockAgentInventory"
    effect    = "Allow"
    actions   = ["bedrock:ListAgents", "bedrock:GetAgent", "bedrock:GetAgentActionGroup"]
    resources = ["*"]
  }

  # Opt-in, bucket-scoped object read for DSPM/PII classification.
  dynamic "statement" {
    for_each = length(var.dspm_s3_bucket_arns) > 0 ? [1] : []
    content {
      sid       = "DspmS3ObjectSample"
      effect    = "Allow"
      actions   = ["s3:GetObject", "s3:ListBucket"]
      resources = concat(var.dspm_s3_bucket_arns, [for arn in var.dspm_s3_bucket_arns : "${arn}/*"])
    }
  }
}

resource "aws_iam_policy" "deep_scan" {
  count = var.enable_deep_scan_reads ? 1 : 0

  name        = "${local.principal_name}-deep-scan"
  path        = var.path
  description = "agent-bom deep-scan content reads (Lambda code, ECR pull, Inspector, CIS contacts, Bedrock; opt-in S3 DSPM). Read-only."
  policy      = data.aws_iam_policy_document.deep_scan[0].json
  tags        = local.common_tags
}

resource "aws_iam_role_policy_attachment" "deep_scan" {
  count = var.enable_deep_scan_reads && local.use_role ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.deep_scan[0].arn
}

resource "aws_iam_user_policy_attachment" "deep_scan" {
  count = var.enable_deep_scan_reads && !local.use_role ? 1 : 0

  user       = aws_iam_user.this[0].name
  policy_arn = aws_iam_policy.deep_scan[0].arn
}
