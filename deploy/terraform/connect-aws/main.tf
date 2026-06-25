# connect-aws — mints the read-only grant agent-bom's AWS connector needs.
#
# This is the ONLY per-cloud difference in the connect flow: an IAM principal
# with the AWS-managed SecurityAudit (+ optional ViewOnlyAccess) policy attached.
# No create/update/delete permission is granted anywhere. agent-bom calls only
# List*/Describe*/Get* and sts:GetCallerIdentity.

locals {
  common_tags = merge(
    {
      "agent-bom.io/managed-by" = "terraform"
      "agent-bom.io/module"     = "connect-aws"
      "agent-bom.io/access"     = "read-only"
    },
    var.tags,
  )

  use_role = var.principal_type == "role"

  # Unique, non-guessable principal name by default. A predictable name is
  # squattable/targetable, so unless the operator pins an explicit "name" we
  # append a random hex suffix to "name_prefix".
  principal_name = var.name != "" ? var.name : "${var.name_prefix}-${random_id.name_suffix.hex}"

  # ExternalId is ALWAYS enforced (never silently omitted) to keep the
  # confused-deputy defense on by default. Use the operator-supplied value when
  # set, otherwise the auto-generated high-entropy one.
  effective_external_id = var.external_id != "" ? var.external_id : random_password.external_id.result

  # AWS-managed read-only policies. SecurityAudit is the documented baseline;
  # ViewOnlyAccess is optional and additive.
  managed_policy_arns = compact([
    "arn:aws:iam::aws:policy/SecurityAudit",
    var.attach_view_only_access ? "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess" : "",
  ])
}

# ---------------------------------------------------------------------------
# Secure-by-default randomness: a unique principal name and a high-entropy
# ExternalId. Generated at apply time (not committed anywhere), so the defaults
# are unique + unguessable without the operator hand-picking a value.
# ---------------------------------------------------------------------------
resource "random_id" "name_suffix" {
  byte_length = 4
}

resource "random_password" "external_id" {
  length  = 32
  special = false
}

# ---------------------------------------------------------------------------
# Trust policy (role mode only): who may assume the read-only role.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "assume_role" {
  count = local.use_role ? 1 : 0

  # Static principals (cross-account / BYOC): the agent-bom scanner account/role.
  dynamic "statement" {
    for_each = length(var.trusted_principal_arns) > 0 ? [1] : []

    content {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]

      principals {
        type        = "AWS"
        identifiers = var.trusted_principal_arns
      }

      # ExternalId is always required on cross-account assume-role — the
      # confused-deputy defense cannot be silently turned off.
      condition {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [local.effective_external_id]
      }
    }
  }

  # Keyless federation (OIDC): GitHub Actions / EKS-IRSA / other web identity.
  dynamic "statement" {
    for_each = var.trusted_oidc_provider_arn != "" ? [1] : []

    content {
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity"]

      principals {
        type        = "Federated"
        identifiers = [var.trusted_oidc_provider_arn]
      }

      condition {
        test     = "StringEquals"
        variable = "${local.oidc_issuer_hostpath}:aud"
        values   = [var.trusted_oidc_audience]
      }

      condition {
        test     = "StringLike"
        variable = "${local.oidc_issuer_hostpath}:sub"
        values   = var.trusted_oidc_subjects
      }
    }
  }
}

locals {
  # Derive "<host>/<path>" form used in OIDC condition keys from the provider ARN.
  oidc_issuer_hostpath = var.trusted_oidc_provider_arn != "" ? replace(
    var.trusted_oidc_provider_arn,
    "/^arn:aws[^:]*:iam::[0-9]+:oidc-provider\\//",
    "",
  ) : ""
}

# ---------------------------------------------------------------------------
# Role mode (recommended, keyless when paired with OIDC or cross-account).
# ---------------------------------------------------------------------------
resource "aws_iam_role" "this" {
  count = local.use_role ? 1 : 0

  name                 = local.principal_name
  path                 = var.path
  description          = "Read-only role assumed by agent-bom (SecurityAudit + ViewOnlyAccess). No write permissions."
  assume_role_policy   = data.aws_iam_policy_document.assume_role[0].json
  permissions_boundary = var.permissions_boundary_arn != "" ? var.permissions_boundary_arn : null
  tags                 = local.common_tags
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each = local.use_role ? toset(local.managed_policy_arns) : toset([])

  role       = aws_iam_role.this[0].name
  policy_arn = each.value
}

# ---------------------------------------------------------------------------
# User mode (only when an assumable role is not viable). No access keys are
# created here — keys are minted out-of-band and supplied as env to the
# scanner, never written into Terraform state by this module.
# ---------------------------------------------------------------------------
resource "aws_iam_user" "this" {
  count = local.use_role ? 0 : 1

  name                 = local.principal_name
  path                 = var.path
  permissions_boundary = var.permissions_boundary_arn != "" ? var.permissions_boundary_arn : null
  tags                 = local.common_tags
}

resource "aws_iam_user_policy_attachment" "this" {
  for_each = local.use_role ? toset([]) : toset(local.managed_policy_arns)

  user       = aws_iam_user.this[0].name
  policy_arn = each.value
}
