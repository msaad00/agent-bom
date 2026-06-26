# connect-aws-sidescan — mints the SEPARATELY-SCOPED snapshot role the agentless
# EBS disk side-scan (CWPP) needs.
#
# This is DISTINCT from connect-aws. connect-aws grants the read-only scanner
# (List*/Describe*/Get* only — never a write). The side-scan is the ONE
# deliberate, opt-in, non-read-only capability in agent-bom: it must create an
# EBS snapshot, create + attach a temp volume to the in-account collector, then
# delete everything. Those mutations live HERE, in a separate role, so the
# read-only posture of everything else is never widened.
#
# Trust-model guarantees this module encodes:
#   * The mutating actions (delete snapshot/volume, attach/detach/delete volume)
#     are conditioned on the `agent-bom-sidescan` resource tag, so the role can
#     only act on resources the side-scan itself created — never pre-existing
#     snapshots/volumes.
#   * CreateSnapshot/CreateVolume require that same tag in the request, so the
#     role cannot create UNtagged (and therefore unsweepable) resources.
#   * ExternalId is always enforced on cross-account assume-role.
# No data leaves the account: the temp volume is attached to an in-account
# collector and only SBOM/CVE/secret *metadata* is emitted by the scanner.

locals {
  common_tags = merge(
    {
      "agent-bom.io/managed-by" = "terraform"
      "agent-bom.io/module"     = "connect-aws-sidescan"
      "agent-bom.io/access"     = "snapshot-lifecycle"
    },
    var.tags,
  )

  # Unique, non-guessable principal name by default (anti-squatting).
  principal_name = var.name != "" ? var.name : "${var.name_prefix}-${random_id.name_suffix.hex}"

  # ExternalId is ALWAYS enforced (never silently omitted).
  effective_external_id = var.external_id != "" ? var.external_id : random_password.external_id.result

  # Scope volume attach/detach to known collectors when provided, else any
  # instance in the account (the operator is expected to run a dedicated
  # collector; pass collector_instance_arns to tighten).
  instance_resources = length(var.collector_instance_arns) > 0 ? var.collector_instance_arns : ["*"]

  # Derive "<host>/<path>" form used in OIDC condition keys from the provider ARN.
  oidc_issuer_hostpath = var.trusted_oidc_provider_arn != "" ? replace(
    var.trusted_oidc_provider_arn,
    "/^arn:aws[^:]*:iam::[0-9]+:oidc-provider\\//",
    "",
  ) : ""
}

# ---------------------------------------------------------------------------
# Secure-by-default randomness (unique name + high-entropy ExternalId).
# ---------------------------------------------------------------------------
resource "random_id" "name_suffix" {
  byte_length = 4
}

resource "random_password" "external_id" {
  length  = 32
  special = false
}

# ---------------------------------------------------------------------------
# Trust policy: who may assume the snapshot role.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "assume_role" {
  # Static principals (collector instance role / cross-account scanner).
  dynamic "statement" {
    for_each = length(var.trusted_principal_arns) > 0 ? [1] : []

    content {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]

      principals {
        type        = "AWS"
        identifiers = var.trusted_principal_arns
      }

      # ExternalId is always required on assume-role — confused-deputy defense
      # cannot be silently turned off.
      condition {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [local.effective_external_id]
      }
    }
  }

  # Keyless federation (OIDC): EKS/IRSA collector pod or CI.
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

# ---------------------------------------------------------------------------
# Scoped snapshot-lifecycle policy. ONLY the actions the side-scan needs —
# no SecurityAudit, no broad read. Mutations are tag-conditioned.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "sidescan" {
  # Read-only enumeration of targets and our own resources. Describe* in EC2
  # is not resource-scopable, so these are account-wide reads (no mutation).
  statement {
    sid    = "ReadOnlyEnumerate"
    effect = "Allow"
    actions = [
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "ec2:DescribeInstances",
      "ec2:DescribeTags",
      "ec2:DescribeAvailabilityZones",
    ]
    resources = ["*"]
  }

  # CreateSnapshot / CreateVolume — require the side-scan tag in the request so
  # the role can never create an untagged (unsweepable) resource. CreateTags is
  # gated to the create flow via the ec2:CreateAction request condition.
  statement {
    sid    = "CreateTaggedSnapshotAndVolume"
    effect = "Allow"
    actions = [
      "ec2:CreateSnapshot",
      "ec2:CreateVolume",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${var.sidescan_tag_key}"
      values   = [var.sidescan_tag_value]
    }
  }

  statement {
    sid       = "TagOnCreateOnly"
    effect    = "Allow"
    actions   = ["ec2:CreateTags"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSnapshot", "CreateVolume"]
    }
  }

  # Delete snapshot / delete volume — ONLY resources we tagged. This is the core
  # guarantee: the role cannot delete a customer's pre-existing snapshot/volume.
  statement {
    sid    = "DeleteTaggedSnapshotAndVolume"
    effect = "Allow"
    actions = [
      "ec2:DeleteSnapshot",
      "ec2:DeleteVolume",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${var.sidescan_tag_key}"
      values   = [var.sidescan_tag_value]
    }
  }

  # Attach/detach the tagged temp volume to/from the in-account collector. The
  # volume side is tag-scoped; the instance side is scoped to the collector
  # ARNs when provided.
  statement {
    sid    = "AttachDetachTaggedVolume"
    effect = "Allow"
    actions = [
      "ec2:AttachVolume",
      "ec2:DetachVolume",
    ]
    resources = concat(
      ["arn:aws:ec2:*:*:volume/*"],
      local.instance_resources == ["*"] ? ["arn:aws:ec2:*:*:instance/*"] : local.instance_resources,
    )

    # The volume acted on must carry our tag.
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${var.sidescan_tag_key}"
      values   = [var.sidescan_tag_value]
    }
  }
}

# ---------------------------------------------------------------------------
# Role (always role mode — keyless assume; the collector or scanner assumes it).
# ---------------------------------------------------------------------------
resource "aws_iam_role" "this" {
  name                 = local.principal_name
  path                 = var.path
  description          = "Scoped snapshot-lifecycle role for agent-bom agentless EBS side-scan. NOT the read-only scanner role. Mutations are tag-conditioned to agent-bom-created resources."
  assume_role_policy   = data.aws_iam_policy_document.assume_role.json
  permissions_boundary = var.permissions_boundary_arn != "" ? var.permissions_boundary_arn : null
  tags                 = local.common_tags
}

resource "aws_iam_role_policy" "sidescan" {
  name   = "sidescan-snapshot-lifecycle"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.sidescan.json
}
