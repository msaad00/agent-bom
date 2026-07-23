data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

locals {
  oidc_provider_hostpath = replace(var.cluster_oidc_issuer_url, "https://", "")
  common_tags = merge(
    {
      "app.kubernetes.io/name"       = "agent-bom"
      "app.kubernetes.io/managed-by" = "terraform"
      "agent-bom.io/module"          = "aws-baseline"
    },
    var.tags,
  )
  scanner_service_account_name = "${var.release_name}-scanner"
  backup_service_account_name  = "${var.release_name}-backup"
  backup_bucket_name = var.backup_bucket_name != "" ? var.backup_bucket_name : format(
    "%s-backups-%s-%s",
    var.name,
    data.aws_caller_identity.current.account_id,
    data.aws_region.current.name,
  )
}

data "aws_iam_policy_document" "scanner_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.cluster_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_hostpath}:sub"
      values = [
        "system:serviceaccount:${var.namespace}:${local.scanner_service_account_name}",
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_hostpath}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scanner" {
  name               = "${var.name}-scanner"
  assume_role_policy = data.aws_iam_policy_document.scanner_assume_role.json
  tags               = local.common_tags

  # Provisioners often lack iam:UpdateRoleDescription; do not clear an existing
  # AWS description when moving from attached managed policies to inline.
  lifecycle {
    ignore_changes = [description]
  }
}

# Inline (PutRolePolicy): customer-managed CreatePolicy is often denied under
# PowerUser + scoped provisioner policies; inline policies keep IRSA usable.
resource "aws_iam_role_policy" "scanner" {
  name   = "${var.name}-scanner"
  role   = aws_iam_role.scanner.id
  # Co-located: Terraform resolves path.module under .terraform/modules/, so
  # climbing out to scripts/provision/ breaks for generated eks-reference roots.
  # IAM requires printable ASCII only (no UTF-8 punctuation in comments).
  # Strip doc-only keys (e.g. _comment); IAM PutRolePolicy rejects them.
  policy = jsonencode({
    for k, v in jsondecode(file("${path.module}/aws_readonly_policy.json")) : k => v
    if contains(["Version", "Id", "Statement"], k)
  })
}

# ---------------------------------------------------------------------------
# Cross-account connect: let the keyless control-plane (scanner) identity
# sts:AssumeRole the read-only connection roles in OTHER accounts. Without this
# the scanner can only read the account it runs in — org fan-out
# (AGENT_BOM_AWS_ORG_INVENTORY) and hosted connect both need to assume a
# read-only role in each target account. Least-privilege: the ONLY action
# granted is sts:AssumeRole, scoped to the connection-role resource ARNs; the
# connection role's own trust policy + ExternalId are the reciprocal guard. No
# static keys — the assumed session is short-lived STS. Set connect_role_arns
# to [] to disable cross-account assume entirely.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "scanner_assume_connect" {
  count = length(var.connect_role_arns) > 0 ? 1 : 0

  statement {
    sid       = "AssumeReadOnlyConnectionRoles"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = var.connect_role_arns
  }
}

resource "aws_iam_role_policy" "scanner_assume_connect" {
  count  = length(var.connect_role_arns) > 0 ? 1 : 0
  name   = "${var.name}-scanner-assume-connect"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner_assume_connect[0].json
}

data "aws_iam_policy_document" "backup_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.cluster_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_hostpath}:sub"
      values = [
        "system:serviceaccount:${var.namespace}:${local.backup_service_account_name}",
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_hostpath}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  count              = var.create_backup_bucket ? 1 : 0
  name               = "${var.name}-backup"
  assume_role_policy = data.aws_iam_policy_document.backup_assume_role.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "backup" {
  count = var.create_backup_bucket ? 1 : 0

  statement {
    sid    = "BackupBucketList"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [aws_s3_bucket.backups[0].arn]
  }

  statement {
    sid    = "BackupObjectWrite"
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.backups[0].arn}/*"]
  }

  dynamic "statement" {
    for_each = var.backup_kms_key_arn != "" ? [1] : []
    content {
      sid    = "BackupKms"
      effect = "Allow"
      actions = [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey",
      ]
      resources = [var.backup_kms_key_arn]
    }
  }
}

resource "aws_iam_role_policy" "backup" {
  count  = var.create_backup_bucket ? 1 : 0
  name   = "${var.name}-backup"
  role   = aws_iam_role.backup[0].id
  policy = data.aws_iam_policy_document.backup[0].json
}

resource "aws_s3_bucket" "backups" {
  count         = var.create_backup_bucket ? 1 : 0
  bucket        = local.backup_bucket_name
  force_destroy = var.backup_bucket_force_destroy
  tags          = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "backups" {
  count                   = var.create_backup_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.backups[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "backups" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = aws_s3_bucket.backups[0].bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.backup_kms_key_arn != "" ? "aws:kms" : "AES256"
      kms_master_key_id = var.backup_kms_key_arn != "" ? var.backup_kms_key_arn : null
    }
    bucket_key_enabled = var.backup_kms_key_arn != "" ? true : null
  }
}

resource "aws_db_subnet_group" "this" {
  count      = var.create_rds ? 1 : 0
  name       = "${var.name}-db"
  subnet_ids = var.private_subnet_ids
  tags       = local.common_tags
}

resource "aws_security_group" "db" {
  count       = var.create_rds ? 1 : 0
  name        = "${var.name}-db"
  description = "Postgres access for the agent-bom control plane"
  vpc_id      = var.vpc_id
  tags        = local.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "db_cidr" {
  for_each          = var.create_rds ? toset(var.db_allowed_cidr_blocks) : toset([])
  security_group_id = aws_security_group.db[0].id
  description       = "Postgres from approved CIDR"
  from_port         = 5432
  ip_protocol       = "tcp"
  to_port           = 5432
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "db_sg" {
  for_each                     = var.create_rds ? toset(var.db_allowed_security_group_ids) : toset([])
  security_group_id            = aws_security_group.db[0].id
  description                  = "Postgres from approved security group"
  from_port                    = 5432
  ip_protocol                  = "tcp"
  to_port                      = 5432
  referenced_security_group_id = each.value
}

resource "aws_vpc_security_group_egress_rule" "db" {
  count             = var.create_rds ? 1 : 0
  security_group_id = aws_security_group.db[0].id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_db_instance" "this" {
  count                       = var.create_rds ? 1 : 0
  identifier                  = var.name
  engine                      = "postgres"
  engine_version              = "16"
  instance_class              = var.db_instance_class
  allocated_storage           = var.db_allocated_storage
  storage_type                = var.db_storage_type
  storage_encrypted           = true
  db_name                     = var.db_name
  username                    = var.db_username
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.this[0].name
  vpc_security_group_ids      = [aws_security_group.db[0].id]
  skip_final_snapshot         = false
  final_snapshot_identifier   = var.db_final_snapshot_identifier != "" ? var.db_final_snapshot_identifier : "${var.name}-final"
  backup_retention_period     = var.db_backup_retention_period
  deletion_protection         = var.db_deletion_protection
  multi_az                    = var.db_multi_az
  publicly_accessible         = false
  apply_immediately           = true
  copy_tags_to_snapshot       = true
  tags                        = local.common_tags
}

resource "aws_secretsmanager_secret" "db_url" {
  count       = var.create_db_url_secret ? 1 : 0
  name        = var.db_url_secret_name
  description = "agent-bom control-plane database URL mirrored by ExternalSecrets"
  tags        = local.common_tags
}

resource "aws_secretsmanager_secret" "auth" {
  count       = var.create_auth_secret ? 1 : 0
  name        = var.auth_secret_name
  description = "agent-bom control-plane auth settings mirrored by ExternalSecrets"
  tags        = local.common_tags
}
