###############################################################################
# agent-bom platform — one-apply root module
#
# A single `terraform apply` stands up the full self-hosted control plane on
# EKS:
#
#   1. Cluster        — reference an existing EKS cluster, OR provision a
#                       minimal managed one (var.create_cluster).
#   2. Baseline       — RDS (Postgres) + IRSA + S3 backups + Secrets Manager,
#                       via the maintained ./../aws/baseline module.
#   3. Control plane  — the packaged Helm chart (API + UI), wired to the
#                       baseline IRSA role and Secrets Manager secrets.
#   4. Connect (opt)  — a read-only IAM role (./../connect-aws) the scanner
#                       assumes to inventory this AWS account. Keyless.
#
# Cloud access is read-only; the only writable infrastructure is the platform's
# own control-plane database, backup bucket, and secret containers.
###############################################################################

data "aws_caller_identity" "current" {}

###############################################################################
# 1. Cluster — optional minimal provisioning
###############################################################################

module "vpc" {
  count = var.create_cluster ? 1 : 0

  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${var.name}-vpc"
  cidr = var.cluster_vpc_cidr

  azs             = local.azs
  private_subnets = [for i, az in local.azs : cidrsubnet(var.cluster_vpc_cidr, 4, i)]
  public_subnets  = [for i, az in local.azs : cidrsubnet(var.cluster_vpc_cidr, 4, i + 8)]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  # Tags required so the AWS load balancer controller / EKS can place subnets.
  private_subnet_tags = { "kubernetes.io/role/internal-elb" = "1" }
  public_subnet_tags  = { "kubernetes.io/role/elb" = "1" }
}

module "eks" {
  count = var.create_cluster ? 1 : 0

  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.8"

  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version

  cluster_endpoint_public_access = true
  enable_irsa                    = true

  vpc_id     = module.vpc[0].vpc_id
  subnet_ids = module.vpc[0].private_subnets

  eks_managed_node_groups = {
    default = {
      instance_types = var.node_instance_types
      desired_size   = var.node_desired_size
      min_size       = var.node_min_size
      max_size       = var.node_max_size
    }
  }
}

###############################################################################
# 1b. Cluster — referencing an existing one
###############################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_eks_cluster" "existing" {
  count = var.create_cluster ? 0 : 1
  name  = var.cluster_name
}

# An existing cluster's IRSA OIDC provider is keyed by the issuer host path.
data "aws_iam_openid_connect_provider" "existing" {
  count = var.create_cluster ? 0 : 1
  url   = data.aws_eks_cluster.existing[0].identity[0].oidc[0].issuer
}

###############################################################################
# Resolve a single, branch-free view of the cluster for downstream modules
###############################################################################

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  cluster_name     = var.create_cluster ? module.eks[0].cluster_name : data.aws_eks_cluster.existing[0].name
  cluster_endpoint = var.create_cluster ? module.eks[0].cluster_endpoint : data.aws_eks_cluster.existing[0].endpoint
  cluster_ca       = var.create_cluster ? module.eks[0].cluster_certificate_authority_data : data.aws_eks_cluster.existing[0].certificate_authority[0].data

  oidc_provider_arn = var.create_cluster ? module.eks[0].oidc_provider_arn : data.aws_iam_openid_connect_provider.existing[0].arn
  oidc_issuer_url   = var.create_cluster ? module.eks[0].cluster_oidc_issuer_url : data.aws_eks_cluster.existing[0].identity[0].oidc[0].issuer

  resolved_vpc_id = var.create_cluster ? module.vpc[0].vpc_id : var.vpc_id
  resolved_subnets = (
    var.create_cluster ? module.vpc[0].private_subnets : var.private_subnet_ids
  )

  effective_image_tag = var.image_tag

  # Ingress values block, emitted only when a domain is supplied.
  ingress_values = var.domain == "" ? {} : {
    controlPlane = {
      ingress = {
        enabled     = true
        className   = var.ingress_class_name
        annotations = var.ingress_annotations
        hosts       = [{ host = var.domain }]
        tls = [{
          hosts      = [var.domain]
          secretName = "${var.name}-control-plane-tls"
        }]
      }
    }
  }

  # Optional image tag override block.
  image_values = local.effective_image_tag == "" ? {} : {
    image   = { tag = local.effective_image_tag }
    uiImage = { tag = local.effective_image_tag }
  }

  # Optional S3 report-export overlay. Binds the dedicated API IRSA role onto
  # the API service account and turns on S3 export, only when a bucket is set.
  report_values = local.report_export_enabled ? {
    controlPlane = {
      api = {
        serviceAccount = {
          annotations = {
            "eks.amazonaws.com/role-arn" = aws_iam_role.report_export[0].arn
          }
        }
        env = [
          { name = "AGENT_BOM_REPORT_S3_BUCKET", value = var.report_export_bucket },
          { name = "AGENT_BOM_REPORT_S3_REGION", value = coalesce(var.report_export_bucket_region, var.region) },
        ]
      }
    }
  } : {}
}

###############################################################################
# 2. Baseline — RDS + IRSA + S3 + Secrets
###############################################################################

module "baseline" {
  source = "../aws/baseline"

  name         = var.name
  namespace    = var.namespace
  release_name = var.name

  cluster_oidc_provider_arn = local.oidc_provider_arn
  cluster_oidc_issuer_url   = local.oidc_issuer_url

  vpc_id             = local.resolved_vpc_id
  private_subnet_ids = local.resolved_subnets

  db_instance_class      = var.db_instance_class
  db_allocated_storage   = var.db_allocated_storage
  db_multi_az            = var.db_multi_az
  db_deletion_protection = var.db_deletion_protection

  # Keyless cross-account read: the scanner IRSA role may sts:AssumeRole the
  # read-only connection roles in target accounts (org fan-out / hosted connect).
  connect_role_arns = var.connect_role_arns

  tags = var.tags
}

###############################################################################
# 3. Control plane — Helm release wired to the baseline outputs
###############################################################################

resource "kubernetes_namespace" "this" {
  metadata {
    name = var.namespace
  }
}

# Baseline wiring rendered as a values document. Enables the control plane,
# binds the scanner/backup IRSA roles, and points External Secrets at the
# Secrets Manager containers the baseline created.
locals {
  baseline_values = {
    controlPlane = {
      enabled = true
      externalSecrets = {
        enabled = true
        secretStoreRef = {
          kind = "ClusterSecretStore"
          name = "aws-secrets-manager"
        }
        secrets = [
          {
            nameSuffix = "control-plane-db"
            target     = { name = "${var.name}-control-plane-db" }
            data = [{
              secretKey = "AGENT_BOM_POSTGRES_URL"
              remoteRef = {
                key      = module.baseline.db_url_secret_name
                property = "AGENT_BOM_POSTGRES_URL"
              }
            }]
          },
          {
            nameSuffix = "control-plane-auth"
            target     = { name = "${var.name}-control-plane-auth" }
            data = [{
              secretKey = "AGENT_BOM_OIDC_ISSUER"
              remoteRef = {
                key      = module.baseline.auth_secret_name
                property = "OIDC_ISSUER"
              }
            }]
          },
        ]
      }
      api = {
        envFrom = [
          { secretRef = { name = "${var.name}-control-plane-db" } },
          { secretRef = { name = "${var.name}-control-plane-auth" } },
        ]
      }
      backup = {
        enabled = true
        serviceAccount = {
          annotations = {
            "eks.amazonaws.com/role-arn" = module.baseline.backup_role_arn
          }
        }
        destination = {
          bucket       = module.baseline.backup_bucket_name
          prefix       = "agent-bom/postgres"
          bucketRegion = var.region
        }
      }
    }
    serviceAccount = {
      annotations = {
        "eks.amazonaws.com/role-arn" = module.baseline.scanner_role_arn
      }
    }
    scanner = {
      serviceAccount = {
        annotations = {
          "eks.amazonaws.com/role-arn" = module.baseline.scanner_role_arn
        }
      }
    }
  }
}

resource "helm_release" "control_plane" {
  name      = var.name
  namespace = kubernetes_namespace.this.metadata[0].name

  chart   = var.chart_path
  version = var.chart_version != "" ? var.chart_version : null

  timeout       = var.helm_timeout_seconds
  wait          = true
  atomic        = true
  recreate_pods = false

  # Precedence (low -> high): baseline wiring, image tag, ingress, report
  # export, user extras.
  values = compact([
    yamlencode(local.baseline_values),
    length(local.image_values) > 0 ? yamlencode(local.image_values) : "",
    length(local.ingress_values) > 0 ? yamlencode(local.ingress_values) : "",
    length(local.report_values) > 0 ? yamlencode(local.report_values) : "",
    var.extra_helm_values,
  ])

  depends_on = [module.baseline]
}

###############################################################################
# 4. Optional read-only connect role (keyless, scanner IRSA-bound)
###############################################################################

module "connect_aws" {
  count = var.create_aws_connect_role ? 1 : 0

  source = "../connect-aws"

  name_prefix               = "${var.name}-readonly"
  principal_type            = "role"
  trusted_oidc_provider_arn = local.oidc_provider_arn
  trusted_oidc_subjects = [
    "system:serviceaccount:${var.namespace}:${var.name}-scanner",
  ]
  trusted_oidc_audience   = "sts.amazonaws.com"
  attach_view_only_access = true

  tags = var.tags
}

###############################################################################
# 5. Optional API IRSA role for S3 report-artifact export (#3512)
#
# The async report exporter (report_artifact_store.py) runs in the API pod and
# calls s3:PutObject on AGENT_BOM_REPORT_S3_BUCKET. The API service account
# (agent-bom-api) otherwise inherits the scanner IRSA role, which has zero s3:
# actions — so S3 export fails AccessDenied. When a report bucket is supplied we
# mint a dedicated, least-privilege role trusted only by the API SA and wire it
# below. Gated on var.report_export_bucket so default deploys are unaffected.
###############################################################################

locals {
  report_export_enabled    = var.report_export_bucket != ""
  oidc_provider_hostpath   = replace(local.oidc_issuer_url, "https://", "")
  api_service_account_name = "${var.name}-api"
  report_bucket_arn        = "arn:aws:s3:::${var.report_export_bucket}"
}

data "aws_iam_policy_document" "report_export_assume_role" {
  count = local.report_export_enabled ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_hostpath}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${local.api_service_account_name}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_hostpath}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "report_export" {
  count = local.report_export_enabled ? 1 : 0

  statement {
    sid       = "ListReportBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [local.report_bucket_arn]
  }

  statement {
    sid       = "ReadWriteReportObjects"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${local.report_bucket_arn}/*"]
  }
}

resource "aws_iam_role" "report_export" {
  count = local.report_export_enabled ? 1 : 0

  name               = "${var.name}-api-report-export"
  assume_role_policy = data.aws_iam_policy_document.report_export_assume_role[0].json
  tags               = var.tags
}

resource "aws_iam_policy" "report_export" {
  count = local.report_export_enabled ? 1 : 0

  name   = "${var.name}-api-report-export"
  policy = data.aws_iam_policy_document.report_export[0].json
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "report_export" {
  count = local.report_export_enabled ? 1 : 0

  role       = aws_iam_role.report_export[0].name
  policy_arn = aws_iam_policy.report_export[0].arn
}
