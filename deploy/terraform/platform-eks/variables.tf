###############################################################################
# Core placement
###############################################################################

variable "region" {
  description = "AWS region for the platform (cluster, RDS, S3, Secrets)."
  type        = string
}

variable "name" {
  description = "Base name applied to platform resources and the Helm release."
  type        = string
  default     = "agent-bom"
}

variable "namespace" {
  description = "Kubernetes namespace the control plane is installed into."
  type        = string
  default     = "agent-bom"
}

variable "tags" {
  description = "Tags applied to all AWS resources this module manages."
  type        = map(string)
  default     = {}
}

###############################################################################
# Cluster: reference an existing one, or provision a minimal managed one
###############################################################################

variable "create_cluster" {
  description = <<-EOT
    When true, provision a minimal EKS cluster (and a small VPC) using the
    community terraform-aws-modules. When false, reference an existing cluster
    named var.cluster_name; you must also supply vpc_id and private_subnet_ids.
  EOT
  type        = bool
  default     = false
}

variable "cluster_name" {
  description = "Name of the EKS cluster. Created when create_cluster = true, otherwise referenced."
  type        = string
  default     = "agent-bom-platform"
}

variable "cluster_version" {
  description = "Kubernetes version for the cluster (only used when create_cluster = true)."
  type        = string
  default     = "1.30"
}

variable "node_instance_types" {
  description = "Instance types for the managed node group (only used when create_cluster = true)."
  type        = list(string)
  default     = ["m6i.large"]
}

variable "node_desired_size" {
  description = "Desired node count for the managed node group (only used when create_cluster = true)."
  type        = number
  default     = 2
}

variable "node_min_size" {
  description = "Minimum node count for the managed node group (only used when create_cluster = true)."
  type        = number
  default     = 2
}

variable "node_max_size" {
  description = "Maximum node count for the managed node group (only used when create_cluster = true)."
  type        = number
  default     = 4
}

variable "cluster_vpc_cidr" {
  description = "CIDR for the VPC created when create_cluster = true."
  type        = string
  default     = "10.42.0.0/16"
}

# Required only when create_cluster = false (referencing an existing cluster).

variable "vpc_id" {
  description = "Existing VPC ID that hosts the cluster and RDS. Required when create_cluster = false."
  type        = string
  default     = ""
}

variable "private_subnet_ids" {
  description = "Existing private subnet IDs for the RDS subnet group. Required when create_cluster = false."
  type        = list(string)
  default     = []
}

###############################################################################
# Control-plane database sizing (passed through to aws/baseline)
###############################################################################

variable "db_instance_class" {
  description = "RDS instance class for the control-plane Postgres database."
  type        = string
  default     = "db.t4g.medium"
}

variable "db_allocated_storage" {
  description = "Allocated storage in GiB for the RDS instance."
  type        = number
  default     = 100
}

variable "db_multi_az" {
  description = "Whether to enable Multi-AZ for the control-plane Postgres database."
  type        = bool
  default     = true
}

variable "db_deletion_protection" {
  description = "Whether to prevent accidental RDS deletion."
  type        = bool
  default     = true
}

variable "db_final_snapshot_identifier" {
  description = "Unique final RDS snapshot identifier used only during an approved destroy after deletion protection is disabled."
  type        = string
  default     = ""
}

variable "db_allowed_security_group_ids" {
  description = <<-EOT
    Additional source security-group IDs allowed to reach Postgres on port 5432.
    The created-cluster mode automatically includes its managed node-group
    security group. Referenced clusters must set this or
    db_allowed_cidr_blocks explicitly because their pod networking model cannot
    be inferred safely.
  EOT
  type        = list(string)
  default     = []
}

variable "db_allowed_cidr_blocks" {
  description = <<-EOT
    Explicit IPv4 CIDRs allowed to reach Postgres on port 5432. Prefer source
    security groups when possible. Referenced clusters must set this or
    db_allowed_security_group_ids; created clusters normally need neither.
  EOT
  type        = list(string)
  default     = []
}

###############################################################################
# Existing Secrets Manager inputs (values never enter Terraform state)
###############################################################################

variable "app_db_secret_name" {
  description = "Name of an existing Secrets Manager secret with username/password for the fixed agent_bom_app login."
  type        = string

  validation {
    condition     = trimspace(var.app_db_secret_name) != ""
    error_message = "app_db_secret_name must name a pre-populated Secrets Manager secret."
  }
}

variable "maintenance_db_secret_name" {
  description = "Name of an existing Secrets Manager secret with username/password for the fixed agent_bom_maintenance login."
  type        = string

  validation {
    condition     = trimspace(var.maintenance_db_secret_name) != ""
    error_message = "maintenance_db_secret_name must name a pre-populated Secrets Manager secret."
  }
}

variable "auth_secret_name" {
  description = "Name of an existing Secrets Manager JSON secret whose AGENT_BOM_* keys are mirrored into the control-plane auth Secret."
  type        = string

  validation {
    condition     = trimspace(var.auth_secret_name) != ""
    error_message = "auth_secret_name must name a pre-populated Secrets Manager secret."
  }
}

variable "runtime_credentials_generation" {
  description = "Non-secret rotation generation shared by ExternalSecret reconciliation, role-password reconciliation, and workload rollout. Change it whenever any referenced secret value changes."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,63}$", var.runtime_credentials_generation))
    error_message = "runtime_credentials_generation must be a 1-63 character non-secret marker using letters, digits, dot, underscore, or hyphen."
  }
}

variable "external_secrets_prerequisites_ready" {
  description = "Explicit acknowledgement that External Secrets Operator and the aws-secrets-manager ClusterSecretStore already exist on the target cluster. Fresh clusters require the documented cluster-first bootstrap before this may be true."
  type        = bool
  default     = false
}

###############################################################################
# Helm release: control-plane chart (API + UI)
###############################################################################

variable "chart_path" {
  description = "Path to the packaged Helm chart relative to this module."
  type        = string
  default     = "../../helm/agent-bom"
}

variable "chart_version" {
  description = "Helm chart version pin. Empty uses whatever chart_path resolves to."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Container image tag for the API and UI images. Empty keeps the chart default."
  type        = string
  default     = ""
}

variable "domain" {
  description = <<-EOT
    Public hostname for the UI/API ingress (e.g. agent-bom.internal.example.com).
    When empty, the chart is installed without an Ingress and you reach the UI
    via a port-forward or an internal Service.
  EOT
  type        = string
  default     = ""
}

variable "ingress_class_name" {
  description = "Ingress class used when domain is set."
  type        = string
  default     = "nginx"
}

variable "ingress_annotations" {
  description = "Extra annotations for the control-plane Ingress (e.g. cert-manager issuer)."
  type        = map(string)
  default     = {}
}

variable "extra_helm_values" {
  description = "Additional raw YAML values merged last into the Helm release (highest precedence)."
  type        = string
  default     = ""
}

variable "helm_timeout_seconds" {
  description = "Timeout for the Helm release apply."
  type        = number
  default     = 900
}

###############################################################################
# Optional read-only cloud connect role (AWS account this platform scans)
###############################################################################

variable "create_aws_connect_role" {
  description = <<-EOT
    When true, also mint a read-only IAM role (via the connect-aws module) that
    the platform's scanner service account can assume to inventory this AWS
    account. Keyless: trust is bound to the cluster OIDC issuer + scanner IRSA.
  EOT
  type        = bool
  default     = false
}

variable "connect_role_arns" {
  description = <<-EOT
    ARNs / ARN patterns of the read-only connection roles the control-plane
    scanner may assume cross-account (AWS Organizations fan-out, hosted connect).
    Passed to the baseline module, which attaches a least-privilege
    sts:AssumeRole policy to the scanner IRSA role — the keyless control-plane
    identity can then read OTHER accounts, not only the one it runs in. Defaults
    match the connect-aws / CloudFormation connector role names
    (agent-bom-readonly*, abom-readonly*). Set to [] to disable cross-account
    assume.
  EOT
  type        = list(string)
  default = [
    "arn:aws:iam::*:role/agent-bom-readonly*",
    "arn:aws:iam::*:role/abom-readonly*",
  ]
}

###############################################################################
# Optional S3 report-artifact export (async report download via presigned URL)
###############################################################################

variable "report_export_bucket" {
  description = <<-EOT
    Name of an existing S3 bucket for async report-artifact export (#3512). When
    non-empty, this module mints a dedicated IRSA role trusted only by the
    control-plane API service account (system:serviceaccount:<namespace>:<name>-api),
    grants it s3:PutObject/GetObject/ListBucket scoped to this bucket, wires the
    role ARN onto controlPlane.api.serviceAccount, and sets AGENT_BOM_REPORT_S3_BUCKET
    on the API. Leave empty (default) to disable S3 export — default deploys are
    unaffected and the API keeps the scanner IRSA role, which has no s3: actions.
  EOT
  type        = string
  default     = ""
}

variable "report_export_bucket_region" {
  description = "Region of report_export_bucket. Empty falls back to var.region."
  type        = string
  default     = ""
}
