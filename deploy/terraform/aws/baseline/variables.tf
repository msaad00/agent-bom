variable "name" {
  description = "Base name for baseline resources."
  type        = string
  default     = "agent-bom"
}

variable "namespace" {
  description = "Kubernetes namespace where the Helm release runs."
  type        = string
  default     = "agent-bom"
}

variable "release_name" {
  description = "Helm release name. Used to match default service-account names."
  type        = string
  default     = "agent-bom"
}

variable "cluster_oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider used for IRSA trust."
  type        = string
}

variable "cluster_oidc_issuer_url" {
  description = "Issuer URL of the EKS OIDC provider, for example https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID that hosts the EKS cluster and RDS instance."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for the RDS subnet group."
  type        = list(string)
}

variable "db_allowed_cidr_blocks" {
  description = "CIDR blocks allowed to connect to the RDS instance."
  type        = list(string)
  default     = []
}

variable "db_allowed_security_group_ids" {
  description = "Security group IDs allowed to connect to the RDS instance."
  type        = list(string)
  default     = []
}

variable "create_rds" {
  description = "Whether to provision the Postgres/RDS baseline."
  type        = bool
  default     = true
}

variable "db_name" {
  description = "Initial Postgres database name."
  type        = string
  default     = "agent_bom"
}

variable "db_username" {
  description = "Postgres admin username. AWS stores the generated password in Secrets Manager."
  type        = string
  default     = "agent_bom"
}

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

variable "db_storage_type" {
  description = "AWS storage type for the RDS instance."
  type        = string
  default     = "gp3"
}

variable "db_multi_az" {
  description = "Whether to enable Multi-AZ for the control-plane Postgres database."
  type        = bool
  default     = true
}

variable "db_backup_retention_period" {
  description = "Retention window in days for automated RDS backups."
  type        = number
  default     = 7
}

variable "db_deletion_protection" {
  description = "Whether to prevent accidental RDS deletion."
  type        = bool
  default     = true
}

variable "create_backup_bucket" {
  description = "Whether to provision the S3 bucket used by the Postgres backup CronJob."
  type        = bool
  default     = true
}

variable "backup_bucket_name" {
  description = "Optional explicit bucket name for backups. Defaults to <name>-backups-<account>-<region>."
  type        = string
  default     = ""
}

variable "backup_bucket_force_destroy" {
  description = "Allow Terraform destroy to remove a non-empty backup bucket."
  type        = bool
  default     = false
}

variable "backup_kms_key_arn" {
  description = "Optional KMS key ARN for S3 backup object encryption and IAM access."
  type        = string
  default     = ""
}

variable "create_auth_secret" {
  description = "Whether to create an empty Secrets Manager secret container for control-plane auth settings."
  type        = bool
  default     = true
}

variable "create_db_url_secret" {
  description = "Whether to create an empty Secrets Manager secret container for the chart-facing AGENT_BOM_POSTGRES_URL value."
  type        = bool
  default     = true
}

variable "db_url_secret_name" {
  description = "Secrets Manager secret name that should hold AGENT_BOM_POSTGRES_URL for ExternalSecrets."
  type        = string
  default     = "agent-bom/control-plane-db"
}

variable "auth_secret_name" {
  description = "Secrets Manager secret name that ExternalSecrets should mirror into AGENT_BOM_OIDC_* / SAML / audit HMAC settings."
  type        = string
  default     = "agent-bom/control-plane-auth"
}

variable "db_final_snapshot_identifier" {
  description = "Identifier used for the final RDS snapshot on destroy when deletion protection is disabled."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to all Terraform-managed baseline resources."
  type        = map(string)
  default     = {}
}
