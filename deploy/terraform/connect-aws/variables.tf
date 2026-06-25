variable "name" {
  description = "Name for the read-only role/user agent-bom assumes."
  type        = string
  default     = "agent-bom-readonly"
}

variable "principal_type" {
  description = "Whether to mint an assumable IAM role (recommended, keyless) or a standalone IAM user. Use \"role\" for hosted/BYOC cross-account or OIDC; \"user\" only when an assumable role is not an option."
  type        = string
  default     = "role"

  validation {
    condition     = contains(["role", "user"], var.principal_type)
    error_message = "principal_type must be either \"role\" or \"user\"."
  }
}

variable "trusted_principal_arns" {
  description = "ARNs allowed to assume the read-only role (e.g. the agent-bom hosted scanner account/role for SaaS, or your own account/role for BYOC). Required when principal_type is \"role\"."
  type        = list(string)
  default     = []
}

variable "trusted_oidc_provider_arn" {
  description = "Optional IAM OIDC provider ARN for keyless federation (e.g. GitHub Actions or an EKS/IRSA issuer). When set, the role can be assumed via web identity instead of a static principal."
  type        = string
  default     = ""
}

variable "trusted_oidc_subjects" {
  description = "Allowed sub claims for the OIDC trust (matched against <issuer>:sub). Required when trusted_oidc_provider_arn is set."
  type        = list(string)
  default     = []
}

variable "trusted_oidc_audience" {
  description = "Expected aud claim for the OIDC trust (matched against <issuer>:aud)."
  type        = string
  default     = "sts.amazonaws.com"
}

variable "external_id" {
  description = "Optional sts:ExternalId required on assume-role, to defend against the confused-deputy problem in cross-account trust. Leave empty to omit."
  type        = string
  default     = ""
}

variable "attach_view_only_access" {
  description = "Also attach the AWS-managed ViewOnlyAccess policy alongside SecurityAudit. SecurityAudit alone covers the scanner's needs; ViewOnlyAccess broadens read visibility for some console/inventory calls."
  type        = bool
  default     = true
}

variable "permissions_boundary_arn" {
  description = "Optional IAM permissions boundary ARN to cap the principal's effective permissions. Read-only managed policies stay well within any sane boundary."
  type        = string
  default     = ""
}

variable "path" {
  description = "IAM path for the created role/user."
  type        = string
  default     = "/"
}

variable "tags" {
  description = "Additional tags to apply to created resources."
  type        = map(string)
  default     = {}
}
