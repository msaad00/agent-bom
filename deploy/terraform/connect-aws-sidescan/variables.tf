variable "name" {
  description = "Explicit, fixed name for the side-scan snapshot role. Leave empty (default) to auto-generate a unique, non-guessable name (\"<name_prefix>-<random hex>\"), which defends against name-squatting and targeting of a predictable principal. Set this only when an external system requires a stable, known name."
  type        = string
  default     = ""
}

variable "name_prefix" {
  description = "Prefix for the auto-generated unique principal name when \"name\" is empty. A random suffix is appended so the final name is unique and unpredictable."
  type        = string
  default     = "abom-sidescan"
}

variable "trusted_principal_arns" {
  description = "ARNs allowed to assume the side-scan snapshot role (e.g. the in-account collector instance role, or the agent-bom hosted scanner account/role for BYOC). At least one trust path (this or trusted_oidc_provider_arn) must be set."
  type        = list(string)
  default     = []
}

variable "trusted_oidc_provider_arn" {
  description = "Optional IAM OIDC provider ARN for keyless federation (e.g. an EKS/IRSA issuer for the collector pod, or GitHub Actions). When set, the role can be assumed via web identity instead of a static principal."
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
  description = "Bring-your-own sts:ExternalId required on assume-role, to defend against the confused-deputy problem in cross-account trust. Leave empty (default) to auto-generate a high-entropy ExternalId — the confused-deputy condition is ALWAYS applied and can never be silently omitted. Read the generated value from the (sensitive) external_id output and configure the collector with it. Set this only to pin a known value."
  type        = string
  default     = ""
}

variable "collector_instance_arns" {
  description = "ARNs of the in-account collector EC2 instance(s) the temp volume may be attached to/detached from. Scopes ec2:AttachVolume / ec2:DetachVolume to known collectors instead of every instance in the account. Empty (default) allows any instance in the account/region — set this to tighten the grant to your collector(s)."
  type        = list(string)
  default     = []
}

variable "sidescan_tag_key" {
  description = "Tag key applied to every snapshot/temp-volume the side-scan creates. The mutating permissions (delete snapshot/volume, attach/detach/delete) are conditioned on this tag via aws:ResourceTag, so the role can only act on resources agent-bom created — never pre-existing snapshots or volumes."
  type        = string
  default     = "agent-bom-sidescan"
}

variable "sidescan_tag_value" {
  description = "Tag value paired with sidescan_tag_key on side-scan-created resources."
  type        = string
  default     = "true"
}

variable "permissions_boundary_arn" {
  description = "Optional IAM permissions boundary ARN to cap the role's effective permissions. The scoped snapshot policy stays well within any sane boundary."
  type        = string
  default     = ""
}

variable "path" {
  description = "IAM path for the created role."
  type        = string
  default     = "/"
}

variable "tags" {
  description = "Additional tags to apply to created resources."
  type        = map(string)
  default     = {}
}
