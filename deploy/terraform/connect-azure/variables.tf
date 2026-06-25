variable "subscription_id" {
  description = "Subscription ID to grant read-only access over (the scope of the role assignments)."
  type        = string
}

variable "principal_id" {
  description = "Object (principal) ID of the service principal or managed identity agent-bom authenticates as. This is the AAD object ID, not the application/client ID."
  type        = string
}

variable "principal_type" {
  description = "Type of the principal being granted access. One of ServicePrincipal, User, Group, or ForeignGroup."
  type        = string
  default     = "ServicePrincipal"

  validation {
    condition     = contains(["ServicePrincipal", "User", "Group", "ForeignGroup"], var.principal_type)
    error_message = "principal_type must be one of ServicePrincipal, User, Group, ForeignGroup."
  }
}

variable "assign_security_reader" {
  description = "Also assign the built-in Security Reader role (for Microsoft Defender posture). Reader alone covers inventory; Security Reader adds Defender for Cloud findings."
  type        = bool
  default     = true
}

variable "scope_override" {
  description = "Optional explicit scope for the assignments (e.g. a management group ID like /providers/Microsoft.Management/managementGroups/<id> to cover every subscription at once). When empty, the subscription scope is used."
  type        = string
  default     = ""
}
