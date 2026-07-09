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

# --- Optional keyless federated credential (Workload Identity Federation) -----
# When enabled, this module pins a federated identity credential on the scanner
# application to an exact issuer + subject + audience, so only one specific
# external workload can mint tokens for the SP — never a wide-open trust.

variable "create_federated_credential" {
  description = "Create a keyless federated identity credential on the scanner application, pinned to a specific issuer + subject + audience. Leave false (default) to only assign RBAC roles to an existing principal (bring-your-own SP/managed-identity certificate auth, as before)."
  type        = bool
  default     = false
}

variable "federated_credential_application_id" {
  description = "Object ID of the Entra (Azure AD) application to attach the federated credential to. Required when create_federated_credential is true."
  type        = string
  default     = ""
}

variable "federated_credential_name" {
  description = "Name of the federated identity credential."
  type        = string
  default     = "agent-bom-readonly"
}

variable "federated_credential_issuer" {
  description = "REQUIRED when create_federated_credential is true: the exact OIDC issuer URL of the external IdP (e.g. https://token.actions.githubusercontent.com). An empty issuer is rejected at plan time — a federated credential must be pinned to a known issuer."
  type        = string
  default     = ""
}

variable "federated_credential_subject" {
  description = "REQUIRED when create_federated_credential is true: the exact subject the external token must carry (e.g. repo:my-org/my-repo:ref:refs/heads/main). An empty/wildcard subject is rejected at plan time — pinning the subject is what prevents any token from the issuer from impersonating the scanner."
  type        = string
  default     = ""
}

variable "federated_credential_audience" {
  description = "Audience the federated credential accepts. Defaults to the Entra token-exchange audience and must not be empty."
  type        = string
  default     = "api://AzureADTokenExchange"
}

variable "assign_key_vault_reader" {
  type        = bool
  default     = false
  description = "Opt-in data-plane read: assign the built-in 'Key Vault Reader' role so CIS 8.1/8.2 (key/secret expiry) can read vault data-plane metadata. Reader alone cannot, and the check would otherwise be unevaluable. RBAC-model vaults only. Off by default so vault-metadata read is opt-in, matching the AWS S3/deep-scan pattern; set true to enable CIS 8.1/8.2."
}

variable "assign_acr_pull" {
  type        = bool
  default     = false
  description = "Opt-in data-plane read: assign the built-in 'AcrPull' role so agent-bom can pull ACR images for SBOM/CVE extraction. Reader cannot pull image content. Off by default so image-content read is opt-in, matching the AWS S3/deep-scan pattern; set true to enable ACR SBOM extraction."
}
