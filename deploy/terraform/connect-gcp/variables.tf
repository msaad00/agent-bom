variable "project_id" {
  description = "GCP project ID to grant read-only access over and to host the service account."
  type        = string
}

variable "service_account_id" {
  description = "The account_id (left part of the email) for the read-only service account agent-bom uses."
  type        = string
  default     = "agent-bom-readonly"
}

variable "service_account_display_name" {
  description = "Display name for the read-only service account."
  type        = string
  default     = "agent-bom read-only scanner"
}

# --- Optional Workload Identity Federation (keyless) -------------------------
# Many orgs disable SA key creation, so keyless federation is the default-safe
# path. When enabled, an external identity (e.g. the agent-bom hosted scanner,
# GitHub Actions OIDC, AWS, or another OIDC IdP) impersonates the SA without a key.

variable "enable_workload_identity_federation" {
  description = "Create a Workload Identity Pool + OIDC provider so an external identity can impersonate the service account keylessly (no SA key needed)."
  type        = bool
  default     = false
}

variable "wif_pool_id" {
  description = "Workload Identity Pool ID (used when enable_workload_identity_federation is true)."
  type        = string
  default     = "agent-bom-pool"
}

variable "wif_provider_id" {
  description = "Workload Identity Pool Provider ID (used when enable_workload_identity_federation is true)."
  type        = string
  default     = "agent-bom-oidc"
}

variable "wif_issuer_uri" {
  description = "OIDC issuer URI of the external IdP (e.g. https://token.actions.githubusercontent.com). Required when enable_workload_identity_federation is true."
  type        = string
  default     = ""
}

variable "wif_allowed_audiences" {
  description = "Optional list of allowed audiences for the OIDC provider. Empty uses the default audience derived from the provider resource name."
  type        = list(string)
  default     = []
}

variable "wif_attribute_mapping" {
  description = "Attribute mapping from the external token to Google STS attributes. google.subject is required."
  type        = map(string)
  default = {
    "google.subject" = "assertion.sub"
  }
}

variable "wif_attribute_condition" {
  description = "Optional CEL condition restricting which external identities may use the provider (e.g. assertion.repository == 'my-org/my-repo'). Empty allows any token from the issuer — set this in production."
  type        = string
  default     = ""
}

variable "wif_principal_set" {
  description = "The principalSet:// member allowed to impersonate the SA via the pool (e.g. principalSet://iam.googleapis.com/<pool-resource>/attribute.repository/my-org/my-repo). Required to bind impersonation when WIF is enabled."
  type        = string
  default     = ""
}
