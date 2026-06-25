variable "project_id" {
  description = "GCP project ID to grant read-only access over and to host the service account."
  type        = string
}

variable "service_account_id" {
  description = "Explicit, fixed account_id (left part of the email) for the read-only service account. Leave empty (default) to auto-generate a unique, non-guessable account_id (\"<service_account_id_prefix>-<random hex>\"), which defends against name-squatting and targeting of a predictable SA. Set this only when an external system requires a stable, known account_id."
  type        = string
  default     = ""
}

variable "service_account_id_prefix" {
  description = "Prefix for the auto-generated unique service-account account_id when service_account_id is empty. A random suffix is appended so the final account_id is unique and unpredictable. Must keep the final account_id within GCP's 6-30 char limit."
  type        = string
  default     = "abom-readonly"
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
  description = "Allowed audiences for the OIDC provider. Required (at least one) when enable_workload_identity_federation is true — an unpinned audience widens the federation trust. Set this to the audience your external IdP issues tokens for."
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
  description = "REQUIRED when enable_workload_identity_federation is true: a scoped CEL condition restricting which external identities may use the provider (e.g. assertion.repository == 'my-org/my-repo'). An empty condition is rejected at plan time because it would let ANY token from the issuer impersonate the read-only SA (wide-open federation)."
  type        = string
  default     = ""
}

variable "wif_principal_set" {
  description = "REQUIRED when enable_workload_identity_federation is true: the principalSet:// member allowed to impersonate the SA via the pool (e.g. principalSet://iam.googleapis.com/<pool-resource>/attribute.repository/my-org/my-repo). Scopes impersonation to a specific external identity, not the whole pool. Empty is rejected at plan time."
  type        = string
  default     = ""
}
