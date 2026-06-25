# connect-gcp — mints the read-only grant agent-bom's GCP connector needs.
#
# The ONLY per-cloud difference: a service account with project IAM bindings
# roles/viewer + roles/iam.securityReviewer — both read-only predefined roles.
# No write permission is granted. agent-bom calls only list/get APIs.
#
# Keyless by default: this module creates NO service-account key. Use Workload
# Identity Federation (variable-gated below) since many orgs disable SA keys.

resource "google_service_account" "this" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = var.service_account_display_name
  description  = "Read-only service account assumed by agent-bom (viewer + securityReviewer). No write permissions."
}

# roles/viewer — read-only visibility over project resources (inventory).
resource "google_project_iam_member" "viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.this.email}"
}

# roles/iam.securityReviewer — read-only access to IAM policies for CIEM/posture.
resource "google_project_iam_member" "security_reviewer" {
  project = var.project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${google_service_account.this.email}"
}

# ---------------------------------------------------------------------------
# Optional Workload Identity Federation (keyless). Lets an external OIDC
# identity impersonate the SA without ever minting an SA key.
# ---------------------------------------------------------------------------
resource "google_iam_workload_identity_pool" "this" {
  count = var.enable_workload_identity_federation ? 1 : 0

  project                   = var.project_id
  workload_identity_pool_id = var.wif_pool_id
  display_name              = "agent-bom"
  description               = "Keyless federation pool for the agent-bom read-only scanner."
}

resource "google_iam_workload_identity_pool_provider" "this" {
  count = var.enable_workload_identity_federation ? 1 : 0

  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.this[0].workload_identity_pool_id
  workload_identity_pool_provider_id = var.wif_provider_id
  display_name                       = "agent-bom OIDC"
  attribute_mapping                  = var.wif_attribute_mapping
  attribute_condition                = var.wif_attribute_condition != "" ? var.wif_attribute_condition : null

  oidc {
    issuer_uri        = var.wif_issuer_uri
    allowed_audiences = length(var.wif_allowed_audiences) > 0 ? var.wif_allowed_audiences : null
  }
}

# Allow the federated principalSet to impersonate the read-only SA (keyless).
resource "google_service_account_iam_member" "wif_impersonation" {
  count = var.enable_workload_identity_federation && var.wif_principal_set != "" ? 1 : 0

  service_account_id = google_service_account.this.name
  role               = "roles/iam.workloadIdentityUser"
  member             = var.wif_principal_set
}
