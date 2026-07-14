# connect-gcp — mints the read-only grant agent-bom's GCP connector needs.
#
# The ONLY per-cloud difference: a service account with IAM bindings
# roles/viewer + roles/iam.securityReviewer — both read-only predefined roles.
# No write permission is granted. agent-bom calls only list/get APIs.
#
# The roles bind at the project by default, or org-wide / folder-wide
# (iam_binding_scope) for fleet onboarding — the GCP analogue of the AWS
# Organizations StackSet and the Azure management-group scope, so one apply
# covers every project the AGENT_BOM_GCP_ALL_PROJECTS fan-out reaches.
#
# Keyless by default: this module creates NO service-account key. Use Workload
# Identity Federation (variable-gated below) since many orgs disable SA keys.

# Unique, non-guessable SA account_id by default. A predictable SA name is
# squattable/targetable, so unless the operator pins an explicit
# service_account_id we append a random hex suffix to the prefix.
resource "random_id" "sa_suffix" {
  byte_length = 4
}

locals {
  service_account_id = var.service_account_id != "" ? var.service_account_id : "${var.service_account_id_prefix}-${random_id.sa_suffix.hex}"

  # The two read-only predefined roles the connector needs, bound as a set so
  # the same grant applies verbatim at whichever scope the operator picks.
  read_roles = toset(["roles/viewer", "roles/iam.securityReviewer"])

  bind_project = var.iam_binding_scope == "project"
  bind_org     = var.iam_binding_scope == "organization"
  bind_folder  = var.iam_binding_scope == "folder"
}

resource "google_service_account" "this" {
  project      = var.project_id
  account_id   = local.service_account_id
  display_name = var.service_account_display_name
  description  = "Read-only service account assumed by agent-bom (viewer + securityReviewer). No write permissions."
}

# roles/viewer (inventory) + roles/iam.securityReviewer (read-only IAM policy
# access for CIEM/posture), bound at the chosen scope. Default: project.
resource "google_project_iam_member" "readonly" {
  for_each = local.bind_project ? local.read_roles : toset([])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.this.email}"
}

# Org-wide grant (fleet onboarding): covers every folder/project under the org,
# the GCP analogue of the AWS Organizations StackSet. Still read-only.
resource "google_organization_iam_member" "readonly" {
  for_each = local.bind_org ? local.read_roles : toset([])

  org_id = var.organization_id
  role   = each.value
  member = "serviceAccount:${google_service_account.this.email}"

  lifecycle {
    precondition {
      condition     = trimspace(var.organization_id) != ""
      error_message = "iam_binding_scope = \"organization\" requires organization_id (the numeric GCP organization ID, e.g. \"123456789012\")."
    }
  }
}

# Folder-wide grant (fleet onboarding, narrower blast radius than org): covers
# every project under the folder. Still read-only.
resource "google_folder_iam_member" "readonly" {
  for_each = local.bind_folder ? local.read_roles : toset([])

  folder = var.folder_id
  role   = each.value
  member = "serviceAccount:${google_service_account.this.email}"

  lifecycle {
    precondition {
      condition     = trimspace(var.folder_id) != ""
      error_message = "iam_binding_scope = \"folder\" requires folder_id (e.g. \"folders/123456789012\" or \"123456789012\")."
    }
  }
}

# Preserve state for existing project-scope deployments across the rename from
# the two named resources to the for_each'd google_project_iam_member.readonly,
# so an in-place upgrade re-keys the bindings instead of destroying/recreating.
moved {
  from = google_project_iam_member.viewer
  to   = google_project_iam_member.readonly["roles/viewer"]
}

moved {
  from = google_project_iam_member.security_reviewer
  to   = google_project_iam_member.readonly["roles/iam.securityReviewer"]
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

  # Always scoped: a federation provider with no attribute_condition would let
  # ANY token from the issuer impersonate the read-only SA. This is enforced by
  # the precondition below, so the value is never null when WIF is enabled.
  attribute_condition = var.wif_attribute_condition

  oidc {
    issuer_uri = var.wif_issuer_uri
    # Pin the accepted audiences. An unpinned audience widens the federation
    # trust; the precondition below requires at least one.
    allowed_audiences = var.wif_allowed_audiences
  }

  lifecycle {
    precondition {
      condition     = trimspace(var.wif_attribute_condition) != ""
      error_message = "Workload Identity Federation requires a non-empty wif_attribute_condition (a scoped CEL like \"assertion.repository == 'my-org/my-repo'\"). An empty condition would let any token from the issuer impersonate the read-only service account (wide-open federation)."
    }

    precondition {
      condition     = length(var.wif_allowed_audiences) > 0
      error_message = "Workload Identity Federation requires at least one wif_allowed_audiences entry. An unpinned audience widens the federation trust beyond the intended workload."
    }

    precondition {
      condition     = trimspace(var.wif_issuer_uri) != ""
      error_message = "Workload Identity Federation requires wif_issuer_uri (the OIDC issuer of the external IdP)."
    }

    precondition {
      condition     = trimspace(var.wif_principal_set) != ""
      error_message = "Workload Identity Federation requires wif_principal_set so the impersonation binding is scoped to a specific external identity, not the whole pool."
    }
  }
}

# Allow the federated principalSet to impersonate the read-only SA (keyless).
# Scoped to the specific principalSet (enforced non-empty by the provider
# precondition above), never the whole pool.
resource "google_service_account_iam_member" "wif_impersonation" {
  count = var.enable_workload_identity_federation ? 1 : 0

  service_account_id = google_service_account.this.name
  role               = "roles/iam.workloadIdentityUser"
  member             = var.wif_principal_set
}
