# connect-azure — mints the read-only grant agent-bom's Azure connector needs.
#
# The ONLY per-cloud difference: built-in RBAC role assignments (Reader +
# optional Security Reader) for a service principal / managed identity at a
# subscription (or management-group) scope. Both roles are read-only built-ins;
# no write/action permission is granted. agent-bom calls only list/get ARM APIs.

data "azurerm_subscription" "current" {
  subscription_id = var.subscription_id
}

locals {
  scope = var.scope_override != "" ? var.scope_override : data.azurerm_subscription.current.id
}

# Reader — read-only visibility over all resources in scope (inventory, posture).
resource "azurerm_role_assignment" "reader" {
  scope                = local.scope
  role_definition_name = "Reader"
  principal_id         = var.principal_id
  principal_type       = var.principal_type
  description          = "Read-only inventory access for agent-bom (built-in Reader). No write permissions."
}

# Security Reader — read-only Microsoft Defender for Cloud posture/findings.
resource "azurerm_role_assignment" "security_reader" {
  count = var.assign_security_reader ? 1 : 0

  scope                = local.scope
  role_definition_name = "Security Reader"
  principal_id         = var.principal_id
  principal_type       = var.principal_type
  description          = "Read-only Defender for Cloud posture for agent-bom (built-in Security Reader). No write permissions."
}

# ---------------------------------------------------------------------------
# Optional keyless federated credential. Pinned to an exact issuer + subject +
# audience so only one specific external workload can exchange a token for the
# scanner SP — a wide-open (empty subject/issuer) trust is rejected at plan time.
# ---------------------------------------------------------------------------
resource "azuread_application_federated_identity_credential" "scanner" {
  count = var.create_federated_credential ? 1 : 0

  application_id = var.federated_credential_application_id
  display_name   = var.federated_credential_name
  description    = "Keyless federated credential for the agent-bom read-only scanner. Pinned issuer + subject + audience."
  issuer         = var.federated_credential_issuer
  subject        = var.federated_credential_subject
  audiences      = [var.federated_credential_audience]

  lifecycle {
    precondition {
      condition     = trimspace(var.federated_credential_application_id) != ""
      error_message = "create_federated_credential requires federated_credential_application_id (the Entra application object ID to attach the credential to)."
    }

    precondition {
      condition     = trimspace(var.federated_credential_issuer) != ""
      error_message = "create_federated_credential requires federated_credential_issuer — a federated credential must be pinned to a known OIDC issuer, never left open."
    }

    precondition {
      condition     = trimspace(var.federated_credential_subject) != "" && !strcontains(var.federated_credential_subject, "*")
      error_message = "create_federated_credential requires an exact federated_credential_subject (no wildcards). Pinning the subject is what prevents any token from the issuer from impersonating the scanner."
    }

    precondition {
      condition     = trimspace(var.federated_credential_audience) != ""
      error_message = "federated_credential_audience must not be empty (default api://AzureADTokenExchange)."
    }
  }
}
