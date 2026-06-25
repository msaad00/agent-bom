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
