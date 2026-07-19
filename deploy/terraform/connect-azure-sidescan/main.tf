# Separate opt-in mutation role for Azure Managed Disk side-scan. This module
# does not modify the read-only connect-azure identity.
resource "azurerm_role_definition" "sidescan" {
  name        = var.role_name
  scope       = var.scope
  description = var.description

  permissions {
    actions = [
      "Microsoft.Compute/snapshots/read",
      "Microsoft.Compute/snapshots/write",
      "Microsoft.Compute/snapshots/delete",
      "Microsoft.Compute/disks/read",
      "Microsoft.Compute/disks/write",
      "Microsoft.Compute/disks/delete",
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Compute/virtualMachines/write",
      "Microsoft.Compute/locations/operations/read",
    ]
    not_actions  = []
    data_actions = []
  }

  assignable_scopes = [var.scope]
}

resource "azurerm_role_assignment" "sidescan" {
  scope              = var.scope
  role_definition_id = azurerm_role_definition.sidescan.role_definition_resource_id
  principal_id       = var.principal_id
}
