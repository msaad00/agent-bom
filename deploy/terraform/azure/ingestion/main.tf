data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

locals {
  subscription_scope = "/subscriptions/${var.subscription_id}"
  scanner_scope      = var.scanner_role_scope != "" ? var.scanner_role_scope : local.subscription_scope
  resource_group     = var.resource_group_name != "" ? var.resource_group_name : "${var.name}-ingestion"
  github_subject = (
    var.federated_subject_override != ""
    ? var.federated_subject_override
    : (
      var.github_environment != ""
      ? "repo:${var.github_owner}/${var.github_repo}:environment:${var.github_environment}"
      : "repo:${var.github_owner}/${var.github_repo}:ref:${var.github_ref}"
    )
  )
  key_vault_name = var.key_vault_name != "" ? var.key_vault_name : substr(replace("${var.name}-${random_string.suffix.result}", "-", ""), 0, 24)
  common_tags = merge(
    {
      "app.kubernetes.io/name"       = "agent-bom"
      "app.kubernetes.io/managed-by" = "terraform"
      "agent-bom.io/module"          = "azure-ingestion"
    },
    var.tags,
  )
}

resource "azurerm_resource_group" "this" {
  count    = var.create_resource_group ? 1 : 0
  name     = local.resource_group
  location = var.location
  tags     = local.common_tags
}

resource "azuread_application" "github_ingestion" {
  display_name = "${var.name}-github-ingestion"
  owners       = [data.azurerm_client_config.current.object_id]
}

resource "azuread_service_principal" "github_ingestion" {
  client_id = azuread_application.github_ingestion.client_id
  owners    = [data.azurerm_client_config.current.object_id]
}

resource "azuread_application_federated_identity_credential" "github_ingestion" {
  application_id = azuread_application.github_ingestion.id
  display_name   = "${var.name}-github-actions"
  description    = "GitHub Actions OIDC federation for agent-bom Azure ingestion."
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = local.github_subject
}

resource "azurerm_role_definition" "scanner" {
  count       = var.create_scanner_role_definition ? 1 : 0
  name        = "${var.name} Scanner"
  scope       = local.scanner_scope
  description = "Read-only role for agent-bom Azure AI infrastructure security scanning."

  permissions {
    actions = [
      "Microsoft.App/containerApps/read",
      "Microsoft.Authorization/roleAssignments/read",
      "Microsoft.Authorization/roleDefinitions/read",
      "Microsoft.Authorization/denyAssignments/read",
      "Microsoft.CognitiveServices/accounts/deployments/read",
      "Microsoft.CognitiveServices/accounts/read",
      "Microsoft.Compute/disks/read",
      "Microsoft.Compute/virtualMachines/extensions/read",
      "Microsoft.Compute/virtualMachines/instanceView/read",
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.ContainerInstance/containerGroups/read",
      "Microsoft.ContainerRegistry/registries/read",
      "Microsoft.ContainerRegistry/registries/repositories/read",
      "Microsoft.ContainerService/managedClusters/agentPools/read",
      "Microsoft.ContainerService/managedClusters/read",
      "Microsoft.DBforMySQL/servers/read",
      "Microsoft.DBforPostgreSQL/servers/configurations/read",
      "Microsoft.DBforPostgreSQL/servers/read",
      "Microsoft.Insights/activityLogAlerts/read",
      "Microsoft.Insights/diagnosticSettings/read",
      "Microsoft.Insights/logProfiles/read",
      "Microsoft.KeyVault/vaults/keys/read",
      "Microsoft.KeyVault/vaults/privateEndpointConnections/read",
      "Microsoft.KeyVault/vaults/read",
      "Microsoft.MachineLearningServices/workspaces/computes/read",
      "Microsoft.MachineLearningServices/workspaces/endpoints/read",
      "Microsoft.MachineLearningServices/workspaces/models/read",
      "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read",
      "Microsoft.MachineLearningServices/workspaces/read",
      "Microsoft.Network/applicationGateways/read",
      "Microsoft.Network/frontDoors/read",
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Network/networkWatchers/read",
      "Microsoft.Resources/subscriptions/read",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
      "Microsoft.Security/pricings/read",
      "Microsoft.Sql/servers/administrators/read",
      "Microsoft.Sql/servers/advancedThreatProtectionSettings/read",
      "Microsoft.Sql/servers/auditingSettings/read",
      "Microsoft.Sql/servers/encryptionProtector/read",
      "Microsoft.Sql/servers/read",
      "Microsoft.Sql/servers/vulnerabilityAssessments/read",
      "Microsoft.Storage/storageAccounts/blobServices/read",
      "Microsoft.Storage/storageAccounts/privateEndpointConnections/read",
      "Microsoft.Storage/storageAccounts/read",
      "Microsoft.Web/sites/config/read",
      "Microsoft.Web/sites/read",
    ]
    not_actions = []
  }

  assignable_scopes = [local.scanner_scope]
}

resource "azurerm_role_assignment" "scanner" {
  scope              = local.scanner_scope
  role_definition_id = var.create_scanner_role_definition ? azurerm_role_definition.scanner[0].role_definition_resource_id : var.scanner_role_definition_id
  principal_id       = azuread_service_principal.github_ingestion.object_id
}

resource "azurerm_key_vault" "ingestion" {
  count                         = var.create_key_vault ? 1 : 0
  name                          = local.key_vault_name
  location                      = var.location
  resource_group_name           = local.resource_group
  tenant_id                     = var.tenant_id
  sku_name                      = var.key_vault_sku_name
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 7
  public_network_access_enabled = var.key_vault_public_network_access_enabled
  tags                          = local.common_tags

  depends_on = [azurerm_resource_group.this]
}

resource "azurerm_role_assignment" "key_vault_secret_reader" {
  for_each = var.create_key_vault ? toset(concat([azuread_service_principal.github_ingestion.object_id], var.key_vault_secret_reader_principal_ids)) : toset([])

  scope                = azurerm_key_vault.ingestion[0].id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = each.value
}
