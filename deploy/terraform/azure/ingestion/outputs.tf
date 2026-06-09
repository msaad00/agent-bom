output "azure_client_id" {
  description = "Application/client ID for GitHub Actions OIDC login."
  value       = azuread_application.github_ingestion.client_id
}

output "azure_tenant_id" {
  description = "Tenant ID for GitHub Actions OIDC login."
  value       = var.tenant_id
}

output "azure_subscription_id" {
  description = "Subscription ID scanned by the ingestion workflow."
  value       = var.subscription_id
}

output "service_principal_object_id" {
  description = "Object ID of the GitHub ingestion service principal."
  value       = azuread_service_principal.github_ingestion.object_id
}

output "federated_subject" {
  description = "GitHub OIDC subject trusted by the Azure application."
  value       = local.github_subject
}

output "scanner_scope" {
  description = "Azure scope where scanner permissions were assigned."
  value       = local.scanner_scope
}

output "scanner_role_definition_id" {
  description = "Custom role definition ID used for scanner access."
  value       = var.create_scanner_role_definition ? azurerm_role_definition.scanner[0].role_definition_resource_id : var.scanner_role_definition_id
}

output "resource_group_name" {
  description = "Support resource group name."
  value       = local.resource_group
}

output "key_vault_name" {
  description = "Key Vault name for ingestion workflow configuration."
  value       = var.create_key_vault ? azurerm_key_vault.ingestion[0].name : null
}

output "key_vault_uri" {
  description = "Key Vault URI for ingestion workflow configuration."
  value       = var.create_key_vault ? azurerm_key_vault.ingestion[0].vault_uri : null
}

output "api_url_secret_name" {
  description = "Expected Key Vault secret name for the agent-bom API base URL."
  value       = var.api_url_secret_name
}

output "api_key_secret_name" {
  description = "Expected Key Vault secret name for the agent-bom API key."
  value       = var.api_key_secret_name
}

output "github_variables_hint" {
  description = "Repository variables consumed by .github/workflows/azure-ingestion.yml."
  value = {
    AGENT_BOM_AZURE_CLIENT_ID       = azuread_application.github_ingestion.client_id
    AGENT_BOM_AZURE_TENANT_ID       = var.tenant_id
    AGENT_BOM_AZURE_SUBSCRIPTION_ID = var.subscription_id
    AGENT_BOM_AZURE_KEY_VAULT_NAME  = var.create_key_vault ? azurerm_key_vault.ingestion[0].name : ""
  }
}

output "key_vault_secret_commands" {
  description = "Commands to set ingestion API configuration outside Terraform state."
  value = var.create_key_vault ? [
    "az keyvault secret set --vault-name ${azurerm_key_vault.ingestion[0].name} --name ${var.api_url_secret_name} --value https://agent-bom.example.com",
    "az keyvault secret set --vault-name ${azurerm_key_vault.ingestion[0].name} --name ${var.api_key_secret_name} --value '<tenant-scoped analyst API key>'",
  ] : []
}
