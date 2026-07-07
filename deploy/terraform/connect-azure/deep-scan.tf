# Data-plane reads the built-in Reader role does NOT cover.
#
# Reader grants control-plane (*/read) only. Two agent-bom scans need data-plane
# reads: Key Vault CIS 8.1/8.2 (keys/secrets expiry metadata) and ACR image SBOM.
# Both are read-only. Key Vault Reader covers RBAC-model vaults; access-policy
# vaults instead need a List access policy on keys/secrets (not managed here).

resource "azurerm_role_assignment" "key_vault_reader" {
  count = var.assign_key_vault_reader ? 1 : 0

  scope                = local.scope
  role_definition_name = "Key Vault Reader"
  principal_id         = var.principal_id
  principal_type       = var.principal_type
  description          = "Read-only Key Vault data-plane metadata (keys/secrets properties, not secret values) for CIS 8.1/8.2. RBAC-model vaults only."
}

resource "azurerm_role_assignment" "acr_pull" {
  count = var.assign_acr_pull ? 1 : 0

  scope                = local.scope
  role_definition_name = "AcrPull"
  principal_id         = var.principal_id
  principal_type       = var.principal_type
  description          = "Read-only ACR data-plane pull for container-image SBOM extraction."
}
