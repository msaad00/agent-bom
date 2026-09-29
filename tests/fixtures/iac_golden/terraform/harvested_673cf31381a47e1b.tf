
resource "azurerm_machine_learning_workspace" "ws" {
  name                          = "fraud-ws"
  resource_group_name           = "rg"
  application_insights_id       = "ai-id"
  key_vault_id                  = "kv-id"
  storage_account_id            = "sa-id"
  public_network_access_enabled = true
}
