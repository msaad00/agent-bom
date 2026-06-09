variable "name" {
  description = "Base name for Azure resources."
  type        = string
  default     = "agent-bom"
}

variable "tenant_id" {
  description = "Existing Microsoft Entra tenant ID."
  type        = string
}

variable "subscription_id" {
  description = "Existing Azure subscription ID to scan and host support resources."
  type        = string
}

variable "location" {
  description = "Azure region for support resources such as Key Vault."
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Resource group for optional support resources. Defaults to <name>-ingestion."
  type        = string
  default     = ""
}

variable "create_resource_group" {
  description = "Whether to create the support resource group."
  type        = bool
  default     = true
}

variable "github_owner" {
  description = "GitHub repository owner or organization allowed to federate into Azure."
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name allowed to federate into Azure."
  type        = string
}

variable "github_ref" {
  description = "Git ref allowed to federate. Ignored when github_environment is set."
  type        = string
  default     = "refs/heads/main"
}

variable "github_environment" {
  description = "Optional GitHub environment name. When set, the federated subject uses environment scoping instead of a branch ref."
  type        = string
  default     = ""
}

variable "federated_subject_override" {
  description = "Optional exact GitHub OIDC subject. Use only when branch/environment defaults are not sufficient."
  type        = string
  default     = ""
}

variable "create_scanner_role_definition" {
  description = "Whether to create the custom agent-bom Scanner role definition."
  type        = bool
  default     = true
}

variable "scanner_role_definition_id" {
  description = "Existing custom role definition ID or built-in role ID to assign when create_scanner_role_definition is false."
  type        = string
  default     = ""
}

variable "scanner_role_scope" {
  description = "Scope for scanner role definition and assignment. Defaults to the subscription."
  type        = string
  default     = ""
}

variable "create_key_vault" {
  description = "Whether to create a Key Vault for ingestion workflow configuration."
  type        = bool
  default     = true
}

variable "key_vault_name" {
  description = "Optional Key Vault name. Defaults to a globally unique name derived from name."
  type        = string
  default     = ""
}

variable "key_vault_sku_name" {
  description = "Key Vault SKU."
  type        = string
  default     = "standard"
}

variable "key_vault_public_network_access_enabled" {
  description = "Whether the Key Vault accepts public network access. GitHub-hosted runners need this true; self-hosted private runners can set false with private networking."
  type        = bool
  default     = true
}

variable "key_vault_secret_reader_principal_ids" {
  description = "Additional principal object IDs allowed to read Key Vault secrets."
  type        = list(string)
  default     = []
}

variable "api_url_secret_name" {
  description = "Key Vault secret name expected to contain the agent-bom API base URL."
  type        = string
  default     = "agent-bom-api-url"
}

variable "api_key_secret_name" {
  description = "Key Vault secret name expected to contain the agent-bom API key."
  type        = string
  default     = "agent-bom-api-key"
}

variable "tags" {
  description = "Tags applied to Terraform-managed Azure resources."
  type        = map(string)
  default     = {}
}
