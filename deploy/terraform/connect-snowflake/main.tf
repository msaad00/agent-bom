# connect-snowflake — mints the read-only grant agent-bom's Snowflake connector
# needs, mirroring the SQL in docs/CLOUD_CONNECT.md §5 as Terraform.
#
# The ONLY per-cloud difference: the ABOM_READONLY role + its read-only grants
# (IMPORTED PRIVILEGES on the SNOWFLAKE db, MONITOR USAGE on account, USAGE on a
# warehouse) and a key-pair scanner user. No password is ever set; no write
# privilege is granted. The connector runs only SELECT/SHOW over ACCOUNT_USAGE.

# ABOM_READONLY — the single read-only role.
resource "snowflake_account_role" "readonly" {
  name    = var.role_name
  comment = "Read-only role for agent-bom (ACCOUNT_USAGE + SHOW). No write privileges."
}

# IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE — powers ACCOUNT_USAGE.* + CIS checks.
resource "snowflake_grant_privileges_to_account_role" "imported_privileges" {
  account_role_name = snowflake_account_role.readonly.name
  privileges        = ["IMPORTED PRIVILEGES"]

  on_account_object {
    object_type = "DATABASE"
    object_name = "SNOWFLAKE"
  }
}

# MONITOR USAGE ON ACCOUNT — powers SHOW-based discovery (tasks, streams, …).
resource "snowflake_grant_privileges_to_account_role" "monitor_account" {
  account_role_name = snowflake_account_role.readonly.name
  privileges        = ["MONITOR USAGE"]
  on_account        = true
}

# USAGE ON WAREHOUSE — the compute to run the read-only SELECTs (usage only).
resource "snowflake_grant_privileges_to_account_role" "warehouse_usage" {
  account_role_name = snowflake_account_role.readonly.name
  privileges        = ["USAGE"]

  on_account_object {
    object_type = "WAREHOUSE"
    object_name = var.warehouse_name
  }
}

# Key-pair scanner user — no password, key-pair (RSA JWT) auth only.
resource "snowflake_service_user" "scanner" {
  name              = var.user_name
  default_role      = snowflake_account_role.readonly.name
  default_warehouse = var.warehouse_name
  default_namespace = var.default_namespace != "" ? var.default_namespace : null
  rsa_public_key    = var.rsa_public_key
  comment           = "Key-pair scanner user for agent-bom. No password; read-only via ABOM_READONLY."
}

# Bind the read-only role to the scanner user.
resource "snowflake_grant_account_role" "scanner_role" {
  role_name = snowflake_account_role.readonly.name
  user_name = snowflake_service_user.scanner.name
}
