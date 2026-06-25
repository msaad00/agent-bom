output "role_name" {
  description = "The read-only role created for agent-bom."
  value       = snowflake_account_role.readonly.name
}

output "user_name" {
  description = "The key-pair scanner user. Set SNOWFLAKE_USER to this value."
  value       = snowflake_service_user.scanner.name
}

output "warehouse_name" {
  description = "Warehouse the scanner is granted USAGE on."
  value       = var.warehouse_name
}

output "granted_privileges" {
  description = "Read-only privileges granted to the role."
  value = [
    "IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE",
    "MONITOR USAGE ON ACCOUNT",
    "USAGE ON WAREHOUSE ${var.warehouse_name}",
  ]
}
