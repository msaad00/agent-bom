output "role_definition_id" {
  description = "ID of the custom Azure side-scan lifecycle role."
  value       = azurerm_role_definition.sidescan.role_definition_resource_id
}

output "role_assignment_id" {
  description = "ID of the assignment to the collector workload identity."
  value       = azurerm_role_assignment.sidescan.id
}
