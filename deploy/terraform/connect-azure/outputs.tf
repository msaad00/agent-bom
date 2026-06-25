output "reader_role_assignment_id" {
  description = "ID of the built-in Reader role assignment."
  value       = azurerm_role_assignment.reader.id
}

output "security_reader_role_assignment_id" {
  description = "ID of the built-in Security Reader role assignment (empty when assign_security_reader is false)."
  value       = var.assign_security_reader ? azurerm_role_assignment.security_reader[0].id : ""
}

output "scope" {
  description = "Scope the read-only roles were assigned at (subscription or management group)."
  value       = local.scope
}

output "principal_id" {
  description = "Object ID of the principal granted read-only access."
  value       = var.principal_id
}

output "assigned_roles" {
  description = "Built-in read-only roles assigned to the principal."
  value       = compact(["Reader", var.assign_security_reader ? "Security Reader" : ""])
}
