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

output "federated_credential_id" {
  description = "ID of the keyless federated identity credential (empty when create_federated_credential is false)."
  value       = var.create_federated_credential ? azuread_application_federated_identity_credential.scanner[0].id : ""
}

output "federated_credential_subject" {
  description = "The exact subject the federated credential is pinned to (empty when not created)."
  value       = var.create_federated_credential ? var.federated_credential_subject : ""
}
