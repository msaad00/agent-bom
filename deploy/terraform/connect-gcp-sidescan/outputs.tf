output "role_name" {
  description = "Fully qualified name of the project custom side-scan role."
  value       = google_project_iam_custom_role.sidescan.name
}
