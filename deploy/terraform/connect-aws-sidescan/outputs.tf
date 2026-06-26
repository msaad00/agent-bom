output "role_arn" {
  description = "ARN of the scoped side-scan snapshot role. Hand this to the in-account collector / agent-bom side-scan so it can assume the role. This role is DISTINCT from the read-only connect-aws role."
  value       = aws_iam_role.this.arn
}

output "role_name" {
  description = "Name of the scoped side-scan snapshot role."
  value       = aws_iam_role.this.name
}

output "external_id" {
  description = "The sts:ExternalId required on assume-role. Always set (auto-generated when not supplied). Configure the collector with this value so it can assume the role. Marked sensitive — read it explicitly with `terraform output -raw external_id`."
  value       = local.effective_external_id
  sensitive   = true
}

output "sidescan_tag" {
  description = "The tag (key=value) the role is permitted to act on. Side-scan-created snapshots/volumes carry this tag; the role cannot touch resources without it."
  value       = "${var.sidescan_tag_key}=${var.sidescan_tag_value}"
}
