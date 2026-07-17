variable "scope" {
  description = "Azure scope for the custom role and assignment. Prefer the narrow resource group containing target disks and the dedicated collector."
  type        = string
}

variable "principal_id" {
  description = "Object ID of the workload identity used by the in-subscription side-scan collector."
  type        = string
}

variable "role_name" {
  description = "Name of the custom Azure side-scan lifecycle role."
  type        = string
  default     = "agent-bom-side-scan-lifecycle"
}

variable "description" {
  description = "Description for the custom role definition."
  type        = string
  default     = "Opt-in snapshot, temporary managed disk, and collector attach/detach lifecycle for agent-bom side-scan."
}
