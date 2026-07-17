variable "project_id" {
  description = "GCP project that owns the target disks and in-project collector."
  type        = string
}

variable "member" {
  description = "IAM member for the collector workload identity, for example serviceAccount:collector@project.iam.gserviceaccount.com."
  type        = string
}

variable "role_id" {
  description = "Project custom role ID for the side-scan lifecycle."
  type        = string
  default     = "agentBomSideScanLifecycle"
}

variable "role_title" {
  description = "Display title for the custom role."
  type        = string
  default     = "agent-bom side-scan lifecycle"
}
