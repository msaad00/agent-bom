variable "role_name" {
  description = "Name of the read-only role agent-bom uses."
  type        = string
  default     = "ABOM_READONLY"
}

variable "user_name" {
  description = "Name of the key-pair scanner user."
  type        = string
  default     = "ABOM_SCANNER"
}

variable "warehouse_name" {
  description = "Warehouse the scanner uses to run its read-only SELECTs. USAGE (not operate/modify) is granted on it."
  type        = string
  default     = "COMPUTE_WH"
}

variable "rsa_public_key" {
  description = "PEM-format RSA public key (body only, no -----BEGIN/END----- headers) for key-pair auth. The PRIVATE key never enters Terraform — it stays on the scanner host. No password is ever set."
  type        = string

  validation {
    condition     = length(trimspace(var.rsa_public_key)) > 0
    error_message = "rsa_public_key must be set — Snowflake password auth is not supported (key-pair only)."
  }
}

variable "default_namespace" {
  description = "Optional DEFAULT_NAMESPACE for the scanner user (e.g. SNOWFLAKE.ACCOUNT_USAGE). Empty leaves it unset."
  type        = string
  default     = ""
}
