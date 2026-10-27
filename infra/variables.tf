variable "project_id" {
  description = "The dogfooded GCP project (from .env AUDITOR_PROJECT_IDS)."
  type        = string
}

variable "operator_email" {
  description = "Your Google account, lowercase. IAM may display it capitalized; it is the same principal."
  type        = string

  validation {
    condition     = var.operator_email == lower(var.operator_email)
    error_message = "Use the lowercase email: the auditor compares emails case-insensitively, Terraform does not."
  }
}
