variable "aws_region" {
  description = "Region for the keys, secrets, ledger and alerting."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "web3-release"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.name_prefix))
    error_message = "name_prefix must be 3-31 chars of lowercase letters, digits and dashes."
  }
}

variable "github_repository" {
  description = "GitHub repository allowed to assume the release roles, as 'owner/repo'."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must look like 'owner/repo' (no wildcards)."
  }
}

variable "environments" {
  description = <<-EOT
    One isolated key + role + secret per release environment. Each name must match a
    GitHub Environment (which carries the required-reviewer and tag-only protection rules).
  EOT
  type = map(object({
    deletion_window_days = optional(number, 30)
  }))
  default = {
    testnet = {}
    mainnet = {}
  }

  validation {
    condition     = alltrue([for e in values(var.environments) : e.deletion_window_days >= 14])
    error_message = "Signing keys need a deletion window of at least 14 days to allow recovery."
  }
}

variable "create_github_oidc_provider" {
  description = "Create the GitHub Actions OIDC provider (false if the account already has one)."
  type        = bool
  default     = true
}

variable "key_admin_arns" {
  description = <<-EOT
    IAM principals that may administer (rotate policy, disable, schedule deletion) the signing
    keys. They can NEVER sign. Defaults to the account root, which delegates to IAM policies.
  EOT
  type        = list(string)
  default     = []
}

variable "alert_email" {
  description = "Optional e-mail subscribed to signing and tamper alerts."
  type        = string
  default     = null
}

variable "ledger_lock_mode" {
  description = "S3 Object Lock mode for the deployment ledger. COMPLIANCE is irreversible - even for root."
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.ledger_lock_mode)
    error_message = "ledger_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "ledger_retention_days" {
  description = "How long deployment records are immutable."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Extra tags applied to every resource."
  type        = map(string)
  default     = {}
}
