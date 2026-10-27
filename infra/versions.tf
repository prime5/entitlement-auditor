terraform {
  # 1.7+: `import` blocks with for_each.
  required_version = ">= 1.7"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
      # The exact version is pinned in .terraform.lock.hcl, which IS committed
      # (threat model T9: supply chain).
    }
  }

  # Local state, gitignored. State holds real identifiers, so it never goes
  # to the public repo. Moving it to a GCS backend is a later decision.
}

provider "google" {
  project = var.project_id
  # No credentials here. The provider uses Application Default Credentials,
  # which on your Mac impersonate auditor-reader (BOOTSTRAP.md §5). So
  # `plan` and import-only `apply` run read-only, and any real change is
  # refused by IAM until you deliberately run it as yourself. See README.md.
}
