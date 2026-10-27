# Declared access for the dogfooded project: exactly what exists today, nothing more.
#
# Every IAM resource here is NON-authoritative (`*_iam_member`): it manages one
# (role, member) pair and ignores everything else on the policy. That is the safe
# choice to apply, and it is also why `terraform plan` can't see grants added
# outside Terraform. Catching those is the auditor's job (DESIGN.md D2).

locals {
  reader_email = "auditor-reader@${var.project_id}.iam.gserviceaccount.com"
  reader_roles = toset([
    "roles/iam.securityReviewer",
    "roles/policyanalyzer.activityAnalysisViewer",
    "roles/serviceusage.serviceUsageConsumer",
  ])
}

# ---------------------------------------------------------------- you

resource "google_project_iam_member" "operator_owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "user:${var.operator_email}"

  # Threat model T4: refuses any plan that would remove the Owner binding while
  # this block exists. Same limit as on the reader account below: deleting the
  # block deletes the guard.
  lifecycle {
    prevent_destroy = true
  }
}

import {
  to = google_project_iam_member.operator_owner
  id = "${var.project_id} roles/owner user:${var.operator_email}"
}

# ---------------------------------------------------------------- the reader

resource "google_service_account" "reader" {
  account_id   = "auditor-reader"
  display_name = "entitlement-auditor (read-only)"
  description  = "Discovery only. No write roles. Impersonated, never keyed."

  # Refuses any plan that would destroy or REPLACE the account while this block
  # exists, e.g. an edit to account_id, which forces a replacement. It does NOT
  # protect against deleting this whole block: the guard goes with it. To stop
  # managing the account without deleting it, use a `removed` block with
  # `lifecycle { destroy = false }` instead of deleting the resource.
  lifecycle {
    prevent_destroy = true
  }
}

import {
  to = google_service_account.reader
  id = "projects/${var.project_id}/serviceAccounts/${local.reader_email}"
}

resource "google_project_iam_member" "reader" {
  for_each = local.reader_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.reader.email}"
}

import {
  for_each = local.reader_roles
  to       = google_project_iam_member.reader[each.value]
  id       = "${var.project_id} ${each.value} serviceAccount:${local.reader_email}"
}

# Bound on the service account, not the project: Token Creator at project level
# would let you mint tokens for every SA in the project (BOOTSTRAP.md §3).
resource "google_service_account_iam_member" "operator_impersonates_reader" {
  service_account_id = google_service_account.reader.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "user:${var.operator_email}"
}

import {
  to = google_service_account_iam_member.operator_impersonates_reader
  id = "projects/${var.project_id}/serviceAccounts/${local.reader_email} roles/iam.serviceAccountTokenCreator user:${var.operator_email}"
}
