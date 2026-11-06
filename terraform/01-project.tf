# Resolves the numeric project number used to construct SPIFFE principalSet://
# identifiers and Google-managed service-agent email addresses.

data "google_project" "this" {
  provider   = google-beta
  project_id = var.project_id
}

locals {
  project_number = var.project_number != null ? var.project_number : data.google_project.this.number
}
