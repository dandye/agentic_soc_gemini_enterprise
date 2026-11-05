provider "google-beta" {
  project = var.project_id
  region  = var.region

  user_project_override = true
  billing_project       = var.project_id
}
