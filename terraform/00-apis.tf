# Enables required Google Cloud APIs and eagerly provisions Google-managed
# service agents for Vertex AI and Discovery Engine before reasoning engines or
# custom IAM bindings are created.

locals {
  required_apis = [
    # Agent platform & SecOps backends
    "aiplatform.googleapis.com",
    "agentregistry.googleapis.com",
    "agentidentity.googleapis.com",
    "discoveryengine.googleapis.com",
    "chronicle.googleapis.com",

    # Agent Gateway & inline authorization / content inspection
    "networkservices.googleapis.com",
    "networksecurity.googleapis.com",
    "iap.googleapis.com",
    "modelarmor.googleapis.com",

    # Semantic Governance Private Service Connect & private DNS
    "compute.googleapis.com",
    "dns.googleapis.com",

    # Platform, identity, and observability
    "cloudresourcemanager.googleapis.com",
    "serviceusage.googleapis.com",
    "iamcredentials.googleapis.com",
    "storage.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudtrace.googleapis.com",
    "telemetry.googleapis.com",
    "secretmanager.googleapis.com",
    "orgpolicy.googleapis.com",

    # Agent Platform console surfaces
    "apphub.googleapis.com",
    "apptopology.googleapis.com",
    "cloudapiregistry.googleapis.com",
    "iam.googleapis.com",
    "observability.googleapis.com",
    "securitycenter.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each = toset(local.required_apis)

  provider = google-beta
  project  = var.project_id
  service  = each.value

  disable_on_destroy         = false
  disable_dependent_services = false
}

resource "google_project_service_identity" "service_agents" {
  for_each = toset([
    "aiplatform.googleapis.com",
    "discoveryengine.googleapis.com",
  ])

  provider = google-beta
  project  = var.project_id
  service  = each.value

  depends_on = [google_project_service.apis]
}
