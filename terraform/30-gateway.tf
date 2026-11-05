# Google-managed egress Agent Gateway (`AGENT_TO_ANYWHERE`).
# Every outbound LLM, MCP, REST, and A2A call from all five SecOps Reasoning
# Engines passes through this single choke point.

resource "google_network_services_agent_gateway" "egress" {
  provider    = google-beta
  project     = var.project_id
  name        = "${var.resource_prefix}-egress"
  location    = var.region
  description = "Egress Agent Gateway governing all outbound LLM, Chronicle MCP, GTI REST, and A2A traffic for the five SecOps agents."

  labels = {
    managed-by = "terraform"
    stack      = var.resource_prefix
  }

  google_managed {
    governed_access_path = "AGENT_TO_ANYWHERE"
  }

  registries = [
    "//agentregistry.googleapis.com/projects/${var.project_id}/locations/${var.region}",
  ]

  dynamic "network_config" {
    for_each = var.enable_semantic_governance ? [1] : []

    content {
      egress {
        network_attachment = google_compute_network_attachment.sgp[0].id
      }

      dns_peering_config {
        domains        = [local.sgp_dns_name]
        target_project = var.project_id
        target_network = "projects/${var.project_id}/global/networks/${google_compute_network.sgp[0].name}"
      }
    }
  }

  depends_on = [
    google_project_service.apis,
    google_project_service_identity.service_agents,
    google_agent_registry_service.google_apis,
    google_agent_registry_service.gti_api,
    google_agent_registry_service.chronicle_mcp,
  ]
}

locals {
  agent_gateway_name = google_network_services_agent_gateway.egress.id
}
