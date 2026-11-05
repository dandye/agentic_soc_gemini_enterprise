# Registers outbound endpoints in Agent Registry (`var.region`).
# Agent Gateway operates in default-deny mode: any unregistered hostname is
# refused at the gateway, including runtime Google APIs.
#
# Note on service_id derivation:
# Regional hosts (`${var.region}-aiplatform.googleapis.com`) keep `<region>-...`
# while global/multi-regional hosts (`aiplatform.googleapis.com`,
# `aiplatform.us.rep.googleapis.com`) receive `${var.region}-g-...` so both
# regional and global endpoints register side-by-side without colliding on
# `service_id` (critical for `gemini-3.1-pro-preview` on `MODEL_LOCATION=global`).

locals {
  google_api_hosts_regional = [
    "${var.region}-aiplatform.googleapis.com",
    "${var.region}-discoveryengine.googleapis.com",
    "${var.region}-agentregistry.googleapis.com",
    "modelarmor.${var.region}.rep.googleapis.com",
  ]

  # Note: Chronicle MCP (`chronicle.<region>.rep.googleapis.com`) is NOT listed
  # here because infrastructure endpoints are granted to all agents, whereas
  # Chronicle MCP access is scoped per specialist in 11-registry-mcp.tf and
  # 52-policies-access.tf.
  google_api_hosts_global = [
    "aiplatform.googleapis.com",
    "aiplatform.us.rep.googleapis.com",
    "discoveryengine.googleapis.com",
    "agentregistry.googleapis.com",
    "agentidentity.googleapis.com",
    "agentidentitycredentials.googleapis.com",
    "iamcredentials.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iap.googleapis.com",
    "oauth2.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudtrace.googleapis.com",
    "telemetry.googleapis.com",
  ]

  google_api_hosts = concat(
    local.google_api_hosts_regional,
    local.google_api_hosts_global,
    var.extra_google_api_hosts,
  )

  api_id_base = {
    for h in toset(local.google_api_hosts) :
    h => replace(trimsuffix(h, ".googleapis.com"), ".", "-")
  }

  api_id_regionalized = {
    for h, base in local.api_id_base :
    h => startswith(base, "${var.region}-") ? base : "${var.region}-g-${base}"
  }

  api_id = {
    for h, id in local.api_id_regionalized :
    h => length(id) < 6 ? "${id}-api" : id
  }

  google_api_endpoints_by_id = {
    for h in local.google_api_hosts : local.api_id[h] => h...
  }

  google_api_endpoints = {
    for id, hosts in local.google_api_endpoints_by_id : id => hosts[0]
  }
}

resource "google_agent_registry_service" "google_apis" {
  for_each = local.google_api_endpoints

  provider     = google-beta
  project      = var.project_id
  location     = var.region
  service_id   = each.key
  display_name = each.value
  description  = "Google API infrastructure endpoint (${each.value}). Reachable by every governed agent."

  interfaces {
    url              = "https://${each.value}"
    protocol_binding = "JSONRPC"
  }

  endpoint_spec {
    type = "NO_SPEC"
  }

  depends_on = [google_project_service.apis]
}

# External Google Threat Intelligence (VirusTotal v3) REST endpoint.
# Granted exclusively to `cti_researcher` in 52-policies-access.tf.
resource "google_agent_registry_service" "gti_api" {
  provider     = google-beta
  project      = var.project_id
  location     = var.region
  service_id   = "${var.resource_prefix}-virustotal"
  display_name = "www.virustotal.com"
  description  = "Google Threat Intelligence (VirusTotal v3) REST API. Granted only to cti_researcher."

  interfaces {
    url              = "https://www.virustotal.com"
    protocol_binding = "HTTP_JSON"
  }

  endpoint_spec {
    type = "NO_SPEC"
  }

  depends_on = [google_project_service.apis]
}

locals {
  google_api_endpoint_ids = {
    for id, svc in google_agent_registry_service.google_apis :
    id => basename(svc.registry_resource)
  }
  gti_endpoint_id = basename(google_agent_registry_service.gti_api.registry_resource)
}
