# Optional Gemini Enterprise app-to-gateway binding (`var.bind_ge_app`, default
# `false` so existing shared Gemini Enterprise apps in a tenant are never
# mutated unless explicitly opted in).

locals {
  ge_gateway_role_id            = replace("${var.resource_prefix}_ge_agent_gateway", "-", "_")
  discoveryengine_service_agent = "service-${local.project_number}@gcp-sa-discoveryengine.iam.gserviceaccount.com"

  ge_required_gateway_region = {
    global = "us-central1"
    us     = "us-central1"
    eu     = "europe-west1"
  }

  ge_region_pairing_ok = lookup(local.ge_required_gateway_region, var.ge_location, var.region) == var.region
  bind_ge_app_script   = "${path.module}/../scripts/governance/bind_ge_app.sh"
}

resource "google_project_iam_custom_role" "ge_agent_gateway" {
  provider    = google-beta
  project     = var.project_id
  role_id     = local.ge_gateway_role_id
  title       = "SecOps Agent Gateway and Agent Registry access role"
  description = "Allows the Gemini Enterprise service agent to discover Agent Registry resources and route through the egress Agent Gateway (${var.resource_prefix})."

  permissions = [
    "agentregistry.agents.get",
    "agentregistry.agents.list",
    "agentregistry.agents.search",
    "agentregistry.mcpServers.get",
    "agentregistry.mcpServers.list",
    "agentregistry.mcpServers.search",
    "networkservices.agentGateways.get",
    "networkservices.agentGateways.list",
    "networkservices.agentGateways.use",
  ]

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "ge_agent_gateway" {
  provider = google-beta
  project  = var.project_id
  role     = google_project_iam_custom_role.ge_agent_gateway.id
  member   = "serviceAccount:${local.discoveryengine_service_agent}"

  depends_on = [google_project_service_identity.service_agents]
}

resource "terraform_data" "ge_binding" {
  count = var.bind_ge_app ? 1 : 0

  input = {
    project_id     = var.project_id
    project_number = local.project_number
    location       = var.ge_location
    collection_id  = var.ge_collection_id
    engine_id      = var.ge_engine_id
    gateway        = local.agent_gateway_name
    script         = local.bind_ge_app_script
  }

  triggers_replace = [
    var.ge_engine_id,
    var.ge_location,
    var.ge_collection_id,
    local.agent_gateway_name,
  ]

  lifecycle {
    precondition {
      condition     = local.ge_region_pairing_ok
      error_message = "A Gemini Enterprise app in '${var.ge_location}' requires its Agent Gateway in '${lookup(local.ge_required_gateway_region, var.ge_location, "?")}', got '${var.region}'."
    }
    precondition {
      condition     = trimspace(var.ge_engine_id) != ""
      error_message = "var.ge_engine_id is empty. Set it to the Gemini Enterprise app ID before enabling bind_ge_app."
    }
  }

  provisioner "local-exec" {
    command = "bash \"${local.bind_ge_app_script}\" bind"

    environment = {
      GE_PROJECT_ID     = var.project_id
      GE_PROJECT_NUMBER = local.project_number
      GE_LOCATION       = var.ge_location
      GE_COLLECTION_ID  = var.ge_collection_id
      GE_ENGINE_ID      = var.ge_engine_id
      GE_AGENT_GATEWAY  = local.agent_gateway_name
    }
  }

  provisioner "local-exec" {
    when       = destroy
    on_failure = continue
    command    = "bash \"${self.input.script}\" unbind"

    environment = {
      GE_PROJECT_ID     = self.input.project_id
      GE_PROJECT_NUMBER = self.input.project_number
      GE_LOCATION       = self.input.location
      GE_COLLECTION_ID  = self.input.collection_id
      GE_ENGINE_ID      = self.input.engine_id
    }
  }

  depends_on = [
    google_project_service.apis,
    google_network_services_agent_gateway.egress,
    google_network_security_authz_policy.request_authz,
    google_project_iam_member.ge_agent_gateway,
  ]
}
