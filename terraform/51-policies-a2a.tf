# Agent-to-Agent (A2A) governance:
#   1. Resolves the four auto-registered specialist agents in Agent Registry so
#      52-policies-access.tf can permit `soc_orchestrator -> <specialist>` at
#      the egress Agent Gateway while denying peer-to-peer specialist hops.
#   2. Grants `roles/aiplatform.viewer` on each specialist Reasoning Engine ONLY
#      to `soc_orchestrator`'s SPIFFE workload identity.

locals {
  a2a_policies_enabled = var.enable_agent_registry_policies

  agent_card_names = {
    for name in local.agent_names : name => jsondecode(local.agent_card_json[name]).name
  }

  agent_registry_filters = {
    for name in local.agent_names :
    name => lookup(var.agent_registry_filters, name, "displayName=\"${local.agent_card_names[name]}\"")
  }

  # Value-level ordering on each specialist engine's numeric `name` without
  # `depends_on` (so perpetual `- agent_card` diffs do not defer plan-time reads).
  agent_registry_read_after = {
    cti_researcher     = substr(google_vertex_ai_reasoning_engine.cti_researcher.name, 0, 0)
    threat_hunter      = substr(google_vertex_ai_reasoning_engine.threat_hunter.name, 0, 0)
    detection_engineer = substr(google_vertex_ai_reasoning_engine.detection_engineer.name, 0, 0)
    tier2_responder    = substr(google_vertex_ai_reasoning_engine.tier2_responder.name, 0, 0)
  }
}

data "google_agent_registry_agent" "cti_researcher" {
  count = local.a2a_policies_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  location = var.region
  filter   = "${local.agent_registry_filters["cti_researcher"]}${local.agent_registry_read_after["cti_researcher"]}"
}

data "google_agent_registry_agent" "threat_hunter" {
  count = local.a2a_policies_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  location = var.region
  filter   = "${local.agent_registry_filters["threat_hunter"]}${local.agent_registry_read_after["threat_hunter"]}"
}

data "google_agent_registry_agent" "detection_engineer" {
  count = local.a2a_policies_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  location = var.region
  filter   = "${local.agent_registry_filters["detection_engineer"]}${local.agent_registry_read_after["detection_engineer"]}"
}

data "google_agent_registry_agent" "tier2_responder" {
  count = local.a2a_policies_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  location = var.region
  filter   = "${local.agent_registry_filters["tier2_responder"]}${local.agent_registry_read_after["tier2_responder"]}"
}

resource "google_vertex_ai_reasoning_engine_iam_member" "orch_to_specialist" {
  for_each = {
    cti_researcher     = google_vertex_ai_reasoning_engine.cti_researcher
    threat_hunter      = google_vertex_ai_reasoning_engine.threat_hunter
    detection_engineer = google_vertex_ai_reasoning_engine.detection_engineer
    tier2_responder    = google_vertex_ai_reasoning_engine.tier2_responder
  }

  provider         = google-beta
  project          = var.project_id
  region           = var.region
  reasoning_engine = each.value.name
  role             = "roles/aiplatform.viewer"
  member           = local.agent_principals["soc_orchestrator"]

  lifecycle {
    precondition {
      condition     = local.agent_identity_ok["soc_orchestrator"]
      error_message = local.agent_identity_error["soc_orchestrator"]
    }
  }
}
