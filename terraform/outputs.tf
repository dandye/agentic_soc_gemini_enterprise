output "project_id" {
  description = "Google Cloud project ID hosting the governed SecOps stack."
  value       = var.project_id
}

output "region" {
  description = "Google Cloud region hosting the Agent Gateway, Agent Registry, Reasoning Engines, and Model Armor templates."
  value       = var.region
}

output "google_api_endpoint_ids" {
  description = "Registered Google API infrastructure endpoints in Agent Registry."
  value       = local.google_api_endpoint_ids
}

output "gti_endpoint_id" {
  description = "Agent Registry endpoint ID for `www.virustotal.com`, granted exclusively to `cti_researcher`."
  value       = local.gti_endpoint_id
}

output "chronicle_mcp_server_id" {
  description = "Agent Registry MCP server ID for Google SecOps Chronicle OneMCP."
  value       = local.chronicle_mcp_server_id
}

output "gti_auth_provider_name" {
  description = "Agent Platform Auth Manager resource name holding the GTI / VirusTotal v3 API key."
  value       = terraform_data.gti_auth_provider.output.name
}

output "agent_gateway_name" {
  description = "Full resource name of the egress Agent Gateway."
  value       = local.agent_gateway_name
}

output "agent_gateway_card" {
  description = "Output-only Agent Gateway card metadata."
  value       = google_network_services_agent_gateway.egress.agent_gateway_card
}

output "authz_enforcement" {
  description = "Current state of the IAP REQUEST_AUTHZ extension and policy."
  value = {
    mode      = var.authz_enforcement_mode
    fail_open = local.authz_fail_open
    extension = google_network_services_authz_extension.iap.id
    policy    = google_network_security_authz_policy.request_authz.id
  }
}

output "agent_engines" {
  description = "Resource paths, bare IDs, and A2A URLs for all five governed SecOps Reasoning Engines."
  value = {
    for name, engine in local.agents : name => {
      path      = "projects/${var.project_id}/locations/${var.region}/reasoningEngines/${engine.name}"
      engine_id = engine.name
      a2a_url = join("", [
        "https://${var.region}-aiplatform.googleapis.com/${local.a2a_api_version}",
        "/projects/${var.project_id}/locations/${var.region}/reasoningEngines/${engine.name}/a2a",
      ])
    }
  }
}

output "agent_identities" {
  description = "Raw `spec.effective_identity` SPIFFE workload identities assigned to the five Reasoning Engines."
  value       = local.agent_identities_raw
}

output "agent_principals" {
  description = "Scheme-prefixed `principal://` SPIFFE workload identities used in IAM v3 access policies."
  value       = local.agent_principals
}

output "agent_principals_long_form" {
  description = "Alias of `agent_principals` matching `principalSubject` in IAP Data Access audit logs."
  value       = local.agent_principals_long_form
}

output "agent_source_hashes" {
  description = "Deterministic SHA-256 source-tree hashes packaged into `terraform/dist/<name>.tar.gz`."
  value       = local.agent_source_hash
}

output "chronicle_tool_policies" {
  description = "Per-specialist Chronicle MCP tool allowlists and compiled IAM v3 CEL expressions."
  value = {
    threat_hunter = {
      allowed     = local.threat_hunter_allowed_tools
      expressions = local.mcp_specialist_cels["threat_hunter"]
    }
    detection_engineer = {
      allowed     = local.detection_engineer_allowed_tools
      expressions = local.mcp_specialist_cels["detection_engineer"]
    }
    tier2_responder = {
      allowed     = local.tier2_responder_allowed_tools
      expressions = local.mcp_specialist_cels["tier2_responder"]
    }
    denied_demo_tools = local.denied_mcp_tools
  }
}

output "a2a_edges" {
  description = "Permitted A2A edges (`soc_orchestrator -> <specialist>`)."
  value = local.a2a_policies_enabled ? {
    "soc_orchestrator -> cti_researcher"     = one(data.google_agent_registry_agent.cti_researcher[*].urn)
    "soc_orchestrator -> threat_hunter"      = one(data.google_agent_registry_agent.threat_hunter[*].urn)
    "soc_orchestrator -> detection_engineer" = one(data.google_agent_registry_agent.detection_engineer[*].urn)
    "soc_orchestrator -> tier2_responder"    = one(data.google_agent_registry_agent.tier2_responder[*].urn)
  } : {}
}

output "ge_binding" {
  description = "Gemini Enterprise app binding status and custom service-agent role."
  value = {
    bound         = var.bind_ge_app
    published     = var.create_ge_agent
    engine        = var.ge_engine_id != "" ? "projects/${local.project_number}/locations/${var.ge_location}/collections/${var.ge_collection_id}/engines/${var.ge_engine_id}" : null
    gateway       = local.agent_gateway_name
    service_agent = local.discoveryengine_service_agent
    custom_role   = google_project_iam_custom_role.ge_agent_gateway.id
  }
}

output "content_governance" {
  description = "Model Armor and Semantic Governance enforcement status on the Agent Gateway."
  value = {
    policy_count = 1 + (var.enable_model_armor ? 1 : 0) + (var.enable_semantic_governance ? 1 : 0)

    model_armor = var.enable_model_armor ? {
      enforcement = var.model_armor_enforcement_type
      confidence  = var.model_armor_confidence_level
      fail_open   = local.model_armor_fail_open
      templates   = local.model_armor_template_ids
      extension   = one(google_network_services_authz_extension.model_armor[*].id)
      policy      = one(google_network_security_authz_policy.content_authz[*].id)
    } : null

    semantic_governance = var.enable_semantic_governance ? {
      enforcement        = var.sgp_enforcement_mode
      endpoint           = local.sgp_host
      engine             = one(google_vertex_ai_semantic_governance_policy_engine.sgp[*].name)
      engine_state       = one(google_vertex_ai_semantic_governance_policy_engine.sgp[*].state)
      network            = one(google_compute_network.sgp[*].id)
      attachment         = one(google_compute_network_attachment.sgp[*].id)
      extension          = one(google_network_services_authz_extension.sgp[*].id)
      policy             = one(google_network_security_authz_policy.sgp_content_authz[*].id)
      policy_ids         = [for p in local.sgp_all_policies : p.id]
      tier2_policy_agent = local.sgp_tier2_crown_jewel_enabled ? local.sgp_tier2_agent : null
    } : null
  }
}

output "observability" {
  description = "Cloud Monitoring dashboard URL and log-based metric identifiers."
  value = var.enable_observability_dashboard ? {
    dashboard         = "https://console.cloud.google.com/monitoring/dashboards/builder/${var.resource_prefix}-secops-governance?project=${var.project_id}"
    id                = one(google_monitoring_dashboard.secops_governance[*].id)
    metrics           = values(local.obs_metric_ids)
    ge_prompt_logging = local.ge_prompt_logging_enabled
  } : null
}
