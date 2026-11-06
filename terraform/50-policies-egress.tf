# SPIFFE Agent Identity derivation and per-specialist Chronicle MCP tool
# allowlists enforced at the egress Agent Gateway via IAM v3 CEL expressions
# in 52-policies-access.tf.

locals {
  trust_domain = "agents.global.org-${var.org_id}.system.id.goog"

  agent_identities_raw = {
    for name, engine in local.agents : name => engine.spec[0].effective_identity
  }

  agent_principals = {
    for name, id in local.agent_identities_raw :
    name => startswith(id, "principal://") ? id : "principal://${id}"
  }

  agent_principals_long_form = local.agent_principals

  agent_identity_ok = {
    for name, id in local.agent_identities_raw :
    name => startswith(id, "principal://${local.trust_domain}/") || startswith(id, "${local.trust_domain}/")
  }

  agent_identity_error = {
    for name, id in local.agent_identities_raw :
    name => join(" ", [
      "The ${name} agent's spec.effective_identity is ${jsonencode(id)}, which is",
      "not an identity under ${local.trust_domain}. Verify identity_type = AGENT_IDENTITY",
      "and `terraform output agent_identities`.",
    ])
  }

  # Read-only Chronicle SIEM hunting tools permitted for Threat Hunter.
  threat_hunter_allowed_tools = [
    "udm_search",
    "search_raw_logs",
    "translate_udm_query",
    "list_security_alerts",
    "get_security_alert",
    "fetch_alert_data",
    "search_entity",
    "summarize_entity",
    "get_ioc_match",
    "list_rules",
    "get_rule",
    "list_rule_detections",
  ]

  # YARA-L 2.0 rule validation, coverage, and search tools permitted for Detection Engineer.
  detection_engineer_allowed_tools = [
    "validate_rule",
    "list_rules",
    "get_rule",
    "list_rule_detections",
    "list_rule_errors",
    "evaluate_rule_coverage",
    "generate_synthetic_events",
    "udm_search",
    "translate_udm_query",
    "get_reference_list",
    "list_log_types",
  ]

  # Alert disposition and reference-list tools permitted for Tier-2 Responder.
  tier2_responder_allowed_tools = [
    "list_security_alerts",
    "get_security_alert",
    "update_security_alert",
    "fetch_alert_data",
    "search_entity",
    "summarize_entity",
    "get_ioc_match",
    "udm_search",
    "get_reference_list",
    "create_reference_list",
    "update_reference_list",
  ]

  # Destructive / administrative MCP tools advertised to specialists so a prompt
  # asking for them reaches the Agent Gateway and triggers a deterministic IAP
  # 403 tool-allowlist denial.
  denied_mcp_tools = [
    "list_feeds",
    "create_rule",
    "delete_feed",
    "create_reference_list",
    "execute_manual_action",
    "activate_parser",
    "deactivate_parser",
  ]
}
