# IAM v3 Unified Access Policies evaluated by IAP (`iapPolicyVersion = "V2"`):
#   1. `google_apis`:      infrastructure Google APIs granted to every agent in the project.
#   2. `agent_tool_edges`: least-privilege per-specialist external/MCP egress:
#        - `cti_researcher`     -> external GTI (`www.virustotal.com`) endpoint ONLY
#        - `threat_hunter`      -> Chronicle MCP read-only tool allowlist + `tools/list`
#        - `detection_engineer` -> Chronicle MCP YARA-L 2.0 validation/coverage allowlist + `tools/list`
#        - `tier2_responder`    -> Chronicle MCP Tier-2 alert/reference-list allowlist + `tools/list`
#   3. `agent_a2a_edges`:  explicit A2A hops (`soc_orchestrator -> <specialist>` ONLY).
#
# IAM v3 enforces two FGAC ceilings on `iap.googleapis.com` access policies:
#   * <= 10 FGAC rule conditions per `google_iam_project_access_policy`
#   * <= 10 items per CEL `in [...]` list literal, and <= 1024 chars per expression
# Splitting tool egress from A2A edges and chunking MCP allowlists at <= 9 tools
# per rule keeps every policy and rule comfortably within both ceilings.

locals {
  all_agent_identities = "principalSet://${local.trust_domain}/attribute.container/projects/${local.project_number}"

  google_apis_access_policy_id  = "${var.resource_prefix}-google-apis"
  google_apis_policy_binding_id = "${var.resource_prefix}-google-apis-binding"

  google_api_endpoint_names = [
    for id in sort(keys(local.google_api_endpoint_ids)) :
    "projects/${var.project_id}/locations/${var.region}/endpoints/${local.google_api_endpoint_ids[id]}"
  ]

  google_apis_endpoints_per_rule = 5

  google_apis_rule_conditions = [
    for chunk in chunklist(local.google_api_endpoint_names, local.google_apis_endpoints_per_rule) :
    "(${join(" || ", [for name in chunk : "destination.agent_registry.endpoint.name == '${name}'"])})"
  ]

  agent_tool_access_policy_id  = "${var.resource_prefix}-agent-tools"
  agent_tool_policy_binding_id = "${var.resource_prefix}-agent-tools-binding"

  agent_a2a_access_policy_id  = "${var.resource_prefix}-a2a-edges"
  agent_a2a_policy_binding_id = "${var.resource_prefix}-a2a-edges-binding"

  gti_endpoint_name         = "projects/${var.project_id}/locations/${var.region}/endpoints/${local.gti_endpoint_id}"
  chronicle_mcp_server_name = "projects/${var.project_id}/locations/${var.region}/mcpServers/${local.chronicle_mcp_server_id}"

  # IAM v3 `iap.googleapis.com` CEL rules cap every `in [...]` list literal at 10
  # items (in addition to the 1024-character per-rule cap), so chunk each
  # specialist's MCP allowlist into <= 9 tools per rule and attach `tools/list`
  # to chunk 0.
  mcp_tools_per_rule = 9

  mcp_specialist_allowlists = {
    threat_hunter = {
      label = "Threat Hunter -> Chronicle MCP read-only hunt allowlist"
      tools = local.threat_hunter_allowed_tools
    }
    detection_engineer = {
      label = "Detection Engineer -> Chronicle MCP YARA-L 2.0 validation/coverage allowlist"
      tools = local.detection_engineer_allowed_tools
    }
    tier2_responder = {
      label = "Tier-2 Responder -> Chronicle MCP alert and reference-list allowlist"
      tools = local.tier2_responder_allowed_tools
    }
  }

  mcp_specialist_chunks = {
    for agent_name, spec in local.mcp_specialist_allowlists :
    agent_name => chunklist(spec.tools, local.mcp_tools_per_rule)
  }

  mcp_specialist_cels = {
    for agent_name, chunks in local.mcp_specialist_chunks :
    agent_name => [
      for idx, chunk in chunks : (
        idx == 0
        ? "destination.agent_registry.mcp_server.name == '${local.chronicle_mcp_server_name}' && (destination.agent_registry.mcp_server.tool.name in [${join(", ", [for t in chunk : "'${t}'"])}] || destination.agent_registry.mcp_server.method == 'tools/list')"
        : "destination.agent_registry.mcp_server.name == '${local.chronicle_mcp_server_name}' && destination.agent_registry.mcp_server.tool.name in [${join(", ", [for t in chunk : "'${t}'"])}]"
      )
    ]
  }

  mcp_specialist_rules = var.chronicle_enforce_tool_allowlist ? merge([
    for agent_name, spec in local.mcp_specialist_allowlists : {
      for idx, expr in local.mcp_specialist_cels[agent_name] :
      "${agent_name}_mcp_${idx + 1}" => {
        description = "${spec.label} (part ${idx + 1} of ${length(local.mcp_specialist_cels[agent_name])}${idx == 0 ? ", plus tools/list" : ""})"
        effect      = "ALLOW"
        principal   = local.agent_principals[agent_name]
        expression  = expr
      }
    }
  ]...) : {
    for agent_name, spec in local.mcp_specialist_allowlists :
    "${agent_name}_mcp_all" => {
      description = "${spec.label} (all tools diagnostic)"
      effect      = "ALLOW"
      principal   = local.agent_principals[agent_name]
      expression  = "destination.agent_registry.mcp_server.name == '${local.chronicle_mcp_server_name}'"
    }
  }

  agent_tool_rules = merge(
    {
      cti_gti = {
        description = "CTI Researcher -> www.virustotal.com (GTI v3 REST API)"
        effect      = "ALLOW"
        principal   = local.agent_principals["cti_researcher"]
        expression  = "destination.agent_registry.endpoint.name == '${local.gti_endpoint_name}'"
      }
    },
    local.mcp_specialist_rules,
  )

  agent_a2a_rules = local.a2a_policies_enabled ? {
    orch_to_cti_researcher = {
      description = "SOC Orchestrator -> CTI Researcher (A2A)"
      effect      = "ALLOW"
      principal   = local.agent_principals["soc_orchestrator"]
      expression  = "destination.agent_registry.agent.name == 'projects/${var.project_id}/locations/${var.region}/agents/${data.google_agent_registry_agent.cti_researcher[0].agent_id}'"
    }
    orch_to_threat_hunter = {
      description = "SOC Orchestrator -> Threat Hunter (A2A)"
      effect      = "ALLOW"
      principal   = local.agent_principals["soc_orchestrator"]
      expression  = "destination.agent_registry.agent.name == 'projects/${var.project_id}/locations/${var.region}/agents/${data.google_agent_registry_agent.threat_hunter[0].agent_id}'"
    }
    orch_to_detection_engineer = {
      description = "SOC Orchestrator -> Detection Engineer (A2A)"
      effect      = "ALLOW"
      principal   = local.agent_principals["soc_orchestrator"]
      expression  = "destination.agent_registry.agent.name == 'projects/${var.project_id}/locations/${var.region}/agents/${data.google_agent_registry_agent.detection_engineer[0].agent_id}'"
    }
    orch_to_tier2_responder = {
      description = "SOC Orchestrator -> Tier-2 Responder (A2A)"
      effect      = "ALLOW"
      principal   = local.agent_principals["soc_orchestrator"]
      expression  = "destination.agent_registry.agent.name == 'projects/${var.project_id}/locations/${var.region}/agents/${data.google_agent_registry_agent.tier2_responder[0].agent_id}'"
    }
  } : {}
}

resource "google_org_policy_policy" "allow_access_policy_binding" {
  count    = var.manage_org_policy_override ? 1 : 0
  provider = google-beta
  name     = "projects/${var.project_id}/policies/iam.managed.disableAccessPolicyBinding"
  parent   = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "FALSE"
    }
  }

  depends_on = [google_project_service.apis]
}

resource "time_sleep" "access_policy_binding_override" {
  count           = var.manage_org_policy_override ? 1 : 0
  create_duration = "120s"

  triggers = {
    policy = google_org_policy_policy.allow_access_policy_binding[0].id
  }

  depends_on = [google_org_policy_policy.allow_access_policy_binding]
}

resource "google_iam_project_access_policy" "google_apis" {
  provider         = google-beta
  project          = var.project_id
  location         = "global"
  access_policy_id = local.google_apis_access_policy_id
  display_name     = "Google APIs, all governed SecOps agents"

  details {
    dynamic "rules" {
      for_each = local.google_apis_rule_conditions
      content {
        description = "Google API infrastructure endpoints, part ${rules.key + 1} of ${length(local.google_apis_rule_conditions)}."
        effect      = "ALLOW"
        principals  = [local.all_agent_identities]

        operation {
          permissions = ["iap.googleapis.com/resources.egressViaIAP"]
        }

        conditions {
          service    = "iap.googleapis.com"
          expression = rules.value
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = length(local.google_apis_rule_conditions) > 0 && length(local.google_apis_rule_conditions) <= 10 && alltrue([for c in local.google_apis_rule_conditions : length(c) > 2 && length(c) <= 1024])
      error_message = "google_apis must have 1..10 FGAC rules, each non-empty and at most 1024 characters."
    }
    precondition {
      condition     = !anytrue([for c in local.google_apis_rule_conditions : strcontains(c, local.gti_endpoint_id) || strcontains(c, local.chronicle_mcp_server_id)])
      error_message = "The Google APIs access policy condition must not contain the GTI endpoint or Chronicle MCP server."
    }
  }
}

resource "google_iam_projects_policy_binding" "google_apis" {
  provider          = google-beta
  project           = var.project_id
  location          = "global"
  policy_binding_id = local.google_apis_policy_binding_id
  policy_kind       = "ACCESS"
  policy            = google_iam_project_access_policy.google_apis.name

  target {
    resource = "//cloudresourcemanager.googleapis.com/projects/${var.project_id}"
  }

  depends_on = [time_sleep.access_policy_binding_override, terraform_data.google_apis_policy_binding]
}

resource "terraform_data" "google_apis_policy_binding" {
  input = {
    project_id = var.project_id
    binding_id = local.google_apis_policy_binding_id
  }

  triggers_replace = ["google_iam_projects_policy_binding"]

  provisioner "local-exec" {
    when    = destroy
    command = "bash \"${path.module}/../scripts/governance/delete_until_gone.sh\" \"${self.input.project_id}\" \"https://iam.googleapis.com/v3/projects/${self.input.project_id}/locations/global/policyBindings/${self.input.binding_id}\""
  }
}

resource "google_iam_project_access_policy" "agent_tool_edges" {
  provider         = google-beta
  project          = var.project_id
  location         = "global"
  access_policy_id = local.agent_tool_access_policy_id
  display_name     = "SecOps per-specialist GTI and Chronicle MCP tool allowlists"

  details {
    dynamic "rules" {
      for_each = local.agent_tool_rules
      content {
        description = rules.value.description
        effect      = rules.value.effect
        principals  = [rules.value.principal]

        operation {
          permissions = ["iap.googleapis.com/resources.egressViaIAP"]
        }

        conditions {
          service    = "iap.googleapis.com"
          expression = rules.value.expression
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = length(local.agent_tool_rules) > 0 && length(local.agent_tool_rules) <= 10 && alltrue([for r in values(local.agent_tool_rules) : length(r.expression) > 0 && length(r.expression) <= 1024])
      error_message = "agent_tool_edges must have 1..10 FGAC rules, each non-empty and at most 1024 characters."
    }
    precondition {
      condition     = alltrue([for name in ["cti_researcher", "threat_hunter", "detection_engineer", "tier2_responder"] : local.agent_identity_ok[name]])
      error_message = join(" ", [for name in ["cti_researcher", "threat_hunter", "detection_engineer", "tier2_responder"] : local.agent_identity_error[name] if !local.agent_identity_ok[name]])
    }
  }
}

resource "google_iam_projects_policy_binding" "agent_tool_edges" {
  provider          = google-beta
  project           = var.project_id
  location          = "global"
  policy_binding_id = local.agent_tool_policy_binding_id
  policy_kind       = "ACCESS"
  policy            = google_iam_project_access_policy.agent_tool_edges.name

  target {
    resource = "//cloudresourcemanager.googleapis.com/projects/${var.project_id}"
  }

  depends_on = [time_sleep.access_policy_binding_override, terraform_data.agent_tool_edges_policy_binding]
}

resource "terraform_data" "agent_tool_edges_policy_binding" {
  input = {
    project_id = var.project_id
    binding_id = local.agent_tool_policy_binding_id
  }

  triggers_replace = ["google_iam_projects_policy_binding"]

  provisioner "local-exec" {
    when    = destroy
    command = "bash \"${path.module}/../scripts/governance/delete_until_gone.sh\" \"${self.input.project_id}\" \"https://iam.googleapis.com/v3/projects/${self.input.project_id}/locations/global/policyBindings/${self.input.binding_id}\""
  }
}

resource "google_iam_project_access_policy" "agent_a2a_edges" {
  count = local.a2a_policies_enabled ? 1 : 0

  provider         = google-beta
  project          = var.project_id
  location         = "global"
  access_policy_id = local.agent_a2a_access_policy_id
  display_name     = "SecOps SOC Orchestrator to specialist A2A edges"

  details {
    dynamic "rules" {
      for_each = local.agent_a2a_rules
      content {
        description = rules.value.description
        effect      = rules.value.effect
        principals  = [rules.value.principal]

        operation {
          permissions = ["iap.googleapis.com/resources.egressViaIAP"]
        }

        conditions {
          service    = "iap.googleapis.com"
          expression = rules.value.expression
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = length(local.agent_a2a_rules) > 0 && length(local.agent_a2a_rules) <= 10 && alltrue([for r in values(local.agent_a2a_rules) : length(r.expression) > 0 && length(r.expression) <= 1024])
      error_message = "agent_a2a_edges must have 1..10 FGAC rules, each non-empty and at most 1024 characters."
    }
    precondition {
      condition     = local.agent_identity_ok["soc_orchestrator"]
      error_message = local.agent_identity_error["soc_orchestrator"]
    }
  }
}

resource "google_iam_projects_policy_binding" "agent_a2a_edges" {
  count = local.a2a_policies_enabled ? 1 : 0

  provider          = google-beta
  project           = var.project_id
  location          = "global"
  policy_binding_id = local.agent_a2a_policy_binding_id
  policy_kind       = "ACCESS"
  policy            = google_iam_project_access_policy.agent_a2a_edges[0].name

  target {
    resource = "//cloudresourcemanager.googleapis.com/projects/${var.project_id}"
  }

  depends_on = [time_sleep.access_policy_binding_override, terraform_data.agent_a2a_edges_policy_binding]
}

resource "terraform_data" "agent_a2a_edges_policy_binding" {
  count = local.a2a_policies_enabled ? 1 : 0

  input = {
    project_id = var.project_id
    binding_id = local.agent_a2a_policy_binding_id
  }

  triggers_replace = ["google_iam_projects_policy_binding"]

  provisioner "local-exec" {
    when    = destroy
    command = "bash \"${path.module}/../scripts/governance/delete_until_gone.sh\" \"${self.input.project_id}\" \"https://iam.googleapis.com/v3/projects/${self.input.project_id}/locations/global/policyBindings/${self.input.binding_id}\""
  }
}
