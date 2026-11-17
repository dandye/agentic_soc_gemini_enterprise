# Dedicated IAM v3 Unified Access Policy for Wizard_Agent's Wiz Remote MCP tools.
#
# Isolating Wiz MCP tool rules into `${var.resource_prefix}-wiz-tools` keeps
# `agw-secops-agent-tools` comfortably below IAM v3's 10-rule-per-policy ceiling
# while chunking `var.wiz_mcp_allowed_tools` at <= 9 tools per CEL `in [...]`
# list literal (`tools/list` attached to chunk 0).

locals {
  wiz_tools_access_policy_id  = "${var.resource_prefix}-wiz-tools"
  wiz_tools_policy_binding_id = "${var.resource_prefix}-wiz-tools-binding"

  wiz_mcp_server_name = var.enable_wiz_mcp ? "projects/${var.project_id}/locations/${var.region}/mcpServers/${local.wiz_mcp_server_id}" : ""

  wiz_mcp_chunks = var.enable_wiz_mcp ? chunklist(var.wiz_mcp_allowed_tools, local.mcp_tools_per_rule) : []

  wiz_mcp_cels = [
    for idx, chunk in local.wiz_mcp_chunks : (
      idx == 0
      ? "destination.agent_registry.mcp_server.name == '${local.wiz_mcp_server_name}' && (destination.agent_registry.mcp_server.tool.name in [${join(", ", [for t in chunk : "'${t}'"])}] || destination.agent_registry.mcp_server.method == 'tools/list')"
      : "destination.agent_registry.mcp_server.name == '${local.wiz_mcp_server_name}' && destination.agent_registry.mcp_server.tool.name in [${join(", ", [for t in chunk : "'${t}'"])}]"
    )
  ]

  wiz_mcp_rules = var.enable_wiz_mcp ? (
    var.chronicle_enforce_tool_allowlist ? {
      for idx, expr in local.wiz_mcp_cels :
      "wizard_agent_wiz_mcp_${idx + 1}" => {
        description = "Wizard Agent -> Wiz Remote MCP allowlist (part ${idx + 1} of ${length(local.wiz_mcp_cels)}${idx == 0 ? ", plus tools/list" : ""})"
        effect      = "ALLOW"
        principal   = local.agent_principals["wizard_agent"]
        expression  = expr
      }
      } : {
      wizard_agent_wiz_mcp_all = {
        description = "Wizard Agent -> Wiz Remote MCP (all tools diagnostic)"
        effect      = "ALLOW"
        principal   = local.agent_principals["wizard_agent"]
        expression  = "destination.agent_registry.mcp_server.name == '${local.wiz_mcp_server_name}'"
      }
    }
  ) : {}
}

resource "google_iam_project_access_policy" "wiz_tools" {
  count = var.enable_wiz_mcp ? 1 : 0

  provider         = google-beta
  project          = var.project_id
  location         = "global"
  access_policy_id = local.wiz_tools_access_policy_id
  display_name     = "SecOps Wizard Agent Wiz Remote MCP tool allowlist"

  details {
    dynamic "rules" {
      for_each = local.wiz_mcp_rules
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
      condition     = length(local.wiz_mcp_rules) > 0 && length(local.wiz_mcp_rules) <= 10 && alltrue([for r in values(local.wiz_mcp_rules) : length(r.expression) > 0 && length(r.expression) <= 1024])
      error_message = "wiz_tools must have 1..10 FGAC rules, each non-empty and at most 1024 characters."
    }
    precondition {
      condition     = local.agent_identity_ok["wizard_agent"]
      error_message = local.agent_identity_error["wizard_agent"]
    }
  }
}

resource "google_iam_projects_policy_binding" "wiz_tools" {
  count = var.enable_wiz_mcp ? 1 : 0

  provider          = google-beta
  project           = var.project_id
  location          = "global"
  policy_binding_id = local.wiz_tools_policy_binding_id
  policy_kind       = "ACCESS"
  policy            = google_iam_project_access_policy.wiz_tools[0].name

  target {
    resource = "//cloudresourcemanager.googleapis.com/projects/${var.project_id}"
  }

  depends_on = [time_sleep.access_policy_binding_override, terraform_data.wiz_tools_policy_binding]
}

resource "terraform_data" "wiz_tools_policy_binding" {
  count = var.enable_wiz_mcp ? 1 : 0

  input = {
    project_id = var.project_id
    binding_id = local.wiz_tools_policy_binding_id
  }

  triggers_replace = ["google_iam_projects_policy_binding"]

  provisioner "local-exec" {
    when    = destroy
    command = "bash \"${path.module}/../scripts/governance/delete_until_gone.sh\" \"${self.input.project_id}\" \"https://iam.googleapis.com/v3/projects/${self.input.project_id}/locations/global/policyBindings/${self.input.binding_id}\""
  }
}
