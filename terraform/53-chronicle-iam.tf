# Least-privilege Google SecOps Chronicle and OneMCP IAM bindings per SPIFFE
# workload identity:
#
#   * All project agent identities -> roles/agentregistry.viewer + roles/agentidentity.viewer
#   * threat_hunter                -> roles/mcp.toolUser + roles/chronicle.viewer
#   * detection_engineer           -> roles/mcp.toolUser + roles/chronicle.viewer
#   * tier2_responder              -> roles/mcp.toolUser + roles/chronicle.editor
#   * cti_researcher               -> ZERO Chronicle or MCP IAM roles
#   * soc_orchestrator             -> ZERO Chronicle or MCP IAM roles

locals {
  chronicle_iam_bindings = {
    "threat_hunter:mcp" = {
      agent = "threat_hunter"
      role  = "roles/mcp.toolUser"
    }
    "threat_hunter:chronicle" = {
      agent = "threat_hunter"
      role  = "roles/chronicle.viewer"
    }
    "detection_engineer:mcp" = {
      agent = "detection_engineer"
      role  = "roles/mcp.toolUser"
    }
    "detection_engineer:chronicle" = {
      agent = "detection_engineer"
      role  = "roles/chronicle.viewer"
    }
    "tier2_responder:mcp" = {
      agent = "tier2_responder"
      role  = "roles/mcp.toolUser"
    }
    "tier2_responder:chronicle" = {
      agent = "tier2_responder"
      role  = "roles/chronicle.editor"
    }
  }
}

resource "google_project_iam_member" "agent_workload_registry_viewer" {
  provider = google-beta
  project  = var.project_id
  role     = "roles/agentregistry.viewer"
  member   = local.all_agent_identities

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "agent_workload_identity_viewer" {
  provider = google-beta
  project  = var.project_id
  role     = "roles/agentidentity.viewer"
  member   = local.all_agent_identities

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "specialist_chronicle_access" {
  for_each = local.chronicle_iam_bindings

  provider = google-beta
  project  = var.project_id
  role     = each.value.role
  member   = local.agent_principals[each.value.agent]

  lifecycle {
    precondition {
      condition     = local.agent_identity_ok[each.value.agent]
      error_message = local.agent_identity_error[each.value.agent]
    }
  }
}
