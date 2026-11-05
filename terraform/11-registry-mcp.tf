# Registers the remote Google SecOps Chronicle OneMCP server (`JSONRPC`) in
# Agent Registry so Agent Gateway inspects JSON-RPC bodies and exposes
# `destination.agent_registry.mcp_server.tool.name` and `.method` to IAM v3 CEL
# policies.

resource "google_agent_registry_service" "chronicle_mcp" {
  provider     = google-beta
  project      = var.project_id
  location     = var.region
  service_id   = "${var.resource_prefix}-chronicle-mcp"
  display_name = "Google SecOps Chronicle MCP"
  description  = "Hosted Google SecOps Chronicle MCP server with per-agent IAM v3 CEL tool allowlists."

  interfaces {
    url              = "https://chronicle.${var.chronicle_region}.rep.googleapis.com/mcp"
    protocol_binding = "JSONRPC"
  }

  mcp_server_spec {
    type = "NO_SPEC"
  }

  depends_on = [google_project_service.apis]
}

locals {
  chronicle_mcp_server_id = basename(google_agent_registry_service.chronicle_mcp.registry_resource)
}
