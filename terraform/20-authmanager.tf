# Agent Platform Auth Manager — stores the Google Threat Intelligence
# (VirusTotal v3) API key on `agentidentity.googleapis.com/v1` without writing
# secret material into Terraform state or container environment variables.
# Only `cti_researcher` receives `roles/agentidentity.user` on this AuthProvider.

locals {
  gti_auth_provider_id   = "${var.resource_prefix}-gti-api-key"
  gti_auth_provider_name = "projects/${var.project_id}/locations/${var.region}/authProviders/${local.gti_auth_provider_id}"
  auth_provider_script   = "${path.module}/../scripts/governance/auth_provider.sh"
}

resource "terraform_data" "gti_auth_provider" {
  input = {
    project_id  = var.project_id
    location    = var.region
    provider_id = local.gti_auth_provider_id
    name        = local.gti_auth_provider_name
    script      = local.auth_provider_script
  }

  triggers_replace = [
    local.gti_auth_provider_name,
    var.gti_api_key_version,
    jsonencode(var.gti_auth_provider_workload_ids),
  ]

  lifecycle {
    precondition {
      condition     = can(regex("^[a-z][a-z0-9-]{0,61}[a-z0-9]$", local.gti_auth_provider_id))
      error_message = "Derived auth provider ID '${local.gti_auth_provider_id}' is not valid. Adjust var.resource_prefix."
    }
    precondition {
      condition     = trimspace(var.gti_api_key) != ""
      error_message = "var.gti_api_key is empty. Export TF_VAR_gti_api_key in the shell environment before running Terraform."
    }
  }

  provisioner "local-exec" {
    command = "bash \"${local.auth_provider_script}\" upsert"

    environment = {
      AUTH_PROVIDER_PROJECT      = var.project_id
      AUTH_PROVIDER_LOCATION     = var.region
      AUTH_PROVIDER_ID           = local.gti_auth_provider_id
      AUTH_PROVIDER_DESCRIPTION  = "Google Threat Intelligence (VirusTotal v3) API key retrieved at tool-call time by cti_researcher under its SPIFFE workload identity."
      AUTH_PROVIDER_VERSION      = tostring(var.gti_api_key_version)
      AUTH_PROVIDER_WORKLOAD_IDS = jsonencode(var.gti_auth_provider_workload_ids)
      GTI_API_KEY                = var.gti_api_key
    }
  }

  provisioner "local-exec" {
    when       = destroy
    on_failure = continue
    command    = "bash \"${self.input.script}\" delete"

    environment = {
      AUTH_PROVIDER_PROJECT  = self.input.project_id
      AUTH_PROVIDER_LOCATION = self.input.location
      AUTH_PROVIDER_ID       = self.input.provider_id
    }
  }

  depends_on = [google_project_service.apis]
}

resource "terraform_data" "gti_auth_provider_grant" {
  input = {
    name   = local.gti_auth_provider_name
    member = local.agent_principals["cti_researcher"]
    role   = "roles/agentidentity.user"
  }

  triggers_replace = [
    terraform_data.gti_auth_provider.id,
    local.agent_principals["cti_researcher"],
  ]

  lifecycle {
    precondition {
      condition     = local.agent_identity_ok["cti_researcher"]
      error_message = local.agent_identity_error["cti_researcher"]
    }
  }

  provisioner "local-exec" {
    command = "bash \"${local.auth_provider_script}\" grant"

    environment = {
      AUTH_PROVIDER_PROJECT  = var.project_id
      AUTH_PROVIDER_LOCATION = var.region
      AUTH_PROVIDER_ID       = local.gti_auth_provider_id
      AUTH_PROVIDER_MEMBER   = local.agent_principals["cti_researcher"]
      AUTH_PROVIDER_ROLE     = "roles/agentidentity.user"
    }
  }

  depends_on = [
    terraform_data.gti_auth_provider,
    google_vertex_ai_reasoning_engine.cti_researcher,
  ]
}
