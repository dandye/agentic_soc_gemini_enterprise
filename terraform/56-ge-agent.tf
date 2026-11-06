# Optional publication of `soc_orchestrator` into the Gemini Enterprise app's
# agent picker (`var.create_ge_agent`, default `false`). Specialists are never
# published directly into Gemini Enterprise.

locals {
  ge_agent_script          = "${path.module}/../scripts/governance/ge_agent.sh"
  ge_agent_icon_file       = var.ge_agent_icon_path == "" ? "" : "${path.module}/../${var.ge_agent_icon_path}"
  orchestrator_engine_path = "projects/${var.project_id}/locations/${var.region}/reasoningEngines/${google_vertex_ai_reasoning_engine.soc_orchestrator.name}"
}

resource "terraform_data" "ge_agent" {
  count = var.create_ge_agent ? 1 : 0

  input = {
    project_id       = var.project_id
    project_number   = local.project_number
    location         = var.ge_location
    collection_id    = var.ge_collection_id
    engine_id        = var.ge_engine_id
    assistant_id     = var.ge_assistant_id
    reasoning_engine = local.orchestrator_engine_path
    script           = local.ge_agent_script
  }

  triggers_replace = [
    var.ge_engine_id,
    var.ge_location,
    var.ge_collection_id,
    var.ge_assistant_id,
    var.ge_agent_display_name,
    var.ge_agent_sharing_scope,
  ]

  lifecycle {
    precondition {
      condition     = trimspace(var.ge_engine_id) != ""
      error_message = "var.ge_engine_id is empty. Set it to the Gemini Enterprise app ID."
    }
    precondition {
      condition     = var.bind_ge_app
      error_message = "create_ge_agent is true while bind_ge_app is false. Bind the Gemini Enterprise app to the Agent Gateway before publishing the governed orchestrator."
    }
    precondition {
      condition     = local.ge_agent_icon_file == "" || fileexists(local.ge_agent_icon_file)
      error_message = "var.ge_agent_icon_path '${var.ge_agent_icon_path}' does not exist relative to the repository root."
    }
  }

  provisioner "local-exec" {
    command = "bash \"${local.ge_agent_script}\" create"

    environment = {
      GE_PROJECT_ID          = var.project_id
      GE_PROJECT_NUMBER      = local.project_number
      GE_LOCATION            = var.ge_location
      GE_COLLECTION_ID       = var.ge_collection_id
      GE_ENGINE_ID           = var.ge_engine_id
      GE_ASSISTANT_ID        = var.ge_assistant_id
      GE_REASONING_ENGINE    = local.orchestrator_engine_path
      GE_AGENT_DISPLAY_NAME  = var.ge_agent_display_name
      GE_AGENT_SHARING_SCOPE = var.ge_agent_sharing_scope
      GE_AGENT_DESCRIPTION   = google_vertex_ai_reasoning_engine.soc_orchestrator.description
      GE_AGENT_ICON_PATH     = var.ge_agent_icon_path
    }
  }

  provisioner "local-exec" {
    when       = destroy
    on_failure = continue
    command    = "bash \"${self.input.script}\" delete"

    environment = {
      GE_PROJECT_ID       = self.input.project_id
      GE_PROJECT_NUMBER   = self.input.project_number
      GE_LOCATION         = self.input.location
      GE_COLLECTION_ID    = self.input.collection_id
      GE_ENGINE_ID        = self.input.engine_id
      GE_ASSISTANT_ID     = self.input.assistant_id
      GE_REASONING_ENGINE = self.input.reasoning_engine
    }
  }

  depends_on = [
    google_project_service.apis,
    google_vertex_ai_reasoning_engine.soc_orchestrator,
    terraform_data.ge_binding,
    google_project_iam_member.ge_agent_gateway,
  ]
}

resource "terraform_data" "ge_agent_icon" {
  count = var.create_ge_agent ? 1 : 0

  triggers_replace = [
    var.ge_agent_icon_path,
    var.ge_agent_icon_path != "" && fileexists(local.ge_agent_icon_file) ? filesha256(local.ge_agent_icon_file) : "",
    terraform_data.ge_agent[0].id,
    "uri",
  ]

  provisioner "local-exec" {
    on_failure = continue
    command    = "bash \"${local.ge_agent_script}\" icon"

    environment = {
      GE_PROJECT_ID       = var.project_id
      GE_PROJECT_NUMBER   = local.project_number
      GE_LOCATION         = var.ge_location
      GE_COLLECTION_ID    = var.ge_collection_id
      GE_ENGINE_ID        = var.ge_engine_id
      GE_ASSISTANT_ID     = var.ge_assistant_id
      GE_REASONING_ENGINE = local.orchestrator_engine_path
      GE_AGENT_ICON_PATH  = var.ge_agent_icon_path
    }
  }

  depends_on = [terraform_data.ge_agent]
}
