# Optional Gemini Enterprise prompt/response audit logging (`var.ge_prompt_logging`,
# gated on `var.bind_ge_app` so shared apps are untouched by default).

locals {
  ge_observability_script   = "${path.module}/../scripts/governance/ge_observability.sh"
  ge_prompt_logging_enabled = var.bind_ge_app && var.ge_prompt_logging
}

resource "terraform_data" "ge_observability" {
  count = local.ge_prompt_logging_enabled ? 1 : 0

  input = {
    project_id     = var.project_id
    project_number = local.project_number
    location       = var.ge_location
    collection_id  = var.ge_collection_id
    engine_id      = var.ge_engine_id
    script         = local.ge_observability_script
  }

  triggers_replace = [
    var.ge_engine_id,
    var.ge_location,
    var.ge_collection_id,
  ]

  lifecycle {
    precondition {
      condition     = trimspace(var.ge_engine_id) != ""
      error_message = "var.ge_engine_id is empty. Set it to the Gemini Enterprise app ID."
    }
  }

  provisioner "local-exec" {
    command = "bash \"${local.ge_observability_script}\" enable"

    environment = {
      GE_PROJECT_ID     = var.project_id
      GE_PROJECT_NUMBER = local.project_number
      GE_LOCATION       = var.ge_location
      GE_COLLECTION_ID  = var.ge_collection_id
      GE_ENGINE_ID      = var.ge_engine_id
    }
  }

  provisioner "local-exec" {
    when       = destroy
    on_failure = continue
    command    = "bash \"${self.input.script}\" disable"

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
    terraform_data.ge_binding,
  ]
}
