# Five governed SecOps Reasoning Engines deployed from source under
# `identity_type = "AGENT_IDENTITY"`, with all outbound traffic routed through
# the egress Agent Gateway (`local.agent_gateway_name`):
#
#   1. cti_researcher      GTI / VirusTotal v3 enrichment via Auth Manager
#   2. threat_hunter       Read-only Chronicle SIEM MCP hunting
#   3. detection_engineer  YARA-L 2.0 validation, coverage, and rule search
#   4. tier2_responder     Tier-2 case/alert updates, reference lists, and containment
#   5. soc_orchestrator    Zero-tool A2A coordinator + Gemini Enterprise entry point

locals {
  a2a_api_version = "v1beta1"

  a2a_class_methods = [
    "on_message_send",
    "on_get_task",
    "on_list_tasks",
    "on_cancel_task",
    "on_create_task_push_notification_config",
    "on_get_task_push_notification_config",
    "on_list_task_push_notification_configs",
    "on_delete_task_push_notification_config",
    "on_get_extended_agent_card",
  ]

  agent_card_json = {
    for name in local.agent_names :
    name => jsonencode(jsondecode(file("${path.module}/agentcards/${name}.json")))
  }

  query_parameters_schema = {
    type = "object"
    properties = {
      message = {
        anyOf = [
          { type = "string" },
          { type = "object", additionalProperties = true },
        ]
      }
      user_id    = { type = "string" }
      session_id = { type = "string", nullable = true }
      run_config = { type = "object", nullable = true }
    }
    required = ["message", "user_id"]
  }

  stream_class_methods = [
    {
      name        = "stream_query"
      api_mode    = "stream"
      description = null
      parameters  = local.query_parameters_schema
    },
    {
      name        = "async_stream_query"
      api_mode    = "async_stream"
      description = null
      parameters  = local.query_parameters_schema
    },
    {
      name        = "streaming_agent_run_with_events"
      api_mode    = "async_stream"
      description = null
      parameters = {
        type       = "object"
        properties = { request_json = { type = "string" } }
        required   = ["request_json"]
      }
    },
  ]

  agent_a2a_class_methods = {
    for name in local.agent_names : name => [
      for method in local.a2a_class_methods : {
        name        = method
        api_mode    = "a2a_extension"
        description = null
        parameters = {
          type       = "object"
          properties = {}
          required   = ["request", "context"]
        }
        a2a_agent_card = local.agent_card_json[name]
      }
    ]
  }

  agent_class_methods = {
    for name in local.agent_names : name => "[${join(",", concat(
      [for method in local.agent_a2a_class_methods[name] : jsonencode(method)],
      name == "soc_orchestrator" ? [for method in local.stream_class_methods : jsonencode(method)] : [],
    ))}]"
  }

  agent_version = {
    for name in local.agent_names :
    name => jsondecode(file("${path.module}/agentcards/${name}.json")).version
  }

  agent_labels = {
    for name in local.agent_names : name => {
      managed-by = "terraform"
      stack      = var.resource_prefix
      version    = replace(local.agent_version[name], ".", "-")
    }
  }

  agent_framework = "google-adk"

  # Note: GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY stays declared unconditionally
  # because the google-beta provider omits it when flattening state; keeping
  # deployment_spec dirty prevents a spec-only updateMask=spec call from pruning
  # deploymentSpec and clearing agent_gateway_config.
  telemetry_env = merge(
    {
      GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY       = "true"
      OTEL_SEMCONV_STABILITY_OPT_IN                    = "gen_ai_latest_experimental"
      OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED = "true"
    },
    var.trace_capture_message_content ? {
      OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT = "EVENT_ONLY"
    } : {},
  )
}

# 1. CTI Researcher — external GTI / VirusTotal v3 REST enrichment only.
resource "google_vertex_ai_reasoning_engine" "cti_researcher" {
  provider        = google-beta
  project         = var.project_id
  region          = var.region
  display_name    = "${var.resource_prefix}-cti-researcher"
  description     = "CTI Researcher specialist agent. Enriches domains, IPs, and SHA-256 hashes via Google Threat Intelligence (VirusTotal v3) using credentials retrieved from Agent Platform Auth Manager."
  labels          = local.agent_labels["cti_researcher"]
  deletion_policy = "FORCE"

  spec {
    agent_framework = local.agent_framework
    class_methods   = local.agent_class_methods["cti_researcher"]
    identity_type   = "AGENT_IDENTITY"

    source_code_spec {
      inline_source {
        source_archive = local.agent_source_archive["cti_researcher"]
      }
      python_spec {
        entrypoint_module = "agent"
        entrypoint_object = "root_agent"
        requirements_file = "requirements.txt"
        version           = var.python_version
      }
    }

    deployment_spec {
      env {
        name  = "MODEL"
        value = var.specialist_model
      }
      env {
        name  = "MODEL_LOCATION"
        value = var.model_location
      }
      env {
        name  = "GTI_AUTH_PROVIDER"
        value = local.gti_auth_provider_name
      }
      env {
        name  = "GOOGLE_API_USE_CLIENT_CERTIFICATE"
        value = "false"
      }

      dynamic "env" {
        for_each = local.telemetry_env
        content {
          name  = env.key
          value = env.value
        }
      }

      min_instances = var.min_instances
      max_instances = var.max_instances

      agent_gateway_config {
        agent_to_anywhere_config {
          agent_gateway = local.agent_gateway_name
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = local.agent_package_ok["cti_researcher"]
      error_message = local.agent_package_error["cti_researcher"]
    }
  }

  depends_on = [
    google_project_service.apis,
    google_project_service_identity.service_agents,
    terraform_data.package,
    terraform_data.gti_auth_provider,
    google_network_security_authz_policy.request_authz,
    google_iam_project_access_policy.google_apis,
    google_iam_projects_policy_binding.google_apis,
  ]
}

# 2. Threat Hunter — read-only Chronicle SIEM UDM hunting and entity context.
resource "google_vertex_ai_reasoning_engine" "threat_hunter" {
  provider        = google-beta
  project         = var.project_id
  region          = var.region
  display_name    = "${var.resource_prefix}-threat-hunter"
  description     = "Threat Hunter specialist agent. Executes read-only UDM searches, entity summaries, and alert triage against Google SecOps Chronicle MCP."
  labels          = local.agent_labels["threat_hunter"]
  deletion_policy = "FORCE"

  spec {
    agent_framework = local.agent_framework
    class_methods   = local.agent_class_methods["threat_hunter"]
    identity_type   = "AGENT_IDENTITY"

    source_code_spec {
      inline_source {
        source_archive = local.agent_source_archive["threat_hunter"]
      }
      python_spec {
        entrypoint_module = "agent"
        entrypoint_object = "root_agent"
        requirements_file = "requirements.txt"
        version           = var.python_version
      }
    }

    deployment_spec {
      env {
        name  = "MODEL"
        value = var.specialist_model
      }
      env {
        name  = "MODEL_LOCATION"
        value = var.model_location
      }
      env {
        name  = "CHRONICLE_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "CHRONICLE_CUSTOMER_ID"
        value = var.chronicle_customer_id
      }
      env {
        name  = "CHRONICLE_REGION"
        value = var.chronicle_region
      }
      env {
        name  = "GOOGLE_API_USE_CLIENT_CERTIFICATE"
        value = "false"
      }

      dynamic "env" {
        for_each = local.telemetry_env
        content {
          name  = env.key
          value = env.value
        }
      }

      min_instances = var.min_instances
      max_instances = var.max_instances

      agent_gateway_config {
        agent_to_anywhere_config {
          agent_gateway = local.agent_gateway_name
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = local.agent_package_ok["threat_hunter"]
      error_message = local.agent_package_error["threat_hunter"]
    }
  }

  depends_on = [
    google_project_service.apis,
    google_project_service_identity.service_agents,
    terraform_data.package,
    google_network_security_authz_policy.request_authz,
    google_iam_project_access_policy.google_apis,
    google_iam_projects_policy_binding.google_apis,
  ]
}

# 3. Detection Engineer — YARA-L 2.0 rule validation, coverage, and rule search.
resource "google_vertex_ai_reasoning_engine" "detection_engineer" {
  provider        = google-beta
  project         = var.project_id
  region          = var.region
  display_name    = "${var.resource_prefix}-detection-engineer"
  description     = "Detection Engineer specialist agent. Validates YARA-L 2.0 Chronicle SIEM UDM detection rules and evaluates rule coverage without production rule deployment privileges."
  labels          = local.agent_labels["detection_engineer"]
  deletion_policy = "FORCE"

  spec {
    agent_framework = local.agent_framework
    class_methods   = local.agent_class_methods["detection_engineer"]
    identity_type   = "AGENT_IDENTITY"

    source_code_spec {
      inline_source {
        source_archive = local.agent_source_archive["detection_engineer"]
      }
      python_spec {
        entrypoint_module = "agent"
        entrypoint_object = "root_agent"
        requirements_file = "requirements.txt"
        version           = var.python_version
      }
    }

    deployment_spec {
      env {
        name  = "MODEL"
        value = var.specialist_model
      }
      env {
        name  = "MODEL_LOCATION"
        value = var.model_location
      }
      env {
        name  = "CHRONICLE_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "CHRONICLE_CUSTOMER_ID"
        value = var.chronicle_customer_id
      }
      env {
        name  = "CHRONICLE_REGION"
        value = var.chronicle_region
      }
      env {
        name  = "GOOGLE_API_USE_CLIENT_CERTIFICATE"
        value = "false"
      }

      dynamic "env" {
        for_each = local.telemetry_env
        content {
          name  = env.key
          value = env.value
        }
      }

      min_instances = var.min_instances
      max_instances = var.max_instances

      agent_gateway_config {
        agent_to_anywhere_config {
          agent_gateway = local.agent_gateway_name
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = local.agent_package_ok["detection_engineer"]
      error_message = local.agent_package_error["detection_engineer"]
    }
  }

  depends_on = [
    google_project_service.apis,
    google_project_service_identity.service_agents,
    terraform_data.package,
    google_network_security_authz_policy.request_authz,
    google_iam_project_access_policy.google_apis,
    google_iam_projects_policy_binding.google_apis,
  ]
}

# 4. Tier-2 Responder — alert/reference-list updates and governed containment.
resource "google_vertex_ai_reasoning_engine" "tier2_responder" {
  provider        = google-beta
  project         = var.project_id
  region          = var.region
  display_name    = "${var.resource_prefix}-tier2-responder"
  description     = "Tier-2 Incident Responder specialist agent. Updates Chronicle SIEM alerts and IOC reference lists and executes governed host isolation and account containment."
  labels          = local.agent_labels["tier2_responder"]
  deletion_policy = "FORCE"

  spec {
    agent_framework = local.agent_framework
    class_methods   = local.agent_class_methods["tier2_responder"]
    identity_type   = "AGENT_IDENTITY"

    source_code_spec {
      inline_source {
        source_archive = local.agent_source_archive["tier2_responder"]
      }
      python_spec {
        entrypoint_module = "agent"
        entrypoint_object = "root_agent"
        requirements_file = "requirements.txt"
        version           = var.python_version
      }
    }

    deployment_spec {
      env {
        name  = "MODEL"
        value = var.tier2_model
      }
      env {
        name  = "MODEL_LOCATION"
        value = var.model_location
      }
      env {
        name  = "CHRONICLE_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "CHRONICLE_CUSTOMER_ID"
        value = var.chronicle_customer_id
      }
      env {
        name  = "CHRONICLE_REGION"
        value = var.chronicle_region
      }
      env {
        name  = "GOOGLE_API_USE_CLIENT_CERTIFICATE"
        value = "false"
      }

      dynamic "env" {
        for_each = local.telemetry_env
        content {
          name  = env.key
          value = env.value
        }
      }

      min_instances = var.min_instances
      max_instances = var.max_instances

      agent_gateway_config {
        agent_to_anywhere_config {
          agent_gateway = local.agent_gateway_name
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = local.agent_package_ok["tier2_responder"]
      error_message = local.agent_package_error["tier2_responder"]
    }
  }

  depends_on = [
    google_project_service.apis,
    google_project_service_identity.service_agents,
    terraform_data.package,
    google_network_security_authz_policy.request_authz,
    google_iam_project_access_policy.google_apis,
    google_iam_projects_policy_binding.google_apis,
  ]
}

locals {
  specialist_engine_paths = {
    cti_researcher     = "projects/${var.project_id}/locations/${var.region}/reasoningEngines/${google_vertex_ai_reasoning_engine.cti_researcher.name}"
    threat_hunter      = "projects/${var.project_id}/locations/${var.region}/reasoningEngines/${google_vertex_ai_reasoning_engine.threat_hunter.name}"
    detection_engineer = "projects/${var.project_id}/locations/${var.region}/reasoningEngines/${google_vertex_ai_reasoning_engine.detection_engineer.name}"
    tier2_responder    = "projects/${var.project_id}/locations/${var.region}/reasoningEngines/${google_vertex_ai_reasoning_engine.tier2_responder.name}"
  }

  specialist_a2a_urls = {
    for name, path in local.specialist_engine_paths :
    name => "https://${var.region}-aiplatform.googleapis.com/${local.a2a_api_version}/${path}/a2a"
  }
}

# 5. SOC Orchestrator — zero-tool A2A coordinator and Gemini Enterprise entry point.
resource "google_vertex_ai_reasoning_engine" "soc_orchestrator" {
  provider        = google-beta
  project         = var.project_id
  region          = var.region
  display_name    = "${var.resource_prefix}-soc-orchestrator"
  description     = "Governed SOC Orchestrator agent. Coordinates Threat Hunter, CTI Researcher, Detection Engineer, and Tier-2 Responder over A2A with zero direct SIEM, SOAR, or external API tools."
  labels          = local.agent_labels["soc_orchestrator"]
  deletion_policy = "FORCE"

  spec {
    agent_framework = local.agent_framework
    class_methods   = local.agent_class_methods["soc_orchestrator"]
    identity_type   = "AGENT_IDENTITY"

    source_code_spec {
      inline_source {
        source_archive = local.agent_source_archive["soc_orchestrator"]
      }
      python_spec {
        entrypoint_module = "agent"
        entrypoint_object = "root_agent"
        requirements_file = "requirements.txt"
        version           = var.python_version
      }
    }

    deployment_spec {
      env {
        name  = "MODEL"
        value = var.orchestrator_model
      }
      env {
        name  = "MODEL_LOCATION"
        value = var.model_location
      }
      env {
        name  = "GOOGLE_API_USE_CLIENT_CERTIFICATE"
        value = "false"
      }
      env {
        name  = "CTI_RESEARCHER_URL"
        value = local.specialist_a2a_urls["cti_researcher"]
      }
      env {
        name  = "THREAT_HUNTER_URL"
        value = local.specialist_a2a_urls["threat_hunter"]
      }
      env {
        name  = "DETECTION_ENGINEER_URL"
        value = local.specialist_a2a_urls["detection_engineer"]
      }
      env {
        name  = "TIER2_RESPONDER_URL"
        value = local.specialist_a2a_urls["tier2_responder"]
      }
      env {
        name  = "MODEL_ARMOR_CONTROL"
        value = "${var.resource_prefix}-ma-content-authz"
      }
      env {
        name  = "DENIED_MCP_TOOLS"
        value = join(",", local.denied_mcp_tools)
      }

      dynamic "env" {
        for_each = local.telemetry_env
        content {
          name  = env.key
          value = env.value
        }
      }

      min_instances = var.min_instances
      max_instances = var.max_instances

      agent_gateway_config {
        agent_to_anywhere_config {
          agent_gateway = local.agent_gateway_name
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = local.agent_package_ok["soc_orchestrator"]
      error_message = local.agent_package_error["soc_orchestrator"]
    }
  }

  depends_on = [
    google_project_service.apis,
    google_project_service_identity.service_agents,
    terraform_data.package,
    google_network_security_authz_policy.request_authz,
    google_iam_project_access_policy.google_apis,
    google_iam_projects_policy_binding.google_apis,
  ]
}

locals {
  agents = {
    cti_researcher     = google_vertex_ai_reasoning_engine.cti_researcher
    threat_hunter      = google_vertex_ai_reasoning_engine.threat_hunter
    detection_engineer = google_vertex_ai_reasoning_engine.detection_engineer
    tier2_responder    = google_vertex_ai_reasoning_engine.tier2_responder
    soc_orchestrator   = google_vertex_ai_reasoning_engine.soc_orchestrator
  }
}

# hashicorp/google-beta omits min_instances = 0 from Create and Update JSON
# payloads because SDKv2 tpgresource.IsEmptyValue treats integer 0 as empty,
# leaving the Reasoning Engine on the service default (minScale = 1 warm
# instance in us-central1) and clearing any previously patched 0 on subsequent
# spec updates. Re-assert spec.deploymentSpec.minInstances via field-masked REST
# PATCH whenever an engine is created, updated in-place, or min_instances changes.
resource "terraform_data" "reasoning_engine_min_instances" {
  for_each = local.agents

  triggers_replace = [
    each.value.name,
    tostring(var.min_instances),
  ]

  lifecycle {
    replace_triggered_by = [
      google_vertex_ai_reasoning_engine.cti_researcher,
      google_vertex_ai_reasoning_engine.threat_hunter,
      google_vertex_ai_reasoning_engine.detection_engineer,
      google_vertex_ai_reasoning_engine.tier2_responder,
      google_vertex_ai_reasoning_engine.soc_orchestrator,
    ]
  }

  provisioner "local-exec" {
    environment = {
      RE_PROJECT_ID       = var.project_id
      RE_REGION           = var.region
      RE_ENGINE_NAME      = each.value.name
      RE_MIN_INSTANCES    = tostring(var.min_instances)
      RE_EXPECTED_GATEWAY = local.agent_gateway_name
    }
    command = "bash ${path.module}/../scripts/governance/reasoning_engine_scaling.sh ensure"
  }
}
