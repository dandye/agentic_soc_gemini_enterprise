# Cyber-tuned Model Armor inline `CONTENT_AUTHZ` extension and policy on the
# egress Agent Gateway.
#
# Screens JSON and text bodies for prompt injection, jailbreak attempts, and
# Responsible AI violations at `HIGH` confidence so legitimate SOC indicators
# (LOLBins, YARA-L 2.0 snippets, hashes, IPs) pass cleanly while adversarial
# prompt-injection payloads embedded in alerts or logs are blocked.
# Note: `malicious_uri_filter_settings` defaults to disabled
# (`var.model_armor_enable_malicious_uri_filter = false`) because SOC analysts
# routinely submit suspected phishing and C2 URLs for threat-intelligence triage.

locals {
  model_armor_enabled = var.enable_model_armor

  gateway_service_agent = coalesce(
    var.gateway_service_agent,
    "service-${local.project_number}@gcp-sa-dep.iam.gserviceaccount.com",
  )

  model_armor_request_template  = "${var.resource_prefix}-request"
  model_armor_response_template = "${var.resource_prefix}-response"

  model_armor_blocking  = var.model_armor_enforcement_type == "INSPECT_AND_BLOCK"
  model_armor_fail_open = var.model_armor_fail_open != null ? var.model_armor_fail_open : !local.model_armor_blocking

  model_armor_template_ids = {
    request  = "projects/${var.project_id}/locations/${var.region}/templates/${local.model_armor_request_template}"
    response = "projects/${var.project_id}/locations/${var.region}/templates/${local.model_armor_response_template}"
  }
}

resource "google_model_armor_template" "request" {
  count = local.model_armor_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  location    = var.region
  template_id = local.model_armor_request_template

  labels = {
    managed-by = "terraform"
    stack      = var.resource_prefix
  }

  filter_config {
    pi_and_jailbreak_filter_settings {
      filter_enforcement = "ENABLED"
      confidence_level   = var.model_armor_confidence_level
    }

    dynamic "malicious_uri_filter_settings" {
      for_each = var.model_armor_enable_malicious_uri_filter ? [1] : []
      content {
        filter_enforcement = "ENABLED"
      }
    }

    rai_settings {
      dynamic "rai_filters" {
        for_each = toset(["SEXUALLY_EXPLICIT", "HATE_SPEECH", "HARASSMENT", "DANGEROUS"])
        content {
          filter_type      = rai_filters.value
          confidence_level = var.model_armor_confidence_level
        }
      }
    }
  }

  template_metadata {
    enforcement_type                   = var.model_armor_enforcement_type
    log_sanitize_operations            = true
    log_template_operations            = true
    ignore_partial_invocation_failures = true
  }

  depends_on = [google_project_service.apis]
}

resource "google_model_armor_template" "response" {
  count = local.model_armor_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  location    = var.region
  template_id = local.model_armor_response_template

  labels = {
    managed-by = "terraform"
    stack      = var.resource_prefix
  }

  filter_config {
    dynamic "malicious_uri_filter_settings" {
      for_each = var.model_armor_enable_malicious_uri_filter ? [1] : []
      content {
        filter_enforcement = "ENABLED"
      }
    }

    rai_settings {
      dynamic "rai_filters" {
        for_each = toset(["SEXUALLY_EXPLICIT", "HATE_SPEECH", "HARASSMENT", "DANGEROUS"])
        content {
          filter_type      = rai_filters.value
          confidence_level = var.model_armor_confidence_level
        }
      }
    }
  }

  template_metadata {
    enforcement_type                   = var.model_armor_enforcement_type
    log_sanitize_operations            = true
    log_template_operations            = true
    ignore_partial_invocation_failures = true
  }

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "model_armor_callout_user" {
  count = local.model_armor_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  role     = "roles/modelarmor.calloutUser"
  member   = "serviceAccount:${local.gateway_service_agent}"

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "model_armor_service_usage" {
  count = local.model_armor_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  role     = "roles/serviceusage.serviceUsageConsumer"
  member   = "serviceAccount:${local.gateway_service_agent}"

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "model_armor_user" {
  count = local.model_armor_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  role     = "roles/modelarmor.user"
  member   = "serviceAccount:${local.gateway_service_agent}"

  depends_on = [google_project_service.apis]
}

resource "google_network_services_authz_extension" "model_armor" {
  count = local.model_armor_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  name        = "${var.resource_prefix}-ma-content-authz"
  location    = var.region
  description = "Cyber-tuned Model Armor callout for the egress Agent Gateway."

  labels = {
    managed-by = "terraform"
    stack      = var.resource_prefix
  }

  service   = "modelarmor.${var.region}.rep.googleapis.com"
  timeout   = var.model_armor_timeout
  fail_open = local.model_armor_fail_open

  metadata = {
    model_armor_settings = jsonencode([
      {
        request_template_id  = local.model_armor_template_ids.request
        response_template_id = local.model_armor_template_ids.response
      }
    ])
  }

  depends_on = [
    google_project_service.apis,
    google_model_armor_template.request,
    google_model_armor_template.response,
    google_project_iam_member.model_armor_callout_user,
    google_project_iam_member.model_armor_service_usage,
    google_project_iam_member.model_armor_user,
  ]
}

resource "google_network_security_authz_policy" "content_authz" {
  count = local.model_armor_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  name        = "${var.resource_prefix}-ma-content-authz"
  location    = var.region
  description = "Routes JSON and text traffic through the egress Agent Gateway to Model Armor."

  labels = {
    managed-by = "terraform"
    stack      = var.resource_prefix
  }

  policy_profile = "CONTENT_AUTHZ"
  action         = "CUSTOM"

  target {
    resources = [local.agent_gateway_name]
  }

  custom_provider {
    authz_extension {
      resources = [one(google_network_services_authz_extension.model_armor[*].id)]
    }
  }

  http_rules {
    to {
      operations {
        paths {
          prefix = "/"
        }
      }
    }

    when = "request.headers['content-type'] == 'application/json' || request.headers['content-type'].startsWith('text/')"
  }

  depends_on = [google_network_security_authz_policy.request_authz]
}
