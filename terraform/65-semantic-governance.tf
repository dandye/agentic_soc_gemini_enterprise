# Vertex AI Semantic Governance Policy Engine, private PSC VPC + Cloud DNS,
# inline `CONTENT_AUTHZ` gateway callout, and built-in Tier-0 Crown Jewel
# Change-Control policy attached to `tier2_responder`.

locals {
  sgp_enabled     = var.enable_semantic_governance
  sgp_gateway_key = var.resource_prefix
  sgp_host        = "${var.region}.${var.sgp_dns_zone_suffix}"
  sgp_dns_name    = "${var.sgp_dns_zone_suffix}."
  sgp_dry_run     = var.sgp_enforcement_mode == "DRY_RUN"

  aiplatform_service_agent = "service-${local.project_number}@gcp-sa-aiplatform.iam.gserviceaccount.com"

  sgp_tier2_agent = local.a2a_policies_enabled ? "projects/${var.project_id}/locations/${var.region}/agents/${data.google_agent_registry_agent.tier2_responder[0].agent_id}" : null

  sgp_tier2_crown_jewel_constraint = replace(trimspace(var.sgp_tier2_crown_jewel_constraint), "/\\s+/", " ")

  sgp_tier2_crown_jewel_enabled = local.sgp_enabled && local.a2a_policies_enabled && local.sgp_tier2_crown_jewel_constraint != ""

  sgp_tier2_crown_jewel_display_name = "Tier-2 Responder - Tier-0 Crown Jewel Change Control"

  sgp_builtin_policies = local.sgp_tier2_crown_jewel_enabled ? [
    {
      id                          = "${var.resource_prefix}-tier2-crown-jewel-change-control"
      display_name                = local.sgp_tier2_crown_jewel_display_name
      description                 = "Blocks Tier-0 Domain Controller isolation and privileged admin account disablement unless an approved CHG-* emergency change ticket is cited."
      agent                       = local.sgp_tier2_agent
      natural_language_constraint = local.sgp_tier2_crown_jewel_constraint
      denial_message              = trimspace(var.sgp_tier2_crown_jewel_denial_message) == "" ? null : trimspace(var.sgp_tier2_crown_jewel_denial_message)
      mcp_tools                   = []
    }
  ] : []

  sgp_user_policies = [
    for p in var.sgp_policies : {
      id                          = p.id
      display_name                = coalesce(p.display_name, p.id)
      description                 = coalesce(p.description, "")
      agent                       = p.agent
      natural_language_constraint = p.natural_language_constraint
      denial_message              = null
      mcp_tools = [
        for t in p.mcp_tools : {
          mcp_server = t.mcp_server
          tools      = t.tools
        }
      ]
    }
  ]

  sgp_all_policies          = concat(local.sgp_builtin_policies, local.sgp_user_policies)
  sgp_gateway_config_script = "${path.module}/../scripts/governance/sgp_gateway_config.sh"
}

resource "google_compute_network" "sgp" {
  count = local.sgp_enabled ? 1 : 0

  provider                = google-beta
  project                 = var.project_id
  name                    = "${var.resource_prefix}-sgp"
  description             = "Dedicated VPC hosting the Semantic Governance PSC endpoint and Agent Gateway PSC attachment."
  auto_create_subnetworks = false

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "sgp" {
  count = local.sgp_enabled ? 1 : 0

  provider                 = google-beta
  project                  = var.project_id
  name                     = "${var.resource_prefix}-sgp"
  region                   = var.region
  network                  = google_compute_network.sgp[0].id
  ip_cidr_range            = var.sgp_subnet_cidr
  purpose                  = "PRIVATE"
  private_ip_google_access = true
}

resource "google_compute_network_attachment" "sgp" {
  count = local.sgp_enabled ? 1 : 0

  provider              = google-beta
  project               = var.project_id
  name                  = "${var.resource_prefix}-sgp"
  region                = var.region
  description           = "PSC interface attachment connecting the egress Agent Gateway to the Semantic Governance VPC."
  connection_preference = "ACCEPT_AUTOMATIC"
  subnetworks           = [google_compute_subnetwork.sgp[0].id]
}

resource "google_dns_managed_zone" "sgp" {
  count = local.sgp_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  name        = "${var.resource_prefix}-sgp"
  dns_name    = local.sgp_dns_name
  description = "Private Cloud DNS zone resolving ${local.sgp_host} to the Semantic Governance PSC forwarding rule."

  labels = {
    managed-by = "terraform"
    stack      = var.resource_prefix
  }

  visibility = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.sgp[0].id
    }
  }

  force_destroy = true

  depends_on = [google_project_service.apis]
}

resource "google_vertex_ai_semantic_governance_policy_engine" "sgp" {
  count = local.sgp_enabled ? 1 : 0

  provider = google-beta

  timeouts {
    create = "60m"
    delete = "60m"
  }

  lifecycle {
    ignore_changes = [gateway_configs]
  }

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "sgp_network_admin" {
  count = local.sgp_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  role     = "roles/compute.networkAdmin"
  member   = "serviceAccount:${local.aiplatform_service_agent}"

  depends_on = [
    google_project_service.apis,
    google_project_service_identity.service_agents,
  ]
}

resource "google_project_iam_member" "sgp_dns_admin" {
  count = local.sgp_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  role     = "roles/dns.admin"
  member   = "serviceAccount:${local.aiplatform_service_agent}"

  depends_on = [
    google_project_service.apis,
    google_project_service_identity.service_agents,
  ]
}

resource "google_project_iam_member" "sgp_trace_agent" {
  count = local.sgp_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  role     = "roles/cloudtrace.agent"
  member   = "serviceAccount:${local.aiplatform_service_agent}"

  depends_on = [
    google_project_service.apis,
    google_project_service_identity.service_agents,
  ]
}

resource "terraform_data" "sgp_gateway_config" {
  count = local.sgp_enabled ? 1 : 0

  input = {
    project_id  = var.project_id
    region      = var.region
    gateway_key = local.sgp_gateway_key
    network     = google_compute_network.sgp[0].id
    subnetwork  = google_compute_subnetwork.sgp[0].id
    dns_zone    = var.sgp_dns_zone_suffix
    script      = local.sgp_gateway_config_script
  }

  triggers_replace = [
    local.sgp_gateway_key,
    google_compute_network.sgp[0].id,
    google_compute_subnetwork.sgp[0].id,
    var.sgp_dns_zone_suffix,
  ]

  provisioner "local-exec" {
    command = "bash \"${local.sgp_gateway_config_script}\" attach"

    environment = {
      SGP_PROJECT_ID    = var.project_id
      SGP_REGION        = var.region
      SGP_GATEWAY_KEY   = local.sgp_gateway_key
      SGP_NETWORK       = google_compute_network.sgp[0].id
      SGP_SUBNETWORK    = google_compute_subnetwork.sgp[0].id
      SGP_DNS_ZONE_FQDN = var.sgp_dns_zone_suffix
    }
  }

  provisioner "local-exec" {
    when       = destroy
    on_failure = continue
    command    = "bash \"${self.input.script}\" detach"

    environment = {
      SGP_PROJECT_ID  = self.input.project_id
      SGP_REGION      = self.input.region
      SGP_GATEWAY_KEY = self.input.gateway_key
    }
  }

  depends_on = [
    google_vertex_ai_semantic_governance_policy_engine.sgp,
    google_compute_subnetwork.sgp,
    google_dns_managed_zone.sgp,
    google_project_iam_member.sgp_network_admin,
    google_project_iam_member.sgp_dns_admin,
  ]
}

data "google_compute_forwarding_rule" "sgp_endpoint" {
  count = local.sgp_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id
  region   = var.region
  name     = "sgpe-psce-${local.sgp_gateway_key}"

  depends_on = [terraform_data.sgp_gateway_config]
}

resource "google_dns_record_set" "sgp_endpoint" {
  count = local.sgp_enabled ? 1 : 0

  provider     = google-beta
  project      = var.project_id
  managed_zone = google_dns_managed_zone.sgp[0].name
  name         = "${local.sgp_host}."
  type         = "A"
  ttl          = 300
  rrdatas      = [data.google_compute_forwarding_rule.sgp_endpoint[0].ip_address]
}

resource "google_network_services_authz_extension" "sgp" {
  count = local.sgp_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  name        = "${var.resource_prefix}-sgp-content-authz"
  location    = var.region
  description = "Semantic Governance callout evaluating natural-language SOC policies on model turns."

  labels = {
    managed-by = "terraform"
    stack      = var.resource_prefix
  }

  service   = local.sgp_host
  authority = local.sgp_host
  timeout   = var.sgp_timeout
  fail_open = false
  metadata  = local.sgp_dry_run ? { sgpEnforcementMode = "DRY_RUN" } : {}

  depends_on = [
    google_project_service.apis,
    terraform_data.sgp_gateway_config,
    google_dns_record_set.sgp_endpoint,
  ]
}

resource "google_network_security_authz_policy" "sgp_content_authz" {
  count = local.sgp_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  name        = "${var.resource_prefix}-sgp-content-authz"
  location    = var.region
  description = "Routes non-gRPC generateContent and streamGenerateContent calls to the Semantic Governance policy engine."

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
      resources = [one(google_network_services_authz_extension.sgp[*].id)]
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

    when = "!request.headers['content-type'].startsWith('application/grpc') && (request.path.endsWith(':generateContent') || request.path.endsWith(':streamGenerateContent'))"
  }

  depends_on = [
    google_network_security_authz_policy.request_authz,
    google_network_security_authz_policy.content_authz,
  ]
}

check "sgp_tier2_policy_reachable" {
  assert {
    condition     = !local.sgp_enabled || local.a2a_policies_enabled
    error_message = "enable_semantic_governance is true while enable_agent_registry_policies is false; data.google_agent_registry_agent.tier2_responder cannot resolve."
  }

  assert {
    condition = length(local.sgp_all_policies) == length(distinct([
      for p in local.sgp_all_policies : p.id
    ]))
    error_message = "A policy id in var.sgp_policies collides with '${var.resource_prefix}-tier2-crown-jewel-change-control'."
  }
}

resource "google_vertex_ai_semantic_governance_policy" "sgp" {
  for_each = local.sgp_enabled ? { for p in local.sgp_all_policies : p.id => p } : {}

  provider                      = google-beta
  project                       = var.project_id
  region                        = var.region
  semantic_governance_policy_id = each.key
  display_name                  = each.value.display_name
  description                   = each.value.description
  agent                         = each.value.agent
  natural_language_constraint   = each.value.natural_language_constraint

  dynamic "mcp_tools" {
    for_each = each.value.mcp_tools
    content {
      mcp_server = mcp_tools.value.mcp_server
      tools      = mcp_tools.value.tools
    }
  }

  dynamic "agent_response_customization" {
    for_each = each.value.denial_message == null ? [] : [each.value.denial_message]
    content {
      denial_message = agent_response_customization.value
    }
  }

  depends_on = [
    google_vertex_ai_semantic_governance_policy_engine.sgp,
    terraform_data.sgp_gateway_config,
    terraform_data.sgp_policies,
  ]
}

resource "terraform_data" "sgp_policies" {
  count = local.sgp_enabled && length(local.sgp_all_policies) > 0 ? 1 : 0

  input = {
    project_id = var.project_id
    region     = var.region
    policies   = jsonencode([for p in local.sgp_all_policies : { id = p.id }])
  }

  triggers_replace = ["google_vertex_ai_semantic_governance_policy"]

  provisioner "local-exec" {
    when        = destroy
    interpreter = ["bash", "-c"]
    environment = {
      DG_PROJECT  = self.input.project_id
      DG_REGION   = self.input.region
      DG_POLICIES = self.input.policies
    }
    command = <<-EOT
      urls=$(jq -r --arg project "$DG_PROJECT" --arg region "$DG_REGION" \
        '.[] | "https://" + $region + "-aiplatform.googleapis.com/v1beta1/projects/" + $project + "/locations/" + $region + "/semanticGovernancePolicies/" + .id' \
        <<<"$DG_POLICIES")
      if [[ -n "$urls" ]]; then
        bash "${path.module}/../scripts/governance/delete_until_gone.sh" "$DG_PROJECT" $urls
      fi
    EOT
  }
}
