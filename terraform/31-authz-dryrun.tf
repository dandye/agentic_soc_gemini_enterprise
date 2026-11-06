# IAP REQUEST_AUTHZ callout extension and policy on the egress Agent Gateway.
# Evaluates IAM v3 Unified Access Policies (`iapPolicyVersion = "V2"`) on every
# outbound request from any governed agent.

locals {
  dry_run         = var.authz_enforcement_mode == "DRY_RUN"
  authz_fail_open = var.authz_fail_open != null ? var.authz_fail_open : local.dry_run
}

resource "google_network_services_authz_extension" "iap" {
  provider    = google-beta
  project     = var.project_id
  name        = "${var.resource_prefix}-iap-authz"
  location    = var.region
  description = "IAP callout extension evaluating IAM v3 Unified Access Policies on every outbound gateway request."

  labels = {
    managed-by = "terraform"
    stack      = var.resource_prefix
  }

  service   = "iap.googleapis.com"
  timeout   = "1s"
  fail_open = local.authz_fail_open

  metadata = merge(
    { iapPolicyVersion = "V2" },
    local.dry_run ? { iamEnforcementMode = "DRY_RUN" } : {},
  )

  depends_on = [google_project_service.apis]
}

resource "google_network_security_authz_policy" "request_authz" {
  provider    = google-beta
  project     = var.project_id
  name        = "${var.resource_prefix}-request-authz"
  location    = var.region
  description = "Delegates every outbound gateway request to IAP for SPIFFE identity and per-tool CEL evaluation."

  labels = {
    managed-by = "terraform"
    stack      = var.resource_prefix
  }

  policy_profile = "REQUEST_AUTHZ"
  action         = "CUSTOM"

  target {
    resources = [local.agent_gateway_name]
  }

  custom_provider {
    authz_extension {
      resources = [google_network_services_authz_extension.iap.id]
    }
  }
}
