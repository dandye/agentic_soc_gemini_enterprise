# Input variables for the governed SecOps multi-agent Terraform stack.
# Copy `terraform.tfvars.example` to `terraform.tfvars` (git-ignored) and pass
# `TF_VAR_gti_api_key` via the shell environment.

variable "project_id" {
  description = "Google Cloud project ID hosting the Agent Gateway, Agent Registry, and five SecOps Reasoning Engines."
  type        = string
}

variable "project_number" {
  description = "Optional numeric Google Cloud project number override. Leave null so 01-project.tf reads it automatically."
  type        = string
  default     = null

  validation {
    condition     = var.project_number == null || can(regex("^[0-9]+$", var.project_number))
    error_message = "project_number must be a numeric project number or null."
  }
}

variable "org_id" {
  description = "Numeric Google Cloud organization ID used to construct the SPIFFE trust domain (`agents.global.org-<ORG_ID>.system.id.goog`)."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.org_id))
    error_message = "org_id must be the numeric organization ID."
  }
}

variable "chronicle_customer_id" {
  description = "Google SecOps Chronicle tenant customer UUID."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.chronicle_customer_id))
    error_message = "chronicle_customer_id must be a valid UUID."
  }
}

variable "chronicle_region" {
  description = "Google SecOps Chronicle API and MCP region prefix (for example `us` or `eu`)."
  type        = string
  default     = "us"
}

variable "manage_org_policy_override" {
  description = "Whether Terraform manages the project-level override disabling `iam.managed.disableAccessPolicyBinding`."
  type        = bool
  default     = true
}

variable "region" {
  description = "Google Cloud region hosting the Agent Gateway, Agent Registry, Reasoning Engines, and Model Armor templates."
  type        = string
  default     = "us-central1"
}

variable "resource_prefix" {
  description = "Lowercase prefix applied to every governed resource so multiple stacks can coexist cleanly in one project."
  type        = string
  default     = "agw-secops"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,18}[a-z0-9])?$", var.resource_prefix))
    error_message = "resource_prefix must be lowercase alphanumeric with hyphens, start with a letter, and be at most 20 characters."
  }
}

# Secrets (never persisted to Terraform state)

variable "gti_api_key" {
  description = "Google Threat Intelligence (VirusTotal v3) API key stored in Agent Platform Auth Manager. Pass via `TF_VAR_gti_api_key` in the shell environment, never in a committed file."
  type        = string
  sensitive   = true
  default     = ""
}

variable "gti_api_key_version" {
  description = "Monotonic version counter used to trigger rotation of the GTI API key in Agent Platform Auth Manager."
  type        = number
  default     = 1
}

variable "gti_auth_provider_workload_ids" {
  description = "Optional create-time SPIFFE workload IDs on the GTI AuthProvider. Leave empty; 20-authmanager.tf binds `roles/agentidentity.user` directly to `cti_researcher`."
  type        = list(string)
  default     = []
}

variable "gemini_api_key" {
  description = "Optional Gemini API key stored in Agent Platform Auth Manager for the Gemini Decisions API (`gemini-decision-1`). Pass via `TF_VAR_gemini_api_key` in the shell environment, never in a committed file. When empty, Auth Manager provisioning is skipped and agents fall back to runtime `GEMINI_API_KEY` or disable Decisions API calls."
  type        = string
  sensitive   = true
  default     = ""
}

variable "gemini_api_key_version" {
  description = "Monotonic version counter used to trigger rotation of the Gemini API key in Agent Platform Auth Manager."
  type        = number
  default     = 1
}

variable "gemini_auth_provider_workload_ids" {
  description = "Optional create-time SPIFFE workload IDs on the Gemini AuthProvider. Leave empty; 20-authmanager.tf binds `roles/agentidentity.user` directly to all five governed agents."
  type        = list(string)
  default     = []
}

# Gemini Enterprise integration (opt-in defaults so shared apps remain untouched)

variable "ge_engine_id" {
  description = "ID of an existing Gemini Enterprise app when opting into `bind_ge_app` / `create_ge_agent`."
  type        = string
  default     = ""
}

variable "ge_location" {
  description = "Location of the Gemini Enterprise app (`global`, `us`, or `eu`)."
  type        = string
  default     = "global"
}

variable "ge_collection_id" {
  description = "Collection segment of the Gemini Enterprise app resource name."
  type        = string
  default     = "default_collection"
}

variable "bind_ge_app" {
  description = "Whether to PATCH the Gemini Enterprise app (`var.ge_engine_id`) to route all agent egress through this Agent Gateway. Defaults to false to protect existing shared apps."
  type        = bool
  default     = false
}

variable "ge_prompt_logging" {
  description = "Whether to enable prompt and response logging on the Gemini Enterprise app when `bind_ge_app = true`."
  type        = bool
  default     = false
}

variable "create_ge_agent" {
  description = "Whether to publish `soc_orchestrator` into the Gemini Enterprise app's agent picker (`bind_ge_app` must also be true)."
  type        = bool
  default     = false
}

variable "ge_assistant_id" {
  description = "Assistant ID under the Gemini Enterprise app where `soc_orchestrator` is registered."
  type        = string
  default     = "default_assistant"
}

variable "ge_agent_display_name" {
  description = "Display name of the governed orchestrator in the Gemini Enterprise agent picker."
  type        = string
  default     = "Governed SecOps Orchestrator"
}

variable "ge_agent_icon_path" {
  description = "Optional repository-relative PNG/SVG icon path for the Gemini Enterprise agent picker entry."
  type        = string
  default     = ""
}

variable "ge_agent_sharing_scope" {
  description = "Visibility scope (`ALL_USERS` or `RESTRICTED`) when publishing `soc_orchestrator` into Gemini Enterprise."
  type        = string
  default     = "ALL_USERS"

  validation {
    condition     = contains(["ALL_USERS", "RESTRICTED"], var.ge_agent_sharing_scope)
    error_message = "ge_agent_sharing_scope must be ALL_USERS or RESTRICTED."
  }
}

# Models and runtime

variable "orchestrator_model" {
  description = "Gemini model ID used by `soc_orchestrator`."
  type        = string
  default     = "gemini-4-hydrogen"
}

variable "tier2_model" {
  description = "Gemini model ID used by `tier2_responder`."
  type        = string
  default     = "gemini-4-carbon"
}

variable "specialist_model" {
  description = "Gemini model ID used by `cti_researcher`, `threat_hunter`, and `detection_engineer`."
  type        = string
  default     = "gemini-3.8-flash"
}

variable "model_location" {
  description = "Vertex AI model endpoint location (`global`, `us`, or `eu`) passed via `MODEL_LOCATION`."
  type        = string
  default     = "global"

  validation {
    condition     = contains(["us", "eu", "global"], var.model_location)
    error_message = "model_location must be one of: us, eu, global."
  }
}

variable "python_version" {
  description = "Python runtime version for the five Vertex AI Reasoning Engines."
  type        = string
  default     = "3.12"
}

variable "trace_capture_message_content" {
  description = "Whether to set `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=EVENT_ONLY` on the five Reasoning Engines."
  type        = bool
  default     = true
}

variable "min_instances" {
  description = "Minimum warm container instances per Reasoning Engine (`0` scales idle memory cost to $0/hr with a cold start on first request; `1` keeps one warm instance at ~$24/mo per engine)."
  type        = number
  default     = 1
  nullable    = false

  validation {
    condition     = var.min_instances >= 0 && var.min_instances <= 10 && floor(var.min_instances) == var.min_instances
    error_message = "min_instances must be a whole number between 0 and 10."
  }
}

variable "max_instances" {
  description = "Optional maximum container instances per Reasoning Engine (`null` preserves the Vertex AI platform default of 100)."
  type        = number
  default     = null

  validation {
    condition = var.max_instances == null || (
      var.max_instances >= 1 &&
      var.max_instances <= 1000 &&
      floor(var.max_instances) == var.max_instances &&
      var.max_instances >= var.min_instances
    )
    error_message = "max_instances must be null or a whole number between 1 and 1000 that is >= min_instances."
  }
}

# Agent Registry & IAP CEL policies

variable "extra_google_api_hosts" {
  description = "Additional Google API hostnames to register in Agent Registry and permit for all agents."
  type        = list(string)
  default     = []
}

variable "chronicle_enforce_tool_allowlist" {
  description = "Whether IAP enforces per-specialist Chronicle MCP tool allowlists (`true` in steady state; set `false` only for diagnostics)."
  type        = bool
  default     = true
}

variable "enable_agent_registry_policies" {
  description = "Whether to look up auto-registered specialist agents in Agent Registry and bind A2A + Semantic Governance policies."
  type        = bool
  default     = true
}

variable "agent_registry_filters" {
  description = "Optional per-agent filter overrides for `data.google_agent_registry_agent` lookups."
  type        = map(string)
  default     = {}

  validation {
    condition = length(setsubtract(keys(var.agent_registry_filters), [
      "cti_researcher",
      "threat_hunter",
      "detection_engineer",
      "tier2_responder",
      "soc_orchestrator",
    ])) == 0
    error_message = "agent_registry_filters keys must be among: cti_researcher, threat_hunter, detection_engineer, tier2_responder, soc_orchestrator."
  }
}

variable "authz_enforcement_mode" {
  description = "IAP authorization enforcement mode (`ENFORCED` returns HTTP 403 on denials; `DRY_RUN` logs denials while failing open)."
  type        = string
  default     = "ENFORCED"

  validation {
    condition     = contains(["DRY_RUN", "ENFORCED"], var.authz_enforcement_mode)
    error_message = "authz_enforcement_mode must be DRY_RUN or ENFORCED."
  }
}

variable "authz_fail_open" {
  description = "Optional explicit override for the IAP extension's `fail_open` flag (`null` derives from `authz_enforcement_mode`)."
  type        = bool
  default     = null
}

variable "enable_iap_data_access_logs" {
  description = "Enable `ADMIN_READ` + `DATA_READ` Data Access audit logs on `iap.googleapis.com` so per-tool verdicts and SPIFFE principals are recorded."
  type        = bool
  default     = true
}

variable "enable_modelarmor_data_access_logs" {
  description = "Optional diagnostic Data Access audit logs on `modelarmor.googleapis.com`."
  type        = bool
  default     = false
}

variable "enable_observability_dashboard" {
  description = "Create the five log-based metrics and the SecOps Governance Cloud Monitoring dashboard."
  type        = bool
  default     = true
}

# Model Armor

variable "enable_model_armor" {
  description = "Create cyber-tuned Model Armor templates and attach the `CONTENT_AUTHZ` policy to the Agent Gateway."
  type        = bool
  default     = true
}

variable "model_armor_enforcement_type" {
  description = "Model Armor enforcement mode (`INSPECT_AND_BLOCK` or `INSPECT_ONLY`)."
  type        = string
  default     = "INSPECT_AND_BLOCK"

  validation {
    condition     = contains(["INSPECT_ONLY", "INSPECT_AND_BLOCK"], var.model_armor_enforcement_type)
    error_message = "model_armor_enforcement_type must be INSPECT_ONLY or INSPECT_AND_BLOCK."
  }
}

variable "model_armor_confidence_level" {
  description = "Model Armor filter confidence threshold (`HIGH` avoids false positives on legitimate cyber IOCs, YARA-L 2.0 rules, and LOLBin command lines)."
  type        = string
  default     = "HIGH"

  validation {
    condition     = contains(["LOW_AND_ABOVE", "MEDIUM_AND_ABOVE", "HIGH"], var.model_armor_confidence_level)
    error_message = "model_armor_confidence_level must be LOW_AND_ABOVE, MEDIUM_AND_ABOVE, or HIGH."
  }
}

variable "model_armor_enable_malicious_uri_filter" {
  description = "Whether to enable Model Armor's malicious-URI detector. Disabled by default so SOC analysts can submit suspected phishing and C2 URLs for triage without tripping URI blocks."
  type        = bool
  default     = false
}

variable "model_armor_fail_open" {
  description = "Optional explicit override for the Model Armor extension's `fail_open` flag (`null` derives from `model_armor_enforcement_type`)."
  type        = bool
  default     = null
}

variable "model_armor_timeout" {
  description = "Per-message timeout for the Model Armor callout extension."
  type        = string
  default     = "2s"

  validation {
    condition     = can(regex("^[0-9]+(\\.[0-9]+)?s$", var.model_armor_timeout))
    error_message = "model_armor_timeout must be a duration string in seconds, such as \"2s\"."
  }
}

# Semantic Governance

variable "enable_semantic_governance" {
  description = "Provision the Semantic Governance VPC, private Cloud DNS, policy engine, gateway callout, and Tier-0 Crown Jewel Change-Control policy."
  type        = bool
  default     = true
}

variable "sgp_dns_zone_suffix" {
  description = "Private DNS suffix resolving `{region}.{suffix}` to the Semantic Governance PSC forwarding rule."
  type        = string
  default     = "sgp.agw-secops.internal"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.sgp_dns_zone_suffix))
    error_message = "sgp_dns_zone_suffix must be a lowercase dotted domain with no trailing dot."
  }
}

variable "sgp_subnet_cidr" {
  description = "IPv4 CIDR range for the dedicated Semantic Governance PRIVATE subnet."
  type        = string
  default     = "10.61.0.0/24"

  validation {
    condition     = can(cidrhost(var.sgp_subnet_cidr, 0))
    error_message = "sgp_subnet_cidr must be a valid IPv4 CIDR block."
  }
}

variable "sgp_enforcement_mode" {
  description = "Semantic Governance enforcement mode (`ENFORCED` or `DRY_RUN`)."
  type        = string
  default     = "ENFORCED"

  validation {
    condition     = contains(["DRY_RUN", "ENFORCED"], var.sgp_enforcement_mode)
    error_message = "sgp_enforcement_mode must be DRY_RUN or ENFORCED."
  }
}

variable "sgp_timeout" {
  description = "Timeout for the Semantic Governance callout extension (up to `10s`)."
  type        = string
  default     = "10s"

  validation {
    condition     = can(regex("^[0-9]+(\\.[0-9]+)?s$", var.sgp_timeout))
    error_message = "sgp_timeout must be a duration in seconds, such as \"10s\"."
  }
}

variable "sgp_policies" {
  description = "Optional extra `google_vertex_ai_semantic_governance_policy` definitions on top of the built-in Tier-0 Crown Jewel policy."
  type = list(object({
    id                          = string
    display_name                = optional(string)
    description                 = optional(string)
    agent                       = string
    natural_language_constraint = string
    mcp_tools = optional(list(object({
      mcp_server = string
      tools      = list(string)
    })), [])
  }))
  default = []

  validation {
    condition     = length(var.sgp_policies) == length(distinct([for p in var.sgp_policies : p.id]))
    error_message = "sgp_policies contains duplicate ids."
  }

  validation {
    condition = alltrue([
      for p in var.sgp_policies : can(regex("^[a-z][a-z0-9-]{0,61}[a-z0-9]$", p.id))
    ])
    error_message = "Each sgp_policies id must match ^[a-z][a-z0-9-]{0,61}[a-z0-9]$."
  }

  validation {
    condition = alltrue([
      for p in var.sgp_policies : alltrue([for t in p.mcp_tools : length(t.tools) > 0])
    ])
    error_message = "Each sgp_policies mcp_tools entry must list at least one tool."
  }
}

variable "sgp_tier2_crown_jewel_constraint" {
  description = "Built-in natural-language Semantic Governance constraint attached to `tier2_responder` enforcing emergency change control on Tier-0 Crown Jewel assets."
  type        = string
  default     = <<-EOT
    Do not isolate, quarantine, or approve network containment on Tier-0 Domain
    Controllers (including hostnames starting with DC- or PROD-DC- or Active
    Directory domain controllers), and do not disable or lock out Tier-0
    privileged administrator accounts (including admin@*, krbtgt, or Domain
    Admins), UNLESS the request explicitly cites an approved emergency change
    ticket identifier matching CHG-<digits> (for example CHG-10492). Standard
    Tier-2 user workstations (such as WKSTN-* or LAPTOP-*), non-domain-controller
    member servers, non-privileged user accounts, alert status updates, and
    reference list updates are permitted without a change ticket.
  EOT
}

variable "sgp_tier2_crown_jewel_denial_message" {
  description = "Custom denial message returned when `sgp_tier2_crown_jewel_constraint` blocks a Tier-0 containment action."
  type        = string
  default     = "[POLICY BLOCK] Blocked by AI security policy -- SEMANTIC GOVERNANCE POLICY (Tier-0 Crown Jewel Change Control): Isolating Domain Controllers (DC-*) or disabling privileged admin accounts requires an approved CHG-* emergency change ticket."

  validation {
    condition     = length(var.sgp_tier2_crown_jewel_denial_message) <= 1000
    error_message = "sgp_tier2_crown_jewel_denial_message must be at most 1000 characters."
  }
}

variable "gateway_service_agent" {
  description = "Optional override for the Service Extensions data-plane service account email (`service-<PROJECT_NUMBER>@gcp-sa-dep.iam.gserviceaccount.com`)."
  type        = string
  default     = null

  validation {
    condition     = var.gateway_service_agent == null || can(regex("@[a-z0-9-]+\\.iam\\.gserviceaccount\\.com$", var.gateway_service_agent))
    error_message = "gateway_service_agent must be a valid service account email without `serviceAccount:`."
  }
}
