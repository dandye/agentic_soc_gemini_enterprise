# Cloud Monitoring dashboard ("SecOps Governance") and five log-based metrics
# unifying Gemini Enterprise prompt logs, Agent Gateway SNI egress verdicts,
# Model Armor content sanitization, IAP per-tool MCP decisions, and Semantic
# Governance policy evaluations onto a single console surface.

locals {
  observability_enabled = var.enable_observability_dashboard

  obs_metric_ids = {
    gateway_requests   = "${var.resource_prefix}/gateway_requests"
    tool_calls_allowed = "${var.resource_prefix}/tool_calls_allowed"
    tool_calls_denied  = "${var.resource_prefix}/tool_calls_denied"
    model_armor        = "${var.resource_prefix}/model_armor_sanitize"
    sgp_verdicts       = "${var.resource_prefix}/sgp_verdicts"
  }

  obs_metric_types = {
    for k, v in local.obs_metric_ids : k => "logging.googleapis.com/user/${v}"
  }

  obs_filter_gateway = join(" AND ", [
    "logName=\"projects/${var.project_id}/logs/networkservices.googleapis.com%2Fgateway_requests\"",
    "jsonPayload.tlsSniHostname:*",
  ])

  obs_filter_tools = join(" AND ", [
    "logName=\"projects/${var.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access\"",
    "protoPayload.methodName=\"GatekeeperAuthorizer.AuthorizeUser\"",
    "protoPayload.metadata.mcp_attributes.mcp_tool_name:*",
  ])

  obs_filter_model_armor = "logName=\"projects/${var.project_id}/logs/modelarmor.googleapis.com%2Fsanitize_operations\""
  obs_filter_sgp         = "logName=\"projects/${var.project_id}/logs/semantic-governance-policy\""

  obs_filter_ge_prompts = join(" AND ", [
    "logName=\"projects/${var.project_id}/logs/discoveryengine.googleapis.com%2Fgemini_enterprise_user_activity\"",
    "jsonPayload.logMetadata.methodName=\"StreamAssist\"",
  ])
}

resource "google_logging_metric" "gateway_requests" {
  count = local.observability_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  name        = local.obs_metric_ids.gateway_requests
  description = "Agent Gateway egress requests by destination host and authorization verdict."
  filter      = local.obs_filter_gateway

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "host"
      value_type  = "STRING"
      description = "TLS SNI hostname"
    }

    labels {
      key         = "result"
      value_type  = "STRING"
      description = "ALLOWED or DENIED"
    }
  }

  label_extractors = {
    host   = "EXTRACT(jsonPayload.tlsSniHostname)"
    result = "EXTRACT(jsonPayload.authzPolicyInfo.result)"
  }
}

resource "google_logging_metric" "tool_calls_allowed" {
  count = local.observability_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  name        = local.obs_metric_ids.tool_calls_allowed
  description = "Chronicle MCP tool calls permitted by IAP CEL policy, by tool and SPIFFE principal."
  filter      = "${local.obs_filter_tools} AND protoPayload.authorizationInfo.granted=true"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "tool"
      value_type  = "STRING"
      description = "MCP tool name"
    }

    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Calling SPIFFE Agent Identity"
    }
  }

  label_extractors = {
    tool      = "EXTRACT(protoPayload.metadata.mcp_attributes.mcp_tool_name)"
    principal = "EXTRACT(protoPayload.authenticationInfo.principalSubject)"
  }
}

resource "google_logging_metric" "tool_calls_denied" {
  count = local.observability_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  name        = local.obs_metric_ids.tool_calls_denied
  description = "Chronicle MCP tool calls denied by IAP CEL policy, by tool and SPIFFE principal."
  filter      = "${local.obs_filter_tools} AND protoPayload.authorizationInfo.granted=false"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "tool"
      value_type  = "STRING"
      description = "MCP tool name"
    }

    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Calling SPIFFE Agent Identity"
    }
  }

  label_extractors = {
    tool      = "EXTRACT(protoPayload.metadata.mcp_attributes.mcp_tool_name)"
    principal = "EXTRACT(protoPayload.authenticationInfo.principalSubject)"
  }
}

resource "google_logging_metric" "model_armor_sanitize" {
  count = local.observability_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  name        = local.obs_metric_ids.model_armor
  description = "Model Armor sanitize operations by match state, direction, template, and filter."
  filter      = local.obs_filter_model_armor

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "match_state"
      value_type  = "STRING"
      description = "MATCH_FOUND or NO_MATCH_FOUND"
    }

    labels {
      key         = "operation"
      value_type  = "STRING"
      description = "SANITIZE_USER_PROMPT or SANITIZE_MODEL_RESPONSE"
    }

    labels {
      key         = "template"
      value_type  = "STRING"
      description = "Model Armor template ID"
    }

    labels {
      key         = "pi_jailbreak"
      value_type  = "STRING"
      description = "Prompt injection and jailbreak filter"
    }

    labels {
      key         = "dangerous"
      value_type  = "STRING"
      description = "Responsible AI dangerous content"
    }

    labels {
      key         = "sexually_explicit"
      value_type  = "STRING"
      description = "Responsible AI sexually explicit"
    }

    labels {
      key         = "harassment"
      value_type  = "STRING"
      description = "Responsible AI harassment"
    }

    labels {
      key         = "hate_speech"
      value_type  = "STRING"
      description = "Responsible AI hate speech"
    }

    labels {
      key         = "malicious_uris"
      value_type  = "STRING"
      description = "Malicious URI filter"
    }

    labels {
      key         = "csam"
      value_type  = "STRING"
      description = "CSAM filter"
    }
  }

  label_extractors = {
    match_state       = "EXTRACT(jsonPayload.sanitizationResult.filterMatchState)"
    operation         = "EXTRACT(jsonPayload.operationType)"
    template          = "EXTRACT(resource.labels.template_id)"
    pi_jailbreak      = "EXTRACT(jsonPayload.sanitizationResult.filterResults.pi_and_jailbreak.piAndJailbreakFilterResult.matchState)"
    dangerous         = "EXTRACT(jsonPayload.sanitizationResult.filterResults.rai.raiFilterResult.raiFilterTypeResults.dangerous.matchState)"
    sexually_explicit = "EXTRACT(jsonPayload.sanitizationResult.filterResults.rai.raiFilterResult.raiFilterTypeResults.sexually_explicit.matchState)"
    harassment        = "EXTRACT(jsonPayload.sanitizationResult.filterResults.rai.raiFilterResult.raiFilterTypeResults.harassment.matchState)"
    hate_speech       = "EXTRACT(jsonPayload.sanitizationResult.filterResults.rai.raiFilterResult.raiFilterTypeResults.hate_speech.matchState)"
    malicious_uris    = "EXTRACT(jsonPayload.sanitizationResult.filterResults.malicious_uris.maliciousUriFilterResult.matchState)"
    csam              = "EXTRACT(jsonPayload.sanitizationResult.filterResults.csam.csamFilterFilterResult.matchState)"
  }
}

resource "google_logging_metric" "sgp_verdicts" {
  count = local.observability_enabled ? 1 : 0

  provider    = google-beta
  project     = var.project_id
  name        = local.obs_metric_ids.sgp_verdicts
  description = "Semantic Governance top-level verdicts (ALLOW or DENY)."
  filter      = local.obs_filter_sgp

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "verdict"
      value_type  = "STRING"
      description = "ALLOW or DENY"
    }
  }

  label_extractors = {
    verdict = "EXTRACT(jsonPayload.verdict)"
  }
}

resource "google_monitoring_dashboard" "secops_governance" {
  count = local.observability_enabled ? 1 : 0

  provider = google-beta
  project  = var.project_id

  depends_on = [
    google_logging_metric.gateway_requests,
    google_logging_metric.tool_calls_allowed,
    google_logging_metric.tool_calls_denied,
    google_logging_metric.model_armor_sanitize,
    google_logging_metric.sgp_verdicts,
  ]

  dashboard_json = jsonencode({
    name        = "projects/${local.project_number}/dashboards/${var.resource_prefix}-secops-governance"
    displayName = "SecOps Governance"

    mosaicLayout = {
      columns = 12
      tiles = [
        {
          width = 12, height = 4
          widget = {
            title = "SecOps Agent Governance: five platform choke-point layers"
            text = {
              format = "MARKDOWN"
              content = join("\n", [
                "**Prompts and Responses** shows user turns from Gemini Enterprise (`StreamAssist`). Below it sit the four enforced platform choke points on the egress Agent Gateway: **Gateway** (default-deny SNI and A2A routing), **Model Armor** (prompt injection and content sanitization), **Chronicle MCP Tools** (per-specialist IAM v3 CEL allowlists), and **Semantic Governance** (Tier-0 Crown Jewel change-control evaluations).",
                "",
                "Charts count traffic recorded after the log-based metrics were created; log panels display historical entries immediately.",
              ])
            }
          }
        },
        {
          yPos = 4, width = 12, height = 1
          widget = {
            title = "Prompts and Responses"
            sectionHeader = {
              subtitle     = "Gemini Enterprise StreamAssist activity log"
              dividerBelow = true
            }
          }
        },
        {
          yPos = 5, width = 12, height = 8
          widget = {
            title = "Gemini Enterprise prompt and response log"
            logsPanel = {
              filter        = local.obs_filter_ge_prompts
              resourceNames = ["projects/${var.project_id}"]
            }
          }
        },
        {
          yPos = 13, width = 12, height = 1
          widget = {
            title = "Gateway"
            sectionHeader = {
              subtitle     = "Outbound Agent Gateway verdicts across LLM, Chronicle MCP, GTI REST, and A2A traffic"
              dividerBelow = true
            }
          }
        },
        {
          yPos = 14, width = 3, height = 4
          widget = {
            title = "Requests denied"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"${local.obs_metric_types.gateway_requests}\" AND metric.label.\"result\"=\"DENIED\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_DELTA"
                    crossSeriesReducer = "REDUCE_SUM"
                  }
                }
              }
              sparkChartView = { sparkChartType = "SPARK_LINE" }
            }
          }
        },
        {
          xPos = 3, yPos = 14, width = 5, height = 4
          widget = {
            title = "Verdict over time"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"${local.obs_metric_types.gateway_requests}\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_DELTA"
                      crossSeriesReducer = "REDUCE_SUM"
                      groupByFields      = ["metric.label.\"result\""]
                    }
                  }
                }
                plotType       = "STACKED_BAR"
                targetAxis     = "Y1"
                legendTemplate = "$${metric.labels.result}"
              }]
              yAxis        = { label = "requests", scale = "LINEAR" }
              chartOptions = { mode = "COLOR" }
            }
          }
        },
        {
          xPos = 8, yPos = 14, width = 4, height = 4
          widget = {
            title = "Destination host"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"${local.obs_metric_types.gateway_requests}\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_DELTA"
                      crossSeriesReducer = "REDUCE_SUM"
                      groupByFields      = ["metric.label.\"host\""]
                    }
                  }
                }
                plotType       = "STACKED_AREA"
                targetAxis     = "Y1"
                legendTemplate = "$${metric.labels.host}"
              }]
              yAxis        = { label = "requests", scale = "LINEAR" }
              chartOptions = { mode = "COLOR" }
            }
          }
        },
        {
          yPos = 18, width = 12, height = 8
          widget = {
            title = "Gateway request log"
            logsPanel = {
              filter        = local.obs_filter_gateway
              resourceNames = ["projects/${var.project_id}"]
            }
          }
        },
        {
          yPos = 26, width = 12, height = 1
          widget = {
            title = "Model Armor"
            sectionHeader = {
              subtitle     = "Prompt injection, jailbreak, and Responsible AI content screening"
              dividerBelow = true
            }
          }
        },
        {
          yPos = 27, width = 3, height = 4
          widget = {
            title = "Payloads blocked"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = join(" AND ", [
                    "metric.type=\"${local.obs_metric_types.model_armor}\"",
                    "metric.label.\"match_state\"=\"MATCH_FOUND\"",
                  ])
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_DELTA"
                    crossSeriesReducer = "REDUCE_SUM"
                  }
                }
              }
              sparkChartView = { sparkChartType = "SPARK_LINE" }
            }
          }
        },
        {
          xPos = 3, yPos = 27, width = 9, height = 4
          widget = {
            title = "Matched Model Armor filters"
            xyChart = {
              dataSets = [
                for f in [
                  { label = "prompt injection or jailbreak", key = "pi_jailbreak" },
                  { label = "dangerous", key = "dangerous" },
                  { label = "sexually explicit", key = "sexually_explicit" },
                  { label = "harassment", key = "harassment" },
                  { label = "hate speech", key = "hate_speech" },
                  { label = "malicious URI", key = "malicious_uris" },
                  ] : {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.obs_metric_types.model_armor}\" AND metric.label.\"${f.key}\"=\"MATCH_FOUND\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_DELTA"
                        crossSeriesReducer = "REDUCE_SUM"
                        groupByFields      = ["metric.label.\"operation\""]
                      }
                    }
                  }
                  plotType       = "STACKED_BAR"
                  targetAxis     = "Y1"
                  legendTemplate = "${f.label}, $${metric.labels.operation}"
                }
              ]
              yAxis        = { label = "operations", scale = "LINEAR" }
              chartOptions = { mode = "COLOR" }
            }
          }
        },
        {
          yPos = 31, width = 12, height = 8
          widget = {
            title = "Model Armor sanitize log"
            logsPanel = {
              filter        = local.obs_filter_model_armor
              resourceNames = ["projects/${var.project_id}"]
            }
          }
        },
        {
          yPos = 39, width = 12, height = 1
          widget = {
            title = "Chronicle MCP Tools"
            sectionHeader = {
              subtitle     = "Per-specialist IAM v3 CEL tool allowlists evaluated by IAP"
              dividerBelow = true
            }
          }
        },
        {
          yPos = 40, width = 3, height = 4
          widget = {
            title = "Tool calls denied"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"${local.obs_metric_types.tool_calls_denied}\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_DELTA"
                    crossSeriesReducer = "REDUCE_SUM"
                  }
                }
              }
              sparkChartView = { sparkChartType = "SPARK_LINE" }
            }
          }
        },
        {
          xPos = 3, yPos = 40, width = 9, height = 4
          widget = {
            title = "Allowed and denied MCP calls, by tool"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.obs_metric_types.tool_calls_allowed}\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_DELTA"
                        crossSeriesReducer = "REDUCE_SUM"
                        groupByFields      = ["metric.label.\"tool\""]
                      }
                    }
                  }
                  plotType       = "STACKED_BAR"
                  targetAxis     = "Y1"
                  legendTemplate = "allowed $${metric.labels.tool}"
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.obs_metric_types.tool_calls_denied}\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_DELTA"
                        crossSeriesReducer = "REDUCE_SUM"
                        groupByFields      = ["metric.label.\"tool\""]
                      }
                    }
                  }
                  plotType       = "STACKED_BAR"
                  targetAxis     = "Y1"
                  legendTemplate = "denied $${metric.labels.tool}"
                },
              ]
              yAxis        = { label = "tool calls", scale = "LINEAR" }
              chartOptions = { mode = "COLOR" }
            }
          }
        },
        {
          yPos = 44, width = 12, height = 8
          widget = {
            title = "IAP tool authorization log"
            logsPanel = {
              filter        = local.obs_filter_tools
              resourceNames = ["projects/${var.project_id}"]
            }
          }
        },
        {
          yPos = 52, width = 12, height = 1
          widget = {
            title = "Semantic Governance"
            sectionHeader = {
              subtitle     = "Natural-language Tier-0 Crown Jewel change-control and workflow intent evaluations"
              dividerBelow = true
            }
          }
        },
        {
          yPos = 53, width = 3, height = 4
          widget = {
            title = "Judgements"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"${local.obs_metric_types.sgp_verdicts}\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_DELTA"
                    crossSeriesReducer = "REDUCE_SUM"
                  }
                }
              }
              sparkChartView = { sparkChartType = "SPARK_LINE" }
            }
          }
        },
        {
          xPos = 3, yPos = 53, width = 9, height = 4
          widget = {
            title = "Verdicts"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"${local.obs_metric_types.sgp_verdicts}\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_DELTA"
                      crossSeriesReducer = "REDUCE_SUM"
                      groupByFields      = ["metric.label.\"verdict\""]
                    }
                  }
                }
                plotType       = "STACKED_BAR"
                targetAxis     = "Y1"
                legendTemplate = "$${metric.labels.verdict}"
              }]
              yAxis        = { label = "evaluations", scale = "LINEAR" }
              chartOptions = { mode = "COLOR" }
            }
          }
        },
        {
          yPos = 57, width = 12, height = 8
          widget = {
            title = "Semantic Governance policy log"
            logsPanel = {
              filter        = local.obs_filter_sgp
              resourceNames = ["projects/${var.project_id}"]
            }
          }
        },
      ]
    }
  })
}
