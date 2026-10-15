"""Unit tests for Phase 3: Custom domain-specific SOC metrics in aqua/custom_metrics.py and aqua/eval_config.yaml."""

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_aqua_eval_config_yaml_registers_all_four_custom_metrics():
    """Verify aqua/eval_config.yaml is valid YAML and registers the 4 custom SOC evaluators."""
    config_path = REPO_ROOT / "aqua" / "eval_config.yaml"
    assert config_path.exists(), "aqua/eval_config.yaml must exist"
    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    custom_metrics = cfg.get("custom_metrics", [])
    metric_names = {m["name"] for m in custom_metrics}
    expected = {
        "timerange_propagation_check",
        "soar_phase2_fallback_check",
        "subagent_context_forwarding_check",
        "design_spec_attribution_check",
    }
    assert expected.issubset(metric_names)


def test_timerange_propagation_check():
    """Verify timerange_propagation_check catches dropped lookback windows and passes preserved ones."""
    from aqua.custom_metrics import timerange_propagation_check

    # Case 1: User asks for last 7 days (168h), tool uses hours_back=168 -> PASS (1.0)
    passing_trace = {
        "user_prompt": "Hunt for suspicious PowerShell executions on wks-finance-04 over the last 7 days.",
        "tool_calls": [
            {
                "name": "search_security_events",
                "args": {
                    "query": 'principal.hostname = "wks-finance-04"',
                    "hours_back": 168,
                },
            }
        ],
    }
    res_pass = timerange_propagation_check(passing_trace)
    assert res_pass["score"] == 1.0
    assert res_pass["passed"] is True

    # Case 2: User asks for last 7 days (168h), tool silently resets to hours_back=24 -> FAIL (0.0)
    failing_trace = {
        "user_prompt": "Hunt for suspicious PowerShell executions on wks-finance-04 over the last 7 days.",
        "tool_calls": [
            {
                "name": "udm_search",
                "args": {
                    "query": 'principal.hostname = "wks-finance-04"',
                    "hours_back": 24,
                },
            }
        ],
    }
    res_fail = timerange_propagation_check(failing_trace)
    assert res_fail["score"] == 0.0
    assert res_fail["passed"] is False
    assert "168" in res_fail["explanation"]

    # Case 3: User asks for last 7 days (168h), tool omits hours_back entirely -> FAIL (0.0)
    omitted_trace = {
        "user_prompt": "Hunt for suspicious PowerShell executions on wks-finance-04 over the last 7 days.",
        "tool_calls": [
            {
                "name": "udm_search",
                "args": {"query": 'principal.hostname = "wks-finance-04"'},
            }
        ],
    }
    res_omitted = timerange_propagation_check(omitted_trace)
    assert res_omitted["score"] == 0.0
    assert res_omitted["passed"] is False

    # Case 4: Chronicle OneMCP ISO-8601 startTime/endTime (24h span vs 168h expected in Turn 2) -> FAIL (0.0)
    multi_turn_iso_trace = {
        "conversation": [
            {"role": "user", "content": "Check Finance hosts over the last 24 hours."},
            {
                "role": "user",
                "content": "Expand the hunt on svc_finance over the past 7 days.",
            },
        ],
        "tool_calls": [
            {
                "turn": 1,
                "name": "delegate_to_threat_hunter",
                "args": {"request": "Hunt Finance hosts over last 24 hours"},
            },
            {
                "turn": 2,
                "name": "udm_search",
                "args": {
                    "query": 'principal.user.userid = "svc_finance"',
                    "startTime": "2026-10-13T23:50:49.521000Z",
                    "endTime": "2026-10-14T23:50:49.521000Z",
                },
            },
        ],
    }
    res_iso = timerange_propagation_check(multi_turn_iso_trace)
    assert res_iso["score"] == 0.0
    assert res_iso["passed"] is False
    assert "hours_back=24 instead of expected hours_back=168" in res_iso["explanation"]
    assert "delegate_to_threat_hunter" not in res_iso["explanation"]


def test_soar_phase2_fallback_check():
    """Verify soar_phase2_fallback_check enforces Siemplify SOAR fallback when native list_cases returns {}."""
    from aqua.custom_metrics import soar_phase2_fallback_check

    # Case 1: list_cases returns {} on secops-demo-env and agent stops without Siemplify fallback -> FAIL (0.0)
    failing_trace = {
        "user_prompt": "List active SOAR cases in secops-demo-env (a13f6726-efed-452e-9008-8fe0d3cb0f75).",
        "tool_calls": [
            {
                "name": "list_cases",
                "args": {"project_id": "secops-demo-env"},
                "response": {},
            }
        ],
        "final_response": "There are currently no active cases in the environment.",
    }
    res_fail = soar_phase2_fallback_check(failing_trace)
    assert res_fail["score"] == 0.0
    assert res_fail["passed"] is False
    assert (
        "Siemplify" in res_fail["explanation"]
        or "/api/1p/external/v1/cases" in res_fail["explanation"]
    )

    # Case 2: list_cases returns {} and agent falls back to Siemplify SOAR endpoint/tool -> PASS (1.0)
    passing_trace = {
        "user_prompt": "List active SOAR cases in secops-demo-env (a13f6726-efed-452e-9008-8fe0d3cb0f75).",
        "tool_calls": [
            {
                "name": "list_cases",
                "args": {"project_id": "secops-demo-env"},
                "response": {},
            },
            {
                "name": "siemplify_list_cases",
                "args": {
                    "endpoint": "https://ytvgh.siemplify-soar.com:443/api/1p/external/v1/cases"
                },
                "response": {"cases": [{"id": 4091, "title": "Ransomware Alert"}]},
            },
        ],
        "final_response": "Found active Case 4091 via Siemplify SOAR fallback.",
    }
    res_pass = soar_phase2_fallback_check(passing_trace)
    assert res_pass["score"] == 1.0
    assert res_pass["passed"] is True


def test_subagent_context_forwarding_check():
    """Verify subagent_context_forwarding_check catches dropped entities across delegate_to_specialist."""
    from aqua.custom_metrics import subagent_context_forwarding_check

    # Case 1: Prior turn discovered IP 185.220.101.42 and host srv-db-prod-01, both forwarded -> PASS
    passing_trace = {
        "prior_entities": ["185.220.101.42", "srv-db-prod-01", "case-4091"],
        "tool_calls": [
            {
                "name": "delegate_to_specialist",
                "args": {
                    "specialist": "tier2",
                    "request": "Investigate lateral movement from 185.220.101.42 on host srv-db-prod-01 for case-4091 over last 48h.",
                },
            }
        ],
    }
    res_pass = subagent_context_forwarding_check(passing_trace)
    assert res_pass["score"] == 1.0
    assert res_pass["passed"] is True

    # Case 2: Delegation drops srv-db-prod-01 and case-4091 -> FAIL
    failing_trace = {
        "prior_entities": ["185.220.101.42", "srv-db-prod-01", "case-4091"],
        "tool_calls": [
            {
                "name": "delegate_to_specialist",
                "args": {
                    "specialist": "tier2",
                    "request": "Investigate lateral movement from 185.220.101.42.",
                },
            }
        ],
    }
    res_fail = subagent_context_forwarding_check(failing_trace)
    assert res_fail["score"] < 1.0
    assert res_fail["passed"] is False
    assert "srv-db-prod-01" in res_fail["explanation"]


def test_design_spec_attribution_check():
    """Verify design_spec_attribution_check validates the mandatory attribution footer and tool honesty."""
    from aqua.custom_metrics import design_spec_attribution_check

    passing_trace = {
        "tool_calls": [
            {"name": "udm_search", "args": {}},
            {"name": "get_ioc_match", "args": {}},
        ],
        "final_response": (
            "Investigation complete. No lateral movement detected.\n\n"
            "*Agent: agent_soc_manager | Model: gemini-3.1-pro-preview | Tools: udm_search, get_ioc_match*"
        ),
    }
    res_pass = design_spec_attribution_check(passing_trace)
    assert res_pass["score"] == 1.0
    assert res_pass["passed"] is True

    missing_footer_trace = {
        "tool_calls": [{"name": "udm_search", "args": {}}],
        "final_response": "Investigation complete. No lateral movement detected.",
    }
    res_missing = design_spec_attribution_check(missing_footer_trace)
    assert res_missing["score"] == 0.0
    assert res_missing["passed"] is False


def test_unified_evaluate_entrypoint():
    """Verify evaluate(trace_info) entrypoint runs single or all 4 custom SOC evaluators."""
    from aqua.custom_metrics import evaluate

    trace = {
        "user_prompt": "Check wks-fin-01 over the last 24 hours.",
        "tool_calls": [
            {"name": "udm_search", "args": {"query": "wks-fin-01", "hours_back": 24}}
        ],
        "final_response": (
            "No suspicious events.\n\n"
            "*Agent: agent_soc_manager | Model: gemini-3.1-pro-preview | Tools: udm_search*"
        ),
    }
    suite_res = evaluate(trace)
    assert suite_res["passed"] is True
    assert suite_res["score"] == 1.0
    assert "timerange_propagation_check" in suite_res["metrics"]


def test_normalize_trace_info_parses_vertex_adk_cloud_trace_spans():
    """Verify _normalize_trace_info extracts tool_calls, conversation, and otel_summary from Vertex ADK Cloud Trace spans."""
    import json
    from aqua.custom_metrics import _normalize_trace_info, evaluate

    raw_cloud_trace_record = {
        "session_id": "1777790627145056256",
        "spans": [
            {
                "name": "invoke_agent SecurityOperationsManager",
                "trace_id": "6caf20bca2bb410fc7a7966455c94027",
                "span_id": "span-root",
                "attributes": {
                    "gen_ai.conversation.id": "1777790627145056256",
                    "service.name": "adk-soc-manager",
                },
            },
            {
                "name": "call_llm",
                "trace_id": "6caf20bca2bb410fc7a7966455c94027",
                "span_id": "span-llm-1",
                "attributes": {
                    "gcp.vertex.agent.session_id": "1777790627145056256",
                    "gen_ai.request.model": "gemini-3.1-pro-preview",
                    "gen_ai.usage.input_tokens": "15240",
                    "gen_ai.usage.output_tokens": "412",
                    "gen_ai.usage.experimental.reasoning_tokens": "280",
                    "service.name": "adk-soc-manager",
                    "gcp.vertex.agent.llm_request": json.dumps(
                        {
                            "contents": [
                                {
                                    "role": "user",
                                    "parts": [
                                        {
                                            "text": "Hunt for suspicious activity on wks-finance-04 over the last 7 days."
                                        }
                                    ],
                                }
                            ]
                        }
                    ),
                    "gcp.vertex.agent.llm_response": json.dumps(
                        {
                            "content": {
                                "role": "model",
                                "parts": [
                                    {
                                        "text": "Completed 7-day hunt.\n\n*Agent: agent_soc_manager | Model: gemini-3.1-pro-preview | Tools: udm_search*"
                                    }
                                ],
                            }
                        }
                    ),
                },
            },
            {
                "name": "execute_tool udm_search",
                "trace_id": "6caf20bca2bb410fc7a7966455c94027",
                "span_id": "span-tool-1",
                "attributes": {
                    "gen_ai.tool.name": "udm_search",
                    "gcp.vertex.agent.tool_call_args": json.dumps(
                        {
                            "query": 'principal.hostname = "wks-finance-04"',
                            "startTime": "2026-10-07T00:00:00Z",
                            "endTime": "2026-10-14T00:00:00Z",
                        }
                    ),
                    "gcp.vertex.agent.tool_response": json.dumps(
                        {"events": [], "total_events": 0}
                    ),
                    "service.name": "adk-soc-manager",
                },
            },
        ],
    }

    norm = _normalize_trace_info(raw_cloud_trace_record)
    assert len(norm["tool_calls"]) == 1
    assert norm["tool_calls"][0]["name"] == "udm_search"
    assert norm["tool_calls"][0]["args"]["startTime"] == "2026-10-07T00:00:00Z"
    assert norm["tool_calls"][0]["response"] == {"events": [], "total_events": 0}
    assert "7 days" in norm["user_prompt"]
    assert "*Agent: agent_soc_manager" in norm["final_response"]
    assert norm["otel_summary"]["span_count"] == 3
    assert norm["otel_summary"]["total_input_tokens"] == 15240
    assert norm["otel_summary"]["total_output_tokens"] == 412
    assert norm["otel_summary"]["total_reasoning_tokens"] == 280
    assert "gemini-3.1-pro-preview" in norm["otel_summary"]["models"]

    eval_res = evaluate(raw_cloud_trace_record)
    assert eval_res["passed"] is True
    assert eval_res["score"] == 1.0


def test_normalize_trace_info_unpacks_a2a_delegation_spans_and_child_tool_calls():
    """Verify _normalize_trace_info unpacks a2a.delegate.* spans and their a2a.child_tool_calls."""
    import json
    from aqua.custom_metrics import _normalize_trace_info, evaluate

    raw_a2a_trace = {
        "session_id": "7325253399786553344",
        "spans": [
            {
                "name": "execute_tool delegate_concurrently",
                "trace_id": "9be0c944c2b56782b432dafe7f26c182",
                "span_id": "span-concurrent",
                "attributes": {
                    "gen_ai.tool.name": "delegate_concurrently",
                    "gcp.vertex.agent.tool_call_args": json.dumps(
                        {
                            "cti_request": "Enrich 185.220.101.42",
                            "threat_hunter_request": "Hunt wks-finance-04 over last 7 days",
                        }
                    ),
                },
            },
            {
                "name": "a2a.delegate.cti_researcher",
                "trace_id": "9be0c944c2b56782b432dafe7f26c182",
                "span_id": "span-a2a-cti",
                "attributes": {
                    "gcp.vertex.agent.session_id": "7325253399786553344",
                    "a2a.specialist": "cti_researcher",
                    "a2a.request": "Enrich 185.220.101.42",
                    "a2a.child_tool_calls": json.dumps(
                        [
                            {
                                "name": "get_domain_report",
                                "args": {"domain": "update-service-auth.com"},
                            }
                        ]
                    ),
                },
            },
            {
                "name": "a2a.delegate.threat_hunter",
                "trace_id": "9be0c944c2b56782b432dafe7f26c182",
                "span_id": "span-a2a-hunter",
                "attributes": {
                    "gcp.vertex.agent.session_id": "7325253399786553344",
                    "a2a.specialist": "threat_hunter",
                    "a2a.request": "Hunt wks-finance-04 over last 7 days",
                    "a2a.child_tool_calls": json.dumps(
                        [
                            {
                                "name": "search_security_events",
                                "args": {
                                    "text": "Events on wks-finance-04",
                                    "hours_back": 168,
                                },
                            }
                        ]
                    ),
                },
            },
        ],
    }

    norm = _normalize_trace_info(raw_a2a_trace)
    tool_names = [tc["name"] for tc in norm["tool_calls"]]
    assert "delegate_concurrently" in tool_names
    assert "delegate_to_cti_researcher" in tool_names
    assert "get_domain_report" in tool_names
    assert "delegate_to_threat_hunter" in tool_names
    assert "search_security_events" in tool_names

    # Verify evaluate runs cleanly on unpacked A2A spans
    eval_res = evaluate(raw_a2a_trace)
    assert "metrics" in eval_res

