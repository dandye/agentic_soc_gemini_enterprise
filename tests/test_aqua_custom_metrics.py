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
                "args": {"query": 'principal.hostname = "wks-finance-04"', "hours_back": 168},
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
                "args": {"query": 'principal.hostname = "wks-finance-04"', "hours_back": 24},
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
    assert "Siemplify" in res_fail["explanation"] or "/api/1p/external/v1/cases" in res_fail["explanation"]

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
                "args": {"endpoint": "https://ytvgh.siemplify-soar.com:443/api/1p/external/v1/cases"},
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
        "tool_calls": [{"name": "udm_search", "args": {}}, {"name": "get_ioc_match", "args": {}}],
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
