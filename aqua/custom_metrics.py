"""
Domain-specific custom evaluators for Ambient Quality Agent (AQuA) outer-loop
and inner-loop trajectory grading in the Agentic SOC platform.

Evaluators:
1. timerange_propagation_check
2. soar_phase2_fallback_check
3. subagent_context_forwarding_check
4. design_spec_attribution_check
5. evaluate(trace_info, metric_name=None) unified AQuA entrypoint
"""

from __future__ import annotations

import json
import re
from typing import Any


# Regex patterns for extracting requested lookback windows from user prompts
_DAYS_PATTERN = re.compile(
    r"\b(?:last|past|previous|over\s+the\s+last)\s+(\d+)\s*days?\b", re.IGNORECASE
)
_HOURS_PATTERN = re.compile(
    r"\b(?:last|past|previous|over\s+the\s+last|hours_back\s*=\s*)(\d+)\s*(?:hours?|h|hrs?)?\b",
    re.IGNORECASE,
)
_EXPLICIT_HOURS_BACK_PATTERN = re.compile(
    r"\bhours_back\s*[=:]\s*(\d+)\b", re.IGNORECASE
)

# Regex for extracting entities from prior turns when `prior_entities` is not explicitly pre-populated
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CASE_ID_PATTERN = re.compile(r"\bcase[-_\s#]?(\d{3,10})\b", re.IGNORECASE)
_HOST_PATTERN = re.compile(
    r"\b(?:wks|srv|dc|host|prod|dev|laptop|db)-[a-z0-9-]+\b", re.IGNORECASE
)

_ATTRIBUTION_FOOTER_PATTERN = re.compile(
    r"\*Agent:\s*(?P<agent>[^|*]+?)\s*\|\s*Model:\s*(?P<model>[^|*]+?)\s*\|\s*Tools:\s*(?P<tools>[^*]+?)\*"
)

_TIME_SENSITIVE_TOOLS = {
    "udm_search",
    "search_security_events",
    "search_udm",
    "find_entity",
    "lookup_entity",
    "summarize_entity",
    "get_ioc_matches",
}

_RAG_TOOLS = {
    "VertexAiRagRetrieval",
    "retrieve_security_runbooks",
    "retrieve_agentic_soc_runbooks",
}

_SPECIALIST_DELEGATION_MAP = {
    "delegate_to_tier2_responder": ("tier 2", "tier2", "incident responder"),
    "delegate_to_threat_hunter": ("threat hunter", "threat_hunter"),
    "delegate_to_cti_researcher": ("cti researcher", "cti_researcher"),
    "delegate_to_detection_engineer": ("detection engineer", "detection_engineer"),
    "tier1_analyst": ("tier 1", "tier1", "tier1_analyst"),
    "cti_researcher": ("cti researcher", "cti_researcher"),
}

_SIEMPLIFY_FALLBACK_INDICATORS = (
    "/api/1p/external/v1/cases",
    "siemplify",
    "soar_list_cases",
    "list_soar_cases",
    "get_siemplify_cases",
    "secops-soar",
)

_NON_PHASE2_TENANTS = {
    "secops-demo-env",
    "a13f6726-efed-452e-9008-8fe0d3cb0f75",
}


def _is_delegation_tool(name: str) -> bool:
    """Return True if the tool name represents an in-process or A2A sub-agent handoff."""
    return name in (
        "delegate_to_specialist",
        "delegate_concurrently",
        "transfer_to_agent",
        "tier1_analyst",
        "cti_researcher",
    ) or name.startswith("delegate_to_")


def _normalize_trace_info(trace_info: Any) -> dict[str, Any]:
    """Normalize dict or object/span TraceInfo payloads into a standard evaluation dict."""
    if isinstance(trace_info, dict):
        raw = dict(trace_info)
    else:
        raw = {}
        for attr in (
            "user_prompt",
            "expected_hours_back",
            "tool_calls",
            "final_response",
            "prior_entities",
            "conversation",
            "spans",
            "tenant_id",
            "customer_id",
            "project_id",
            "sub_agents_invoked",
        ):
            if hasattr(trace_info, attr):
                raw[attr] = getattr(trace_info, attr)

    # Normalize tool_calls items (support dicts, strings, or span objects)
    raw_calls = raw.get("tool_calls") or []
    normalized_calls: list[dict[str, Any]] = []
    for item in raw_calls:
        if isinstance(item, dict):
            normalized_calls.append(item)
        elif isinstance(item, str):
            normalized_calls.append({"name": item, "args": {}})
        else:
            normalized_calls.append(
                {
                    "name": getattr(item, "name", ""),
                    "args": getattr(item, "args", {}) or {},
                    "response": getattr(item, "response", None),
                }
            )

    # Extract tool_calls from OpenTelemetry spans if tool_calls was not pre-populated
    if not normalized_calls and raw.get("spans"):
        for span in raw.get("spans") or []:
            span_dict = (
                span if isinstance(span, dict) else getattr(span, "__dict__", {})
            )
            span_name = str(span_dict.get("name") or "")
            attrs = span_dict.get("attributes") or {}
            if span_name.startswith("execute_tool "):
                t_name = span_name.removeprefix("execute_tool ").strip()
                t_args = attrs.get("gen_ai.tool.call.arguments") or {}
                if isinstance(t_args, str):
                    try:
                        t_args = json.loads(t_args)
                    except Exception:
                        t_args = {"raw": t_args}
                t_resp = attrs.get("gen_ai.tool.call.result")
                normalized_calls.append(
                    {"name": t_name, "args": t_args, "response": t_resp}
                )

    raw["tool_calls"] = normalized_calls
    return raw


def extract_expected_hours_back(user_prompt: str) -> int | None:
    """Extract the expected hours_back integer from a natural-language user prompt."""
    if not user_prompt:
        return None
    explicit_match = _EXPLICIT_HOURS_BACK_PATTERN.search(user_prompt)
    if explicit_match:
        return int(explicit_match.group(1))
    days_match = _DAYS_PATTERN.search(user_prompt)
    if days_match:
        return int(days_match.group(1)) * 24
    hours_match = _HOURS_PATTERN.search(user_prompt)
    if hours_match and any(
        unit in user_prompt.lower() for unit in ("hour", "hr", "h ")
    ):
        return int(hours_match.group(1))
    return None


def timerange_propagation_check(trace_info: Any) -> dict[str, Any]:
    """Verify that user-specified time windows are propagated to SIEM searches and sub-agent delegations."""
    trace = _normalize_trace_info(trace_info)
    user_prompt = str(trace.get("user_prompt") or "")
    if not user_prompt and trace.get("conversation"):
        user_turns = [
            str(t.get("content") or "")
            for t in (trace.get("conversation") or [])
            if isinstance(t, dict) and t.get("role") == "user"
        ]
        user_prompt = " ".join(user_turns)

    expected_hours = trace.get("expected_hours_back") or extract_expected_hours_back(
        user_prompt
    )
    tool_calls = trace.get("tool_calls") or []

    if expected_hours is None:
        return {
            "metric": "timerange_propagation_check",
            "score": 1.0,
            "passed": True,
            "explanation": "No explicit lookback window constraint in user prompt; check not applicable.",
        }

    expected_days = expected_hours // 24 if expected_hours % 24 == 0 else None
    violations: list[str] = []
    checked_calls = 0

    for call in tool_calls:
        name = str(call.get("name") or "")
        args = call.get("args") or {}
        if name in _TIME_SENSITIVE_TOOLS:
            checked_calls += 1
            actual_hours = args.get("hours_back") if isinstance(args, dict) else None
            if actual_hours is None:
                violations.append(
                    f"Tool '{name}' omitted mandatory time bounds (expected hours_back={expected_hours})."
                )
            elif int(actual_hours) != int(expected_hours):
                violations.append(
                    f"Tool '{name}' called with hours_back={actual_hours} instead of expected hours_back={expected_hours}."
                )
        elif _is_delegation_tool(name):
            checked_calls += 1
            payload_text = str(args)
            has_hours = str(expected_hours) in payload_text
            has_days = (
                expected_days is not None
                and re.search(rf"\b{expected_days}\s*(?:day|d)\b", payload_text, re.I)
                is not None
            )
            if not (has_hours or has_days):
                violations.append(
                    f"Delegation tool '{name}' omitted expected lookback window ({expected_hours}h)."
                )

    if violations:
        return {
            "metric": "timerange_propagation_check",
            "score": 0.0,
            "passed": False,
            "explanation": " ".join(violations),
        }

    return {
        "metric": "timerange_propagation_check",
        "score": 1.0,
        "passed": True,
        "explanation": (
            f"All {checked_calls} time-sensitive tool/delegation calls preserved hours_back={expected_hours}."
        ),
    }


def _is_empty_cases_payload(resp: Any) -> bool:
    """Return True if a native Chronicle list_cases response represents an empty `{}` payload."""
    if resp == {} or resp == {"cases": []}:
        return True
    if isinstance(resp, str):
        stripped = resp.strip()
        if stripped == "{}" or stripped.endswith("{}"):
            return True
        try:
            parsed = json.loads(stripped)
            return parsed == {} or parsed == {"cases": []}
        except Exception:
            return False
    return False


def soar_phase2_fallback_check(trace_info: Any) -> dict[str, Any]:
    """Verify fallback to standalone Siemplify SOAR when native Chronicle list_cases returns {}."""
    trace = _normalize_trace_info(trace_info)
    tenant = str(
        trace.get("tenant_id")
        or trace.get("customer_id")
        or trace.get("project_id")
        or ""
    ).strip()
    if tenant and tenant not in _NON_PHASE2_TENANTS:
        return {
            "metric": "soar_phase2_fallback_check",
            "score": 1.0,
            "passed": True,
            "explanation": f"Tenant '{tenant}' is outside non-Phase-2 SOAR fallback scope.",
        }

    tool_calls = trace.get("tool_calls") or []
    native_empty_detected = False
    fallback_executed = False

    for call in tool_calls:
        name = str(call.get("name") or "")
        args = call.get("args") or {}
        resp = call.get("response")

        if name in ("list_cases", "chronicle_list_cases"):
            if _is_empty_cases_payload(resp):
                native_empty_detected = True
            continue

        if native_empty_detected:
            call_blob = f"{name} {args}".lower()
            if any(ind in call_blob for ind in _SIEMPLIFY_FALLBACK_INDICATORS):
                fallback_executed = True

    if not native_empty_detected:
        return {
            "metric": "soar_phase2_fallback_check",
            "score": 1.0,
            "passed": True,
            "explanation": "Native Chronicle list_cases did not return an empty Phase 2 payload; check passed.",
        }

    if fallback_executed:
        return {
            "metric": "soar_phase2_fallback_check",
            "score": 1.0,
            "passed": True,
            "explanation": (
                "Agent properly fell back to standalone Siemplify SOAR (/api/1p/external/v1/cases) after native list_cases returned {}."
            ),
        }

    return {
        "metric": "soar_phase2_fallback_check",
        "score": 0.0,
        "passed": False,
        "explanation": (
            "Native Chronicle list_cases returned {}, but agent did not fall back to standalone Siemplify SOAR (/api/1p/external/v1/cases)."
        ),
    }


def _extract_entities_from_text(text: str) -> list[str]:
    entities: list[str] = []
    for match in _IP_PATTERN.findall(text):
        if match not in entities:
            entities.append(match)
    for match in _HOST_PATTERN.findall(text):
        if match not in entities:
            entities.append(match)
    for match in _CASE_ID_PATTERN.finditer(text):
        full = match.group(0)
        if full not in entities:
            entities.append(full)
    return entities


def subagent_context_forwarding_check(trace_info: Any) -> dict[str, Any]:
    """Verify specialist handoffs forward prior entities, case IDs, and time windows."""
    trace = _normalize_trace_info(trace_info)
    prior_entities: list[str] = list(trace.get("prior_entities") or [])
    if not prior_entities:
        text_sources: list[str] = []
        if trace.get("user_prompt"):
            text_sources.append(str(trace.get("user_prompt")))
        for turn in trace.get("conversation") or []:
            if isinstance(turn, dict) and turn.get("content"):
                text_sources.append(str(turn.get("content")))
        prior_entities = _extract_entities_from_text(" ".join(text_sources))

    tool_calls = trace.get("tool_calls") or []
    delegation_calls = [
        c for c in tool_calls if _is_delegation_tool(str(c.get("name") or ""))
    ]

    if not delegation_calls or not prior_entities:
        return {
            "metric": "subagent_context_forwarding_check",
            "score": 1.0,
            "passed": True,
            "explanation": "No sub-agent delegation or prior entities requiring forwarding.",
        }

    combined_delegation_payload = " ".join(
        str(c.get("args") or {}) for c in delegation_calls
    ).lower()

    missing = [
        entity
        for entity in prior_entities
        if str(entity).lower() not in combined_delegation_payload
    ]
    forwarded_count = len(prior_entities) - len(missing)
    score = forwarded_count / len(prior_entities)

    if missing:
        return {
            "metric": "subagent_context_forwarding_check",
            "score": round(score, 4),
            "passed": False,
            "explanation": (
                f"Sub-agent delegation dropped {len(missing)}/{len(prior_entities)} context entities: {', '.join(missing)}."
            ),
        }

    return {
        "metric": "subagent_context_forwarding_check",
        "score": 1.0,
        "passed": True,
        "explanation": f"All {len(prior_entities)} context entities were forwarded across A2A delegation boundaries.",
    }


def design_spec_attribution_check(trace_info: Any) -> dict[str, Any]:
    """Verify attribution footer, executed tool mentions, specialist attribution, and RAG grounding citations."""
    trace = _normalize_trace_info(trace_info)
    final_response = str(trace.get("final_response") or "").strip()
    final_lower = final_response.lower()
    tool_calls = trace.get("tool_calls") or []
    executed_tools = {str(c.get("name")).strip() for c in tool_calls if c.get("name")}

    match = _ATTRIBUTION_FOOTER_PATTERN.search(final_response)
    if not match:
        return {
            "metric": "design_spec_attribution_check",
            "score": 0.0,
            "passed": False,
            "specialist_attribution": False,
            "tool_name_mentioned": False,
            "has_grounding_citation": False,
            "explanation": (
                "Final response is missing the mandatory '*Agent: ... | Model: ... | Tools: ...*' attribution footer."
            ),
        }

    claimed_raw = match.group("tools").strip()
    if claimed_raw.lower() in ("none", "n/a", ""):
        claimed_tools: set[str] = set()
    else:
        claimed_tools = {t.strip() for t in claimed_raw.split(",") if t.strip()}

    # 1. Verify no fabricated tools and all executed tools are attributed
    if executed_tools and claimed_tools:
        unexecuted_claims = claimed_tools - executed_tools
        if unexecuted_claims:
            return {
                "metric": "design_spec_attribution_check",
                "score": 0.5,
                "passed": False,
                "specialist_attribution": True,
                "tool_name_mentioned": False,
                "has_grounding_citation": True,
                "explanation": (
                    f"Attribution footer claimed unexecuted tools: {', '.join(sorted(unexecuted_claims))}."
                ),
            }

    if executed_tools and not claimed_tools:
        missing_tools = [
            t for t in sorted(executed_tools) if t.lower() not in final_lower
        ]
        if missing_tools:
            return {
                "metric": "design_spec_attribution_check",
                "score": 0.5,
                "passed": False,
                "specialist_attribution": True,
                "tool_name_mentioned": False,
                "has_grounding_citation": True,
                "explanation": (
                    f"Executed tools omitted from response and attribution footer: {', '.join(missing_tools)}."
                ),
            }

    # 2. Verify specialist attribution when sub-agents were invoked
    invoked_specialists: list[str] = list(trace.get("sub_agents_invoked") or [])
    for tool_name in executed_tools:
        if tool_name in _SPECIALIST_DELEGATION_MAP:
            invoked_specialists.append(tool_name)

    for spec in invoked_specialists:
        keywords = _SPECIALIST_DELEGATION_MAP.get(spec, (spec.lower(),))
        if not any(kw in final_lower for kw in keywords):
            return {
                "metric": "design_spec_attribution_check",
                "score": 0.5,
                "passed": False,
                "specialist_attribution": False,
                "tool_name_mentioned": True,
                "has_grounding_citation": True,
                "explanation": (
                    f"Invoked specialist '{spec}' was not attributed in the final response."
                ),
            }

    # 3. Verify grounding citation when RAG retrieval tools were invoked
    rag_calls = [c for c in tool_calls if str(c.get("name") or "") in _RAG_TOOLS]
    has_grounding_citation = True
    if rag_calls and trace.get("require_grounding_citation", False):
        has_grounding_citation = any(
            marker in final_lower
            for marker in ("runbook", ".md", "[source", "playbook", "citation")
        )
        if not has_grounding_citation:
            return {
                "metric": "design_spec_attribution_check",
                "score": 0.5,
                "passed": False,
                "specialist_attribution": True,
                "tool_name_mentioned": True,
                "has_grounding_citation": False,
                "explanation": (
                    "RAG runbook retrieval tool was executed, but final response lacks grounding source citation."
                ),
            }

    return {
        "metric": "design_spec_attribution_check",
        "score": 1.0,
        "passed": True,
        "specialist_attribution": True,
        "tool_name_mentioned": True,
        "has_grounding_citation": has_grounding_citation,
        "explanation": "Attribution footer present and grounded in executed trajectory tools.",
    }


_METRIC_DISPATCH = {
    "timerange_propagation_check": timerange_propagation_check,
    "soar_phase2_fallback_check": soar_phase2_fallback_check,
    "subagent_context_forwarding_check": subagent_context_forwarding_check,
    "design_spec_attribution_check": design_spec_attribution_check,
}


def evaluate(trace_info: Any, metric_name: str | None = None) -> dict[str, Any]:
    """Unified AQuA custom evaluator entrypoint (`evaluate(trace_info) -> EvaluationResult`)."""
    trace = _normalize_trace_info(trace_info)
    target_metric = metric_name or trace.get("metric_name")
    if target_metric and target_metric in _METRIC_DISPATCH:
        return _METRIC_DISPATCH[target_metric](trace)

    results = {name: fn(trace) for name, fn in _METRIC_DISPATCH.items()}
    avg_score = sum(r["score"] for r in results.values()) / len(results)
    all_passed = all(r["passed"] for r in results.values())
    return {
        "metric": "aqua_soc_custom_suite",
        "score": round(avg_score, 4),
        "passed": all_passed,
        "metrics": results,
        "explanation": "; ".join(
            f"{k}: {'PASS' if v['passed'] else 'FAIL'} ({v['score']})"
            for k, v in results.items()
        ),
    }
