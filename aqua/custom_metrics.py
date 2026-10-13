"""
Domain-specific custom evaluators for Ambient Quality Agent (AQuA) outer-loop
and inner-loop trajectory grading in the Agentic SOC platform.

Evaluators:
1. timerange_propagation_check
2. soar_phase2_fallback_check
3. subagent_context_forwarding_check
4. design_spec_attribution_check
"""

from __future__ import annotations

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
    r"\b(?:wks|srv|dc|host|prod|dev| laptop|db)-[a-z0-9-]+\b", re.IGNORECASE
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

_SIEMPLIFY_FALLBACK_INDICATORS = (
    "/api/1p/external/v1/cases",
    "siemplify",
    "soar_list_cases",
    "list_soar_cases",
    "get_siemplify_cases",
    "secops-soar",
)


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


def timerange_propagation_check(trace: dict[str, Any]) -> dict[str, Any]:
    """Verify that user-specified time windows are propagated to SIEM searches and sub-agent delegations."""
    user_prompt = str(trace.get("user_prompt") or "")
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
            actual_hours = args.get("hours_back")
            if actual_hours is not None and int(actual_hours) != int(expected_hours):
                violations.append(
                    f"Tool '{name}' called with hours_back={actual_hours} instead of expected hours_back={expected_hours}."
                )
        elif name in ("delegate_to_specialist", "delegate_concurrently"):
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


def soar_phase2_fallback_check(trace: dict[str, Any]) -> dict[str, Any]:
    """Verify fallback to standalone Siemplify SOAR when native Chronicle list_cases returns {}."""
    tool_calls = trace.get("tool_calls") or []
    native_empty_detected = False
    fallback_executed = False

    for call in tool_calls:
        name = str(call.get("name") or "")
        args = call.get("args") or {}
        resp = call.get("response")
        call_blob = f"{name} {args} {resp}".lower()

        if name in ("list_cases", "chronicle_list_cases"):
            if (
                resp == {}
                or resp == {"cases": []}
                or (isinstance(resp, str) and resp.strip().endswith("{}"))
            ):
                native_empty_detected = True

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


def subagent_context_forwarding_check(trace: dict[str, Any]) -> dict[str, Any]:
    """Verify delegate_to_specialist and delegate_concurrently forward prior entities and case IDs."""
    prior_entities: list[str] = list(trace.get("prior_entities") or [])
    if not prior_entities and trace.get("user_prompt"):
        prior_entities = _extract_entities_from_text(str(trace.get("user_prompt")))

    tool_calls = trace.get("tool_calls") or []
    delegation_calls = [
        c
        for c in tool_calls
        if str(c.get("name") or "")
        in ("delegate_to_specialist", "delegate_concurrently")
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


def design_spec_attribution_check(trace: dict[str, Any]) -> dict[str, Any]:
    """Verify the final response includes the mandatory attribution footer and accurate tool list."""
    final_response = str(trace.get("final_response") or "").strip()
    tool_calls = trace.get("tool_calls") or []
    executed_tools = {
        str(c.get("name")).strip() for c in tool_calls if c.get("name")
    }

    match = _ATTRIBUTION_FOOTER_PATTERN.search(final_response)
    if not match:
        return {
            "metric": "design_spec_attribution_check",
            "score": 0.0,
            "passed": False,
            "explanation": (
                "Final response is missing the mandatory '*Agent: ... | Model: ... | Tools: ...*' attribution footer."
            ),
        }

    claimed_raw = match.group("tools").strip()
    if claimed_raw.lower() in ("none", "n/a", ""):
        claimed_tools: set[str] = set()
    else:
        claimed_tools = {
            t.strip() for t in claimed_raw.split(",") if t.strip()
        }

    # Check if claimed tools include fabricated tools that were never executed
    if executed_tools and claimed_tools:
        unexecuted_claims = claimed_tools - executed_tools
        if unexecuted_claims:
            return {
                "metric": "design_spec_attribution_check",
                "score": 0.5,
                "passed": False,
                "explanation": (
                    f"Attribution footer claimed unexecuted tools: {', '.join(sorted(unexecuted_claims))}."
                ),
            }

    return {
        "metric": "design_spec_attribution_check",
        "score": 1.0,
        "passed": True,
        "explanation": "Attribution footer present and grounded in executed trajectory tools.",
    }
