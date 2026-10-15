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

from datetime import datetime
import json
import re
from typing import Any


# Regex patterns for extracting requested lookback windows from user prompts
_DAYS_PATTERN = re.compile(
    r"\b(?:last|past|previous|over\s+the\s+last)\s+(\d+)\s*days?\b", re.IGNORECASE
)
_HOURS_PATTERN = re.compile(
    r"\b(?:last|past|previous|over\s+the\s+last|hours_back\s*=\s*)\s*(\d+)\s*(?:hours?|h|hrs?)\b",
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

    # Extract tool_calls, conversation, and otel_summary from OpenTelemetry / Cloud Trace spans
    spans_list = raw.get("spans") or []
    span_tool_calls: list[dict[str, Any]] = []
    span_user_turns: list[dict[str, str]] = []
    span_text_responses: list[str] = []
    trace_ids: set[str] = set()
    services: set[str] = set()
    models: set[str] = set()
    total_input_tokens = 0
    total_output_tokens = 0
    total_reasoning_tokens = 0

    for span in spans_list:
        span_dict = span if isinstance(span, dict) else getattr(span, "__dict__", {})
        span_name = str(span_dict.get("name") or "")
        attrs = span_dict.get("attributes") or span_dict.get("labels") or {}
        if not isinstance(attrs, dict):
            attrs = dict(attrs)
        tid = span_dict.get("trace_id") or attrs.get("trace_id")
        if tid:
            trace_ids.add(str(tid))
        svc = attrs.get("service.name") or attrs.get("OTEL_SERVICE_NAME")
        if svc:
            services.add(str(svc))
        mdl = attrs.get("gen_ai.request.model")
        if mdl:
            models.add(str(mdl))
        for tok_key, target_name in (
            ("gen_ai.usage.input_tokens", "in"),
            ("gen_ai.usage.output_tokens", "out"),
            ("gen_ai.usage.experimental.reasoning_tokens", "reason"),
        ):
            val = attrs.get(tok_key)
            if val is not None and str(val).isdigit() and span_name == "call_llm":
                if target_name == "in":
                    total_input_tokens += int(val)
                elif target_name == "out":
                    total_output_tokens += int(val)
                else:
                    total_reasoning_tokens += int(val)

        if span_name.startswith("execute_tool "):
            t_name = str(
                attrs.get("gen_ai.tool.name")
                or span_name.removeprefix("execute_tool ").strip()
            )
            if t_name == "(merged)":
                continue
            t_args = (
                attrs.get("gcp.vertex.agent.tool_call_args")
                or attrs.get("gen_ai.tool.call.arguments")
                or {}
            )
            if isinstance(t_args, str):
                if t_args == "N/A":
                    t_args = {}
                else:
                    try:
                        t_args = json.loads(t_args)
                    except Exception:
                        t_args = {"raw": t_args}
            t_resp = (
                attrs.get("gcp.vertex.agent.tool_response")
                or attrs.get("gen_ai.tool.call.result")
            )
            if isinstance(t_resp, str):
                try:
                    parsed_resp = json.loads(t_resp)
                    if (
                        isinstance(parsed_resp, dict)
                        and set(parsed_resp.keys()) == {"result"}
                    ):
                        t_resp = parsed_resp["result"]
                    else:
                        t_resp = parsed_resp
                except Exception:
                    pass
            span_tool_calls.append(
                {"name": t_name, "args": t_args, "response": t_resp}
            )
        elif span_name.startswith("a2a.delegate."):
            specialist = str(
                attrs.get("a2a.target_agent")
                or span_name.removeprefix("a2a.delegate.").strip()
            )
            a2a_req = str(attrs.get("a2a.request") or "")
            a2a_resp = str(attrs.get("a2a.response_preview") or "")
            child_calls_raw = attrs.get("a2a.child_tool_calls")
            parsed_child_calls: list[dict[str, Any]] = []
            if isinstance(child_calls_raw, str) and child_calls_raw.strip():
                try:
                    loaded = json.loads(child_calls_raw)
                    if isinstance(loaded, list):
                        parsed_child_calls = [
                            c for c in loaded if isinstance(c, dict) and c.get("name")
                        ]
                except Exception:
                    pass
            elif isinstance(child_calls_raw, list):
                parsed_child_calls = [
                    c for c in child_calls_raw if isinstance(c, dict) and c.get("name")
                ]
            span_tool_calls.append(
                {
                    "name": f"delegate_to_{specialist}",
                    "args": {"query": a2a_req},
                    "response": a2a_resp,
                    "a2a_target_resource": attrs.get("a2a.target_resource_name"),
                    "a2a_child_tool_calls": parsed_child_calls,
                }
            )
            for child_c in parsed_child_calls:
                span_tool_calls.append(
                    {
                        "name": str(child_c.get("name")),
                        "args": child_c.get("args") or {},
                        "response": child_c.get("response"),
                        "via_a2a_specialist": specialist,
                    }
                )
        elif span_name == "call_llm":
            llm_req_raw = attrs.get("gcp.vertex.agent.llm_request")
            if isinstance(llm_req_raw, str):
                try:
                    llm_req = json.loads(llm_req_raw)
                    for content_item in llm_req.get("contents") or []:
                        if (
                            isinstance(content_item, dict)
                            and content_item.get("role") == "user"
                        ):
                            for part in content_item.get("parts") or []:
                                txt = (
                                    part.get("text")
                                    if isinstance(part, dict)
                                    else None
                                )
                                if (
                                    isinstance(txt, str)
                                    and txt.strip()
                                    and not txt.strip().startswith("For context:")
                                ):
                                    clean_u = txt.strip()
                                    if not any(
                                        u["content"] == clean_u
                                        for u in span_user_turns
                                    ):
                                        span_user_turns.append(
                                            {"role": "user", "content": clean_u}
                                        )
                except Exception:
                    pass
            llm_resp_raw = attrs.get("gcp.vertex.agent.llm_response")
            if isinstance(llm_resp_raw, str):
                try:
                    llm_resp = json.loads(llm_resp_raw)
                    content_obj = llm_resp.get("content") or {}
                    for part in content_obj.get("parts") or []:
                        txt = part.get("text") if isinstance(part, dict) else None
                        if isinstance(txt, str) and txt.strip():
                            span_text_responses.append(txt.strip())
                except Exception:
                    pass

    if not normalized_calls and span_tool_calls:
        normalized_calls = span_tool_calls
    elif normalized_calls and span_tool_calls:
        # Enrich existing tool_calls that lack args or responses using span_tool_calls
        resp_lookup = {
            c["name"]: c["response"]
            for c in span_tool_calls
            if c.get("response") is not None
        }
        args_lookup = {
            c["name"]: c["args"]
            for c in span_tool_calls
            if c.get("args")
        }
        a2a_children_lookup = {
            c["name"]: c["a2a_child_tool_calls"]
            for c in span_tool_calls
            if c.get("a2a_child_tool_calls") is not None
        }
        for call in normalized_calls:
            c_name = call.get("name")
            if call.get("response") is None and c_name in resp_lookup:
                call["response"] = resp_lookup[c_name]
            if not call.get("args") and c_name in args_lookup:
                call["args"] = args_lookup[c_name]
            if c_name in a2a_children_lookup:
                call["a2a_child_tool_calls"] = a2a_children_lookup[c_name]
        # Append child tool calls recorded via A2A delegation spans (`a2a.delegate.*`)
        for c in span_tool_calls:
            if c.get("via_a2a_specialist"):
                normalized_calls.append(c)

    if not raw.get("conversation") and span_user_turns:
        raw["conversation"] = span_user_turns
    if not raw.get("user_prompt") and span_user_turns:
        raw["user_prompt"] = " ".join(u["content"] for u in span_user_turns)
    if not raw.get("final_response") and span_text_responses:
        raw["final_response"] = "\n\n".join(span_text_responses)

    if spans_list:
        raw["otel_summary"] = {
            "span_count": len(spans_list),
            "trace_ids": sorted(trace_ids),
            "services": sorted(services),
            "models": sorted(models),
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "total_reasoning_tokens": total_reasoning_tokens,
        }

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


def _extract_iso_range_hours(args: dict[str, Any]) -> int | None:
    """Compute lookback span in hours from ISO-8601 startTime/endTime tool arguments."""
    start_str = args.get("startTime") or args.get("start_time")
    end_str = args.get("endTime") or args.get("end_time")
    if not (isinstance(start_str, str) and isinstance(end_str, str)):
        return None
    try:
        start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
        delta_hours = round(abs((end_dt - start_dt).total_seconds()) / 3600.0)
        return delta_hours if delta_hours > 0 else None
    except Exception:
        return None


def timerange_propagation_check(trace_info: Any) -> dict[str, Any]:
    """Verify that user-specified time windows are propagated to SIEM searches and sub-agent delegations."""
    trace = _normalize_trace_info(trace_info)
    user_prompt = str(trace.get("user_prompt") or "")
    conversation = trace.get("conversation") or []
    user_turns: list[str] = [
        str(t.get("content") or t.get("text") or "")
        for t in conversation
        if isinstance(t, dict)
        and (t.get("role") == "user" or t.get("author") == "user")
    ]
    if not user_prompt and user_turns:
        user_prompt = " ".join(user_turns)

    expected_hours = trace.get("expected_hours_back") or extract_expected_hours_back(
        user_prompt
    )
    # Build per-turn expected hours map for multi-turn sessions
    turn_expected_map: dict[int, int] = {}
    running_hours: int | None = None
    for idx, turn_text in enumerate(user_turns, start=1):
        parsed_h = extract_expected_hours_back(turn_text)
        if parsed_h is not None:
            running_hours = parsed_h
        if running_hours is not None:
            turn_expected_map[idx] = running_hours

    tool_calls = trace.get("tool_calls") or []

    if expected_hours is None and not turn_expected_map:
        return {
            "metric": "timerange_propagation_check",
            "score": 1.0,
            "passed": True,
            "explanation": "No explicit lookback window constraint in user prompt; check not applicable.",
        }

    violations: list[str] = []
    checked_calls = 0

    for call in tool_calls:
        name = str(call.get("name") or "")
        args = call.get("args") or {}
        call_turn = call.get("turn") if isinstance(call, dict) else None
        target_hours = (
            turn_expected_map.get(int(call_turn), expected_hours)
            if call_turn is not None and turn_expected_map
            else expected_hours
        )
        if target_hours is None:
            continue
        target_days = target_hours // 24 if target_hours % 24 == 0 else None

        if name in _TIME_SENSITIVE_TOOLS:
            checked_calls += 1
            actual_hours = args.get("hours_back") if isinstance(args, dict) else None
            if actual_hours is None and isinstance(args, dict):
                actual_hours = _extract_iso_range_hours(args)
            if actual_hours is None:
                violations.append(
                    f"Tool '{name}' omitted mandatory time bounds (expected hours_back={target_hours})."
                )
            elif int(actual_hours) != int(target_hours):
                violations.append(
                    f"Tool '{name}' called with hours_back={actual_hours} instead of expected hours_back={target_hours}."
                )
        elif _is_delegation_tool(name) and name not in (
            "transfer_to_agent",
            "delegate_to_tier2_responder",
            "delegate_to_cti_researcher",
            "cti_researcher",
        ):
            checked_calls += 1
            payload_text = str(args)
            has_hours = str(target_hours) in payload_text
            has_days = (
                target_days is not None
                and re.search(rf"\b{target_days}\s*(?:day|d)\b", payload_text, re.I)
                is not None
            )
            if not (has_hours or has_days):
                violations.append(
                    f"Delegation tool '{name}' omitted expected lookback window ({target_hours}h)."
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
            f"All {checked_calls} time-sensitive tool/delegation calls preserved expected lookback window ({expected_hours}h)."
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
