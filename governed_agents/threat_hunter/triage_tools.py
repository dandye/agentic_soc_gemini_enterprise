"""Decision 1 pre-LLM UDM and alert noise-filtering callback for Threat Hunter.

Evaluates Chronicle SIEM UDM events or security alerts returned by `udm_search`
and `list_security_alerts` inside an ADK `after_tool_callback` before
`threat_hunter_llm` sees the payload. Events are batched in chunks of up to 15
into a single shared Decision 1 forward pass (up to 60 indexed questions per
RPC), capped at 60 evaluated events and a 15-second callback time budget:
  * P(true_positive) < 0.30: dropped and counted in `dropped_low_signal_count`
  * 0.30 <= P(true_positive) < 0.85: kept with `decision1_triage` metadata
  * P(true_positive) >= 0.85: kept and tagged `[HIGH_CONFIDENCE_ESCALATE]`
  * Overflow beyond cap or budget: passed through in `passthrough_overflow_count`
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any

from decision_client import evaluate_decisions


_FILTERED_TOOLS = frozenset({"udm_search", "list_security_alerts"})
_EVENT_LIST_KEYS = (
    "events",
    "alerts",
    "results",
    "udmEvents",
    "securityAlerts",
)
_DROP_THRESHOLD = 0.30
_ESCALATE_THRESHOLD = 0.85
_BATCH_SIZE = 15
_MAX_FILTER_EVENTS = 60
_CALLBACK_BUDGET_SECONDS = 15.0
_MAX_UDM_SEARCH_LIMIT = 25
_MAX_UDM_SEARCH_CALLS = 2

_SEVERITY_CRITERIA = [
    "Informational or benign activity with no security impact.",
    "Low severity anomaly or policy notice requiring routine review.",
    "Medium severity suspicious activity warranting analyst investigation.",
    "High severity likely threat activity with potential host or account impact.",
    "Critical severity active compromise, lateral movement, or data exfiltration.",
]

_MITRE_TACTIC_CRITERIA = {
    "initial_access": (
        "Phishing, exploit public-facing application, or external remote service entry."
    ),
    "execution": (
        "Command and scripting interpreter, PowerShell, WMI, or malicious binary execution."
    ),
    "persistence": (
        "Scheduled tasks, registry run keys, new accounts, or startup modifications."
    ),
    "privilege_escalation": (
        "Token manipulation, sudo abuse, UAC bypass, or elevation to admin or SYSTEM."
    ),
    "defense_evasion": (
        "Log clearing, process hollowing, disabling security tools, or obfuscation."
    ),
    "credential_access": (
        "LSASS dumping, brute force, Kerberoasting, or credential harvesting."
    ),
    "discovery": (
        "Network scanning, account or domain enumeration, or host reconnaissance."
    ),
    "lateral_movement": (
        "SMB, WinRM, RDP, or SSH pivoting or remote service execution across hosts."
    ),
    "collection_exfiltration": (
        "Staging archives, unusual outbound transfers, or DNS or HTTP exfiltration."
    ),
    "command_and_control": (
        "Beaconing, C2 callbacks, or anomalous external encrypted channels."
    ),
    "other_or_benign": (
        "Other tactic not listed above, or benign or inconclusive activity."
    ),
}

_NEXT_ACTION_CRITERIA = {
    "dismiss": (
        "Benign or clear false positive; close or deprioritize without further escalation."
    ),
    "enrich_cti": (
        "Suspicious indicators present; enrich IPs, domains, or hashes via CTI before escalating."
    ),
    "escalate_tier2": (
        "High-confidence threat or active compromise; escalate to Tier 2 for containment."
    ),
    "tune_yaral2": (
        "Noisy or overly broad Chronicle SIEM YARA-L 2.0 detection rule "
        "(distinct from standard file/payload YARA); send to Detection Engineering for tuning."
    ),
}


def _summarize_event(item: Any) -> str:
    """Serializes a single UDM event or alert compactly for batched evaluation."""
    if isinstance(item, str):
        return item
    return json.dumps(item, separators=(",", ":"), sort_keys=True)


def _build_batch_payload(
    batch: list[Any],
) -> tuple[str, dict[str, dict[str, Any]]]:
    """Builds one shared Decision 1 input and indexed questions for a batch."""
    sections = [
        "Evaluate each indexed Chronicle SIEM UDM event or security alert below. "
        "Answer each event's indexed questions (e0_*, e1_*, ...) independently."
    ]
    questions: dict[str, dict[str, Any]] = {}

    for idx, item in enumerate(batch):
        tag = f"e{idx}"
        sections.append(f"\n[Event {tag}]\n{_summarize_event(item)}")
        questions[f"{tag}_tp"] = {
            "type": "noul",
            "instructions": (
                f"For Event {tag} only: determine whether it represents a true positive "
                "security threat rather than benign administrative activity or a false positive."
            ),
        }
        questions[f"{tag}_sev"] = {
            "type": "score",
            "instructions": (
                f"For Event {tag} only: score its overall security severity."
            ),
            "criteria": _SEVERITY_CRITERIA,
        }
        questions[f"{tag}_tactic"] = {
            "type": "choice",
            "instructions": (
                f"For Event {tag} only: select the primary MITRE ATT&CK tactic."
            ),
            "criteria": _MITRE_TACTIC_CRITERIA,
        }
        questions[f"{tag}_next"] = {
            "type": "choice",
            "instructions": (
                f"For Event {tag} only: select the recommended next SOC triage action."
            ),
            "criteria": _NEXT_ACTION_CRITERIA,
        }

    return "\n".join(sections), questions


def _evaluate_batch(
    batch: list[Any],
    timeout: float,
) -> tuple[bool, list[dict[str, Any]]]:
    """Evaluates a batch of up to 15 events in a single Decision 1 RPC.

    Returns ``(enabled, per_event_results)``.
    """
    input_text, questions = _build_batch_payload(batch)
    result = evaluate_decisions(
        input_text=input_text,
        questions=questions,
        timeout=timeout,
    )
    if not result.get("enabled", False):
        return False, []
    if "error" in result:
        return True, [{"error": result["error"]} for _ in batch]

    answers = result.get("answers") or {}
    parsed: list[dict[str, Any]] = []
    for idx in range(len(batch)):
        tag = f"e{idx}"
        tp_ans = answers.get(f"{tag}_tp") or {}
        severity_ans = answers.get(f"{tag}_sev") or {}
        tactic_ans = answers.get(f"{tag}_tactic") or {}
        action_ans = answers.get(f"{tag}_next") or {}

        raw_severity = float(severity_ans.get("score", 0.0))
        shifted_severity = round(raw_severity + 1.0, 4)
        severity_level = min(5, max(1, round(raw_severity) + 1))
        tp_prob = float(tp_ans.get("noul", 0.0))

        parsed.append(
            {
                "true_positive_probability": round(tp_prob, 4),
                "severity": severity_level,
                "severity_score": shifted_severity,
                "mitre_tactic": tactic_ans.get("choice", "other_or_benign"),
                "next_action": action_ans.get("choice", "enrich_cti"),
            }
        )
    return True, parsed


def _extract_event_list(
    tool_response: dict[str, Any],
) -> tuple[str, list[Any], str | None, dict[str, Any] | None]:
    """Locates the event/alert list in direct or MCP-wrapped tool responses.

    Returns ``(container_mode, items, list_key, parsed_mcp_dict)`` where
    ``container_mode`` is ``"direct"``, ``"structured"``, ``"mcp_text_dict"``,
    ``"mcp_text_list"``, or ``""`` when no list is present.
    """
    for key in _EVENT_LIST_KEYS:
        val = tool_response.get(key)
        if isinstance(val, list):
            return ("direct", val, key, None)

    structured = tool_response.get("structuredContent")
    if isinstance(structured, dict):
        for key in _EVENT_LIST_KEYS:
            val = structured.get(key)
            if isinstance(val, list):
                return ("structured", val, key, None)

    content = tool_response.get("content")
    if isinstance(content, list) and content:
        first = content[0]
        if isinstance(first, dict) and first.get("type") == "text":
            text = first.get("text", "")
            if isinstance(text, str):
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError:
                    return ("", [], None, None)
                if isinstance(parsed, list):
                    return ("mcp_text_list", parsed, None, None)
                if isinstance(parsed, dict):
                    for key in _EVENT_LIST_KEYS:
                        val = parsed.get(key)
                        if isinstance(val, list):
                            return ("mcp_text_dict", val, key, parsed)

    return ("", [], None, None)


def _inject_current_utc_time_callback(
    callback_context: Any,
    llm_request: Any,
) -> None:
    """Injects `[CURRENT_UTC_TIME]` so relative queries use the live clock."""
    del callback_context
    now_utc = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if hasattr(llm_request, "append_instructions"):
        llm_request.append_instructions([f"[CURRENT_UTC_TIME] {now_utc}"])
    return None


def _cap_udm_search_args(
    tool: Any,
    args: dict[str, Any],
    tool_context: Any,
) -> dict[str, Any] | None:
    """Clamps `udm_search` `maxEvents` to 25 and caps calls per invocation at 2."""
    if getattr(tool, "name", "") != "udm_search":
        return None

    if isinstance(args, dict):
        args.pop("limit", None)
        raw_max = args.get("maxEvents")
        if isinstance(raw_max, int) and not isinstance(raw_max, bool):
            args["maxEvents"] = min(max(1, raw_max), _MAX_UDM_SEARCH_LIMIT)
        else:
            args["maxEvents"] = _MAX_UDM_SEARCH_LIMIT

    state = getattr(tool_context, "state", None)
    if state is not None:
        invocation_id = getattr(tool_context, "invocation_id", "default")
        state_key = f"_udm_search_count_{invocation_id}"
        count = int(state.get(state_key, 0))
        if count >= _MAX_UDM_SEARCH_CALLS:
            return {
                "search_capped": True,
                "message": (
                    f"Reached the per-turn cap of {_MAX_UDM_SEARCH_CALLS} "
                    "udm_search calls. Synthesize your findings concisely from "
                    "the events already retrieved."
                ),
            }
        state[state_key] = count + 1

    return None


def _attach_triage_metadata(item: Any, triage: dict[str, Any]) -> Any:
    """Attaches `decision1_triage` metadata and escalation tag to an item."""
    if isinstance(item, dict):
        updated = dict(item)
        updated["decision1_triage"] = triage
        return updated
    return {"event": item, "decision1_triage": triage}


def _filter_udm_events_after_tool_callback(
    tool: Any,
    args: dict[str, Any],
    tool_context: Any,
    tool_response: dict[str, Any],
) -> dict[str, Any] | None:
    """Filters `udm_search` and `list_security_alerts` output with Decision 1.

    Evaluates up to 60 events in batches of 15 within a 15-second budget.
    Drops benign noise (`P(true_positive) < 0.30`) before `threat_hunter_llm`
    processes the tool response, attaches `decision1_triage` metadata to kept
    events (`0.30 <= P(true_positive) < 0.85`), tags high-confidence threats
    (`P(true_positive) >= 0.85`) with `[HIGH_CONFIDENCE_ESCALATE]`, and passes
    through any overflow events beyond the cap or time budget.
    """
    del args, tool_context
    tool_name = getattr(tool, "name", "")
    if tool_name not in _FILTERED_TOOLS:
        return None
    if not isinstance(tool_response, dict):
        return None
    if tool_response.get("isError") is True or "error" in tool_response:
        return None

    mode, items, list_key, parsed_mcp_dict = _extract_event_list(tool_response)
    if not mode or not items:
        return None

    to_evaluate = items[:_MAX_FILTER_EVENTS]
    overflow_items = items[_MAX_FILTER_EVENTS:]

    kept_items: list[Any] = []
    dropped_low_signal_count = 0
    high_confidence_escalate_count = 0
    passthrough_overflow_count = len(overflow_items)

    deadline = time.monotonic() + _CALLBACK_BUDGET_SECONDS

    for offset in range(0, len(to_evaluate), _BATCH_SIZE):
        batch = to_evaluate[offset : offset + _BATCH_SIZE]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            remaining_items = to_evaluate[offset:]
            kept_items.extend(remaining_items)
            passthrough_overflow_count += len(remaining_items)
            break

        enabled, evaluations = _evaluate_batch(batch, timeout=remaining)
        if not enabled:
            return None

        for item, ev in zip(batch, evaluations, strict=True):
            if "error" in ev:
                kept_items.append(_attach_triage_metadata(item, {"error": ev["error"]}))
                continue

            tp_prob = ev["true_positive_probability"]
            if tp_prob < _DROP_THRESHOLD:
                dropped_low_signal_count += 1
                continue

            triage_meta: dict[str, Any] = {
                "true_positive_probability": tp_prob,
                "severity": ev["severity"],
                "severity_score": ev["severity_score"],
                "mitre_tactic": ev["mitre_tactic"],
                "next_action": ev["next_action"],
            }
            if tp_prob >= _ESCALATE_THRESHOLD:
                triage_meta["tag"] = "[HIGH_CONFIDENCE_ESCALATE]"
                high_confidence_escalate_count += 1

            kept_items.append(_attach_triage_metadata(item, triage_meta))

    kept_items.extend(overflow_items)

    summary_fields = {
        "decision1_filter_applied": True,
        "dropped_low_signal_count": dropped_low_signal_count,
        "kept_event_count": len(kept_items),
        "high_confidence_escalate_count": high_confidence_escalate_count,
        "passthrough_overflow_count": passthrough_overflow_count,
    }

    updated_response = dict(tool_response)
    updated_response.update(summary_fields)

    if mode == "direct" and list_key is not None:
        updated_response[list_key] = kept_items
    elif mode == "structured" and list_key is not None:
        structured = dict(updated_response["structuredContent"])
        structured[list_key] = kept_items
        structured.update(summary_fields)
        updated_response["structuredContent"] = structured
    elif (
        mode == "mcp_text_dict" and list_key is not None and parsed_mcp_dict is not None
    ):
        updated_payload = dict(parsed_mcp_dict)
        updated_payload[list_key] = kept_items
        updated_payload.update(summary_fields)
        updated_content = [dict(c) for c in updated_response["content"]]
        updated_content[0]["text"] = json.dumps(updated_payload)
        updated_response["content"] = updated_content
    elif mode == "mcp_text_list":
        updated_payload = {"events": kept_items, **summary_fields}
        updated_content = [dict(c) for c in updated_response["content"]]
        updated_content[0]["text"] = json.dumps(updated_payload)
        updated_response["content"] = updated_content

    return updated_response
