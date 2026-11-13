"""Decision 1 pre-LLM UDM and alert noise-filtering callback for Threat Hunter.

Evaluates individual Chronicle SIEM UDM events or security alerts returned by
`udm_search` and `list_security_alerts` inside an ADK `after_tool_callback`
before `threat_hunter_llm` sees the payload:
  * P(true_positive) < 0.30: dropped and counted in `dropped_low_signal_count`
  * 0.30 <= P(true_positive) < 0.85: kept with `decision1_triage` metadata
  * P(true_positive) >= 0.85: kept and tagged `[HIGH_CONFIDENCE_ESCALATE]`
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
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
_MAX_WORKERS = 8

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

_EVENT_TRIAGE_QUESTIONS: dict[str, dict[str, Any]] = {
    "severity": {
        "type": "score",
        "instructions": (
            "Score the overall security severity of this Chronicle SIEM alert or UDM event."
        ),
        "criteria": _SEVERITY_CRITERIA,
    },
    "true_positive": {
        "type": "noul",
        "instructions": (
            "Determine whether this alert or UDM event represents a true positive "
            "security threat rather than benign administrative activity or a false positive."
        ),
    },
    "mitre_tactic": {
        "type": "choice",
        "instructions": (
            "Select the primary MITRE ATT&CK tactic represented by this alert or UDM event."
        ),
        "criteria": _MITRE_TACTIC_CRITERIA,
    },
    "next_action": {
        "type": "choice",
        "instructions": (
            "Select the recommended next SOC triage action for this alert or UDM event."
        ),
        "criteria": _NEXT_ACTION_CRITERIA,
    },
}


def _evaluate_single_event(item: Any) -> dict[str, Any]:
    """Evaluates one UDM event or alert via Decision 1 without truncation."""
    serialized = (
        json.dumps(item, indent=2, sort_keys=True)
        if not isinstance(item, str)
        else item
    )
    input_text = (
        "Evaluate the following Chronicle SIEM UDM event or security alert:\n\n"
        f"{serialized}"
    )
    result = evaluate_decisions(
        input_text=input_text,
        questions=_EVENT_TRIAGE_QUESTIONS,
    )
    if not result.get("enabled", False):
        return {"enabled": False}
    if "error" in result:
        return {"enabled": True, "error": result["error"]}

    answers = result.get("answers") or {}
    severity_ans = answers.get("severity") or {}
    raw_severity = float(severity_ans.get("score", 0.0))
    shifted_severity = round(raw_severity + 1.0, 4)
    severity_level = min(5, max(1, round(raw_severity) + 1))

    tp_ans = answers.get("true_positive") or {}
    tp_prob = float(tp_ans.get("noul", 0.0))

    tactic_ans = answers.get("mitre_tactic") or {}
    action_ans = answers.get("next_action") or {}

    return {
        "enabled": True,
        "true_positive_probability": round(tp_prob, 4),
        "severity": severity_level,
        "severity_score": shifted_severity,
        "mitre_tactic": tactic_ans.get("choice", "other_or_benign"),
        "next_action": action_ans.get("choice", "enrich_cti"),
    }


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

    Drops benign noise (`P(true_positive) < 0.30`) before `threat_hunter_llm`
    processes the tool response, attaches `decision1_triage` metadata to kept
    events (`0.30 <= P(true_positive) < 0.85`), and tags high-confidence threats
    (`P(true_positive) >= 0.85`) with `[HIGH_CONFIDENCE_ESCALATE]`.
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

    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(items))) as pool:
        evaluations = list(pool.map(_evaluate_single_event, items))

    if any(not ev.get("enabled", False) for ev in evaluations):
        return None

    kept_items: list[Any] = []
    dropped_low_signal_count = 0
    high_confidence_escalate_count = 0

    for item, ev in zip(items, evaluations, strict=True):
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

    summary_fields = {
        "decision1_filter_applied": True,
        "dropped_low_signal_count": dropped_low_signal_count,
        "kept_event_count": len(kept_items),
        "high_confidence_escalate_count": high_confidence_escalate_count,
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
