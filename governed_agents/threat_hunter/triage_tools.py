"""Decision 1 rubric triage tools for the Chronicle SIEM Threat Hunter agent."""

from __future__ import annotations

import json
from typing import Any

from decision_client import evaluate_decisions


_MAX_INPUT_CHARS = 32000

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
        "Noisy or overly broad Chronicle SIEM YARA-L 2.0 detection rule; send to Detection Engineering for tuning."
    ),
}

_ALERT_TRIAGE_QUESTIONS: dict[str, dict[str, Any]] = {
    "severity": {
        "type": "score",
        "instructions": (
            "Score the overall security severity of this Chronicle SIEM alert or UDM event batch."
        ),
        "criteria": _SEVERITY_CRITERIA,
    },
    "true_positive": {
        "type": "noul",
        "instructions": (
            "Determine whether this alert or UDM event batch represents a true positive "
            "security threat rather than benign administrative activity or a false positive."
        ),
    },
    "mitre_tactic": {
        "type": "choice",
        "instructions": (
            "Select the primary MITRE ATT&CK tactic represented by this alert or UDM event batch."
        ),
        "criteria": _MITRE_TACTIC_CRITERIA,
    },
    "next_action": {
        "type": "choice",
        "instructions": (
            "Select the recommended next SOC triage action for this alert or UDM event batch."
        ),
        "criteria": _NEXT_ACTION_CRITERIA,
    },
}


def _normalize_alerts_input(alerts_json: str) -> str:
    """Normalizes alert/UDM JSON or text into a bounded prompt input string."""
    stripped = alerts_json.strip()
    try:
        parsed = json.loads(stripped)
        formatted = json.dumps(parsed, indent=2, sort_keys=True)
    except json.JSONDecodeError:
        formatted = stripped
    if len(formatted) > _MAX_INPUT_CHARS:
        return formatted[:_MAX_INPUT_CHARS]
    return formatted


def score_alerts_rubric(alerts_json: str) -> dict[str, Any]:
    """Evaluates Chronicle SIEM alerts or UDM events in a single Decision 1 pass.

    Returns a structured rubric with:
      * ``severity_score`` (1.0-5.0, shifted from 0-indexed Decision 1 ``score``)
      * ``severity_level`` (integer 1-5)
      * ``true_positive`` (probability and boolean verdict from ``noul``)
      * ``mitre_tactic`` (selected MITRE ATT&CK tactic ``choice``)
      * ``next_action`` (``dismiss``, ``enrich_cti``, ``escalate_tier2``, or ``tune_yaral2``)
    """
    if not isinstance(alerts_json, str) or not alerts_json.strip():
        return {
            "error": "alerts_json must be a non-empty JSON string or alert summary."
        }

    input_text = (
        "Evaluate the following Chronicle SIEM security alerts or UDM events:\n\n"
        f"{_normalize_alerts_input(alerts_json)}"
    )
    result = evaluate_decisions(
        input_text=input_text,
        questions=_ALERT_TRIAGE_QUESTIONS,
    )

    if not result.get("enabled", False):
        return {
            "enabled": False,
            "reason": result.get("reason", "Gemini Decision 1 is not configured."),
        }

    if "error" in result:
        return {
            "enabled": True,
            "error": result["error"],
        }

    answers = result.get("answers") or {}
    severity_ans = answers.get("severity") or {}
    raw_severity = float(severity_ans.get("score", 0.0))
    shifted_severity = round(raw_severity + 1.0, 4)
    severity_level = min(5, max(1, round(raw_severity) + 1))

    tp_ans = answers.get("true_positive") or {}
    tp_score = float(tp_ans.get("noul", 0.0))

    tactic_ans = answers.get("mitre_tactic") or {}
    action_ans = answers.get("next_action") or {}

    return {
        "enabled": True,
        "severity_score": shifted_severity,
        "severity_level": severity_level,
        "true_positive": {
            "likely": tp_score >= 0.5,
            "score": round(tp_score, 4),
            "confidence": round(float(tp_ans.get("confidence", 0.0)), 4),
        },
        "mitre_tactic": tactic_ans.get("choice", "other_or_benign"),
        "next_action": action_ans.get("choice", "enrich_cti"),
        "details": {
            "severity_confidence": round(float(severity_ans.get("confidence", 0.0)), 4),
            "mitre_tactic_confidence": round(
                float(tactic_ans.get("confidence", 0.0)), 4
            ),
            "next_action_confidence": round(
                float(action_ans.get("confidence", 0.0)), 4
            ),
        },
        "usage": result.get("usage") or {},
    }
