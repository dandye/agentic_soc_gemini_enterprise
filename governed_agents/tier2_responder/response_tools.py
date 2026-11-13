"""Endpoint and identity containment tools for the Tier-2 Incident Responder.

Omit `from __future__ import annotations` in this module so ADK's function
schema introspection sees concrete parameter types at runtime.

Notice that NEITHER function blocks Tier-0 Domain Controllers (`DC-*`) or
privileged directory accounts (`admin@*`) in Python code. That policy lives
outside the container in Vertex AI Semantic Governance (`65-semantic-governance.tf`),
which inspects the proposed tool call on `:generateContent` at the Agent Gateway
and blocks unauthorized Tier-0 containment before the function can execute.
"""

from datetime import UTC, datetime
from typing import Any

from decision_client import decide


_CONTAINMENT_READINESS_QUESTIONS: dict[str, dict[str, Any]] = {
    "asset_tier": {
        "type": "choice",
        "instructions": (
            "Classify the target asset or identity tier for this containment "
            "request."
        ),
        "criteria": {
            "workstation": (
                "Standard end-user workstation, laptop, or client endpoint "
                "(for example WKSTN-* or standard user account)."
            ),
            "server": (
                "Standard application, file, database, or member server "
                "(for example SRV-* or APP-*) that is not Tier-0 identity "
                "infrastructure."
            ),
            "tier0_crown_jewel": (
                "Tier-0 Crown Jewel identity or infrastructure asset such as "
                "Domain Controllers (DC-*, PROD-DC-*), root certificate "
                "authorities, identity providers, or privileged directory "
                "accounts (admin@*, krbtgt)."
            ),
            "unknown": (
                "Target naming and context are insufficient to determine the "
                "asset tier."
            ),
        },
    },
    "evidence_sufficiency": {
        "type": "score",
        "instructions": (
            "Score how sufficient the incident evidence summary is to justify "
            "the proposed containment action."
        ),
        "criteria": [
            "No verifiable alert, indicator, or compromise evidence provided.",
            "Weak or circumstantial indicator only without corroborating telemetry.",
            "Moderate single-source alert or indicator match needing more context.",
            "Strong corroborated detection or confirmed malicious activity.",
            "High-confidence confirmed compromise with explicit alert, indicator, and attribution.",
        ],
    },
    "has_change_ticket": {
        "type": "noul",
        "instructions": (
            "Does the containment request include a valid emergency "
            "change-control ticket ID matching CHG-<digits>?"
        ),
    },
    "requires_human_approval": {
        "type": "noul",
        "instructions": (
            "Does this containment action require human change-control "
            "approval before execution, such as Tier-0 Crown Jewel "
            "infrastructure or privileged directory accounts without an "
            "emergency CHG- ticket?"
        ),
    },
}


def assess_containment_readiness(
    target: str,
    action_type: str,
    evidence_summary: str,
    change_ticket: str = "",
) -> dict[str, Any]:
    """Scores containment readiness using `gemini-decision-1` as advisory metadata.

    Strictly advisory: never blocks containment execution in Python. Agent
    Gateway Semantic Governance remains the authoritative enforcement point.

    Args:
        target: Target hostname, identity, or indicator (for example `DC-PROD-01`).
        action_type: Proposed containment action (for example
            `isolate_endpoint_host`, `disable_compromised_account`, or
            `block_malicious_ioc`).
        evidence_summary: Concise summary of alerts, indicators, and telemetry.
        change_ticket: Optional emergency change-control ticket ID (such as
            `CHG-20261105`).
    """
    normalized_target = target.strip()
    normalized_action = action_type.strip()
    normalized_evidence = evidence_summary.strip()
    normalized_ticket = change_ticket.strip()

    input_text = (
        f"Proposed Containment Action: {normalized_action}\n"
        f"Target: {normalized_target}\n"
        f"Change Ticket: {normalized_ticket or 'NONE'}\n"
        f"Evidence Summary: {normalized_evidence}"
    )

    decision = decide(input_text, _CONTAINMENT_READINESS_QUESTIONS)
    base_result: dict[str, Any] = {
        "action": "assess_containment_readiness",
        "advisory_only": True,
        "target": normalized_target,
        "action_type": normalized_action,
        "change_ticket": normalized_ticket or None,
        "assessed_at_utc": datetime.now(UTC).isoformat(),
        "enforcement_note": (
            "Advisory metadata only. Agent Gateway Semantic Governance "
            "enforces containment policy."
        ),
    }

    if not decision.get("enabled"):
        return {
            **base_result,
            "decision_model_enabled": False,
            "reason": decision.get("reason", "Decisions API not configured."),
        }

    if "error" in decision:
        return {
            **base_result,
            "decision_model_enabled": True,
            "error": decision["error"],
        }

    answers = decision.get("answers") or {}
    tier_ans = answers.get("asset_tier") or {}
    evidence_ans = answers.get("evidence_sufficiency") or {}
    ticket_ans = answers.get("has_change_ticket") or {}
    approval_ans = answers.get("requires_human_approval") or {}

    raw_score = evidence_ans.get("score")
    shifted_score = round(float(raw_score) + 1.0, 2) if raw_score is not None else None

    return {
        **base_result,
        "decision_model_enabled": True,
        "model": decision.get("model", "gemini-decision-1"),
        "asset_tier": tier_ans.get("choice", "unknown"),
        "asset_tier_confidence": tier_ans.get("confidence"),
        "evidence_sufficiency_score": shifted_score,
        "evidence_sufficiency_confidence": evidence_ans.get("confidence"),
        "has_change_ticket_noul": ticket_ans.get("noul"),
        "requires_human_approval_noul": approval_ans.get("noul"),
        "usage": decision.get("usage", {}),
    }


def isolate_endpoint_host(
    hostname: str,
    reason: str,
    change_ticket: str = "",
) -> dict[str, Any]:
    """Quarantines an endpoint host at the EDR network boundary.

    Args:
        hostname: Target endpoint hostname (for example `WKSTN-FIN-042` or `DC-PROD-01`).
        reason: Verified incident justification and alert/IOC reference.
        change_ticket: Optional emergency change-control ticket ID (such as `CHG-20261105`).
    """
    normalized_host = hostname.strip()
    ticket = change_ticket.strip()
    return {
        "action": "isolate_endpoint_host",
        "status": "ISOLATED",
        "hostname": normalized_host,
        "reason": reason.strip(),
        "change_ticket": ticket or None,
        "edr_policy": "NETWORK_QUARANTINE_STRICT",
        "executed_at_utc": datetime.now(UTC).isoformat(),
    }


def disable_compromised_account(
    username: str,
    reason: str,
    change_ticket: str = "",
) -> dict[str, Any]:
    """Disables a user or service identity and revokes active OAuth/SSO sessions.

    Args:
        username: Target identity email or SAMAccountName (for example `jdoe@example.com`).
        reason: Verified compromise evidence and incident reference.
        change_ticket: Optional emergency change-control ticket ID (such as `CHG-20261105`).
    """
    normalized_user = username.strip()
    ticket = change_ticket.strip()
    return {
        "action": "disable_compromised_account",
        "status": "DISABLED_AND_SESSIONS_REVOKED",
        "username": normalized_user,
        "reason": reason.strip(),
        "change_ticket": ticket or None,
        "executed_at_utc": datetime.now(UTC).isoformat(),
    }
