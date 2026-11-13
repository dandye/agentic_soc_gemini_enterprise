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
