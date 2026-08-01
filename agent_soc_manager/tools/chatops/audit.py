"""Structured audit events for the ChatOps approval lifecycle (issue #84).

Every state transition of a human approval emits one single-line JSON
event to the standard logging stream. On Cloud Run these land in Cloud
Logging, where a one-command sink exports them to BigQuery for durable,
queryable, append-only evidence (see docs/chatops_chat_app.md, Audit
trail).

Design rules:
- Emission NEVER raises into the request path; a broken payload degrades
  to a minimal error event.
- The RAW action string is logged (logs are inert evidence; the raw value
  is how an auditor detects parse failures and injection attempts). Only
  the session-injected copy is sanitized -- see decision.py.
- Schema is versioned; bump SCHEMA_VERSION on any field change.
"""

import json
import logging
import uuid
from datetime import UTC, datetime


AUDIT_MARKER = "CHATOPS_AUDIT"
SCHEMA_VERSION = 1

# Lifecycle stages, in nominal order:
#   click_accepted, click_rejected_invalid_token,
#   click_rejected_unauthorized, enqueued, enqueue_deduped,
#   enqueue_failed, worker_start, decision_injected, outcome_success,
#   outcome_failure, outcome_timeout, legacy_action_executed,
#   legacy_action_failed

logger = logging.getLogger("chatops.audit")


def emit_audit_event(
    stage: str,
    action: str | None = None,
    decision: str | None = None,
    approver: str | None = None,
    approver_email: str | None = None,
    session_id: str | None = None,
    agent_engine_id: str | None = None,
    message_name: str | None = None,
    outcome: str | None = None,
    detail: str | None = None,
) -> None:
    """Emits one audit event. Never raises."""
    try:
        event = {
            "marker": AUDIT_MARKER,
            "schema_version": SCHEMA_VERSION,
            "event_id": str(uuid.uuid4()),
            "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
            "stage": stage,
            "action": action,
            "decision": decision,
            "approver": approver,
            "approver_email": approver_email,
            "session_id": session_id,
            "agent_engine_id": agent_engine_id,
            "message_name": message_name,
            "outcome": outcome,
            "detail": detail,
        }
        line = json.dumps(
            {k: v for k, v in event.items() if v is not None}, default=str
        )
    except Exception as e:  # pragma: no cover - defensive
        line = json.dumps(
            {
                "marker": AUDIT_MARKER,
                "schema_version": SCHEMA_VERSION,
                "stage": "audit_emit_error",
                "detail": str(e),
            }
        )
    # warning level so default Cloud Run log filters never drop the trail
    logger.warning(line)
