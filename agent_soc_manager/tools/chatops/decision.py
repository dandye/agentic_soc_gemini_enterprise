"""Human decision semantics for ChatOps approvals (issue #83).

The signed action string is free text like "Approve Isolate Host" or
"Deny Block IP". Injecting it into the agent session as
"USER ACTION CONFIRMED via ChatOps: Deny X" made a denial read as a
confirmation. This module parses the decision once, at the injection seam,
and renders a rigid template that names the decision explicitly and never
echoes attacker-influenceable free text beyond a sanitized action name.
"""

import re


APPROVED = "APPROVED"
DENIED = "DENIED"
UNSPECIFIED = "UNSPECIFIED"

# Match the exact capitalized prefixes produced by generate_action_url call
# sites. Word boundary prevents "Denylist Host" matching as a denial;
# lowercase variants are deliberately UNSPECIFIED (they cannot have come
# from our card generators).
_DECISION_PREFIX = re.compile(r"^(Approve|Deny)\b")

# Free text is reduced to a safe charset, single-spaced, and bounded before
# it may appear (quoted) inside the session template. Control phrases that
# could impersonate system framing are redacted even though they survive
# the charset filter.
_ALLOWED_CHARS = re.compile(r"[^A-Za-z0-9 ,.:/_()\-]")
_CONTROL_PHRASES = re.compile(
    r"(?i)(confirmed|ignore\s+previous|system\s+prompt|instructions?)"
)
_MAX_ACTION_LEN = 200


def parse_decision(action: str | None) -> str:
    """Returns APPROVED, DENIED, or UNSPECIFIED from the action prefix."""
    if not action or not isinstance(action, str):
        return UNSPECIFIED
    match = _DECISION_PREFIX.match(action.strip())
    if not match:
        return UNSPECIFIED
    return APPROVED if match.group(1) == "Approve" else DENIED


def sanitize_action(action: str | None) -> str:
    """Reduces an action string to inert, single-line, bounded text.

    Audit logs keep the raw string (logs are inert evidence); only the
    session-injected copy goes through this. Do not "helpfully" reuse the
    sanitized value in audit events -- the raw value is how an auditor
    detects injection attempts.
    """
    if not action or not isinstance(action, str):
        return "(no action name)"
    text = _ALLOWED_CHARS.sub(" ", action)
    text = re.sub(r"\s+", " ", text).strip()
    text = _CONTROL_PHRASES.sub("[redacted]", text)
    if len(text) > _MAX_ACTION_LEN:
        text = text[:_MAX_ACTION_LEN] + "..."
    return text or "(no action name)"


def build_session_message(action: str | None) -> tuple[str, str]:
    """Builds the rigid session message for a human decision.

    Returns (decision, message). The template states the decision as
    structured data; DENIED explicitly forbids execution so an ambiguous
    prefix can never read as a confirmation.
    """
    decision = parse_decision(action)
    safe_action = sanitize_action(action)

    if decision == APPROVED:
        message = (
            f"HUMAN DECISION via ChatOps [decision=APPROVED] "
            f'action="{safe_action}". A human analyst approved this specific '
            "action. You may proceed with it and must record the approval in "
            "your report."
        )
    elif decision == DENIED:
        message = (
            f"HUMAN DECISION via ChatOps [decision=DENIED] "
            f'action="{safe_action}". A human analyst DENIED this action. Do '
            "NOT execute it. Record the denial in your report and choose a "
            "non-destructive alternative or continue investigating."
        )
    else:
        message = (
            f"HUMAN DECISION via ChatOps [decision=UNSPECIFIED] "
            f'action="{safe_action}". A human interacted with this request '
            "but the decision could not be determined. Do NOT execute the "
            "action. Request a fresh confirmation via "
            "request_human_confirmation before any state change."
        )
    return decision, message
