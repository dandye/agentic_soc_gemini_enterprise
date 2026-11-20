"""Standardized decision schemas for GLiNER2.5-Decide in Agentic SOC."""

from typing import Any, Dict

ALERT_TRIAGE_SCHEMA: Dict[str, Any] = {
    "severity": [
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    ],
    "urgency_tier": [
        "p1_immediate_containment",
        "p2_same_shift_triage",
        "p3_investigative_backlog",
    ],
    "disposition_hypothesis": [
        "true_positive_malicious",
        "benign_scanner_traffic",
        "rfc5737_test_artifact",
        "known_false_positive",
    ],
}

SPECIALIST_ROUTING_SCHEMA: Dict[str, Any] = {
    "assigned_specialist": [
        "tier2_investigator",
        "threat_hunter",
        "cti_researcher",
        "detection_engineer",
    ],
}

HITL_POLICY_GATE_SCHEMA: Dict[str, Any] = {
    "requires_human_approval": [
        "requires_soc_manager_approval",
        "safe_autonomous_investigation",
    ],
    "agent_completion_status": [
        "investigation_complete",
        "insufficient_evidence_pivot_required",
        "blocked_awaiting_telemetry",
    ],
}

CTI_APPLICABILITY_SCHEMA: Dict[str, Any] = {
    "enterprise_relevance": [
        "actionable_threat_advisory",
        "unrelated_vendor_patch",
        "general_awareness",
    ],
    "target_platform": [
        "gcp_cloud",
        "kubernetes",
        "windows_ad",
        "linux_endpoints",
        "saas_identity",
    ],
}

_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "alert_triage": ALERT_TRIAGE_SCHEMA,
    "specialist_routing": SPECIALIST_ROUTING_SCHEMA,
    "hitl_policy_gate": HITL_POLICY_GATE_SCHEMA,
    "cti_applicability": CTI_APPLICABILITY_SCHEMA,
}


def get_schema(name: str) -> Dict[str, Any]:
  """Retrieve a pre-configured schema by name."""
  if name not in _SCHEMAS:
    raise KeyError(
        f"Unknown decision schema '{name}'. Available: {list(_SCHEMAS.keys())}"
    )
  return _SCHEMAS[name]
