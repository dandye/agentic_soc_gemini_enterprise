"""
Unit tests for standardized GLiNER2.5-Decide SOC operational decision schemas.
"""

import pytest
from agent_soc_manager.tools.gliner_decide_schemas import (
    ALERT_TRIAGE_SCHEMA,
    SPECIALIST_ROUTING_SCHEMA,
    HITL_POLICY_GATE_SCHEMA,
    CTI_APPLICABILITY_SCHEMA,
    get_schema,
)


def test_alert_triage_schema_structure():
    assert "severity" in ALERT_TRIAGE_SCHEMA
    assert "critical" in ALERT_TRIAGE_SCHEMA["severity"]
    assert "high" in ALERT_TRIAGE_SCHEMA["severity"]
    assert "urgency_tier" in ALERT_TRIAGE_SCHEMA
    assert "p1_immediate_containment" in ALERT_TRIAGE_SCHEMA["urgency_tier"]
    assert "disposition_hypothesis" in ALERT_TRIAGE_SCHEMA
    assert "rfc5737_test_artifact" in ALERT_TRIAGE_SCHEMA["disposition_hypothesis"]
    assert "true_positive_malicious" in ALERT_TRIAGE_SCHEMA["disposition_hypothesis"]


def test_specialist_routing_schema_structure():
    assert "assigned_specialist" in SPECIALIST_ROUTING_SCHEMA
    specialists = SPECIALIST_ROUTING_SCHEMA["assigned_specialist"]
    assert "tier2_investigator" in specialists
    assert "threat_hunter" in specialists
    assert "cti_researcher" in specialists
    assert "detection_engineer" in specialists


def test_hitl_policy_gate_schema_structure():
    assert "requires_human_approval" in HITL_POLICY_GATE_SCHEMA
    assert "requires_soc_manager_approval" in HITL_POLICY_GATE_SCHEMA["requires_human_approval"]
    assert "safe_autonomous_investigation" in HITL_POLICY_GATE_SCHEMA["requires_human_approval"]
    assert "agent_completion_status" in HITL_POLICY_GATE_SCHEMA
    assert "investigation_complete" in HITL_POLICY_GATE_SCHEMA["agent_completion_status"]


def test_cti_applicability_schema_structure():
    assert "enterprise_relevance" in CTI_APPLICABILITY_SCHEMA
    assert "actionable_threat_advisory" in CTI_APPLICABILITY_SCHEMA["enterprise_relevance"]
    assert "target_platform" in CTI_APPLICABILITY_SCHEMA
    assert "gcp_cloud" in CTI_APPLICABILITY_SCHEMA["target_platform"]


def test_get_schema_lookup():
    assert get_schema("alert_triage") == ALERT_TRIAGE_SCHEMA
    assert get_schema("specialist_routing") == SPECIALIST_ROUTING_SCHEMA
    assert get_schema("hitl_policy_gate") == HITL_POLICY_GATE_SCHEMA
    assert get_schema("cti_applicability") == CTI_APPLICABILITY_SCHEMA


def test_get_schema_invalid():
    with pytest.raises(KeyError):
        get_schema("non_existent_schema")
