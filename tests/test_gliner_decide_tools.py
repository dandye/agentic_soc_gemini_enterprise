"""Unit tests for agent-callable GLiNER operational decision tools."""

from unittest.mock import patch
from agent_soc_manager.tools.gliner_decide_tools import (
    evaluate_hitl_gate_with_gliner,
    filter_cti_advisory_with_gliner,
    route_case_to_specialist_with_gliner,
    triage_alert_with_gliner,
)


@patch("agent_soc_manager.tools.gliner_decide_engine.GLiNERDecideEngine.decide")
def test_triage_alert_tool(mock_decide):
  mock_decide.return_value = {
      "severity": "critical",
      "urgency_tier": "p1_immediate_containment",
      "disposition_hypothesis": "true_positive_malicious",
  }
  res = triage_alert_with_gliner(
      "Ransomware payload executing on domain controller"
  )
  assert res["severity"] == "critical"
  assert res["urgency_tier"] == "p1_immediate_containment"
  assert res["disposition_hypothesis"] == "true_positive_malicious"
  assert mock_decide.called


@patch("agent_soc_manager.tools.gliner_decide_engine.GLiNERDecideEngine.decide")
def test_route_specialist_tool(mock_decide):
  mock_decide.return_value = {"assigned_specialist": "threat_hunter"}
  res = route_case_to_specialist_with_gliner(
      "Periodic DGA beaconing across network edge"
  )
  assert res["assigned_specialist"] == "threat_hunter"
  assert mock_decide.called


@patch("agent_soc_manager.tools.gliner_decide_engine.GLiNERDecideEngine.decide")
def test_hitl_gate_tool(mock_decide):
  mock_decide.return_value = {
      "requires_human_approval": "requires_soc_manager_approval",
      "agent_completion_status": "investigation_complete",
  }
  res = evaluate_hitl_gate_with_gliner(
      "Revoke IAM service account credentials across org", "High blast radius"
  )
  assert res["requires_human_approval"] == "requires_soc_manager_approval"
  assert res["agent_completion_status"] == "investigation_complete"
  assert mock_decide.called


@patch("agent_soc_manager.tools.gliner_decide_engine.GLiNERDecideEngine.decide")
def test_filter_cti_tool(mock_decide):
  mock_decide.return_value = {
      "enterprise_relevance": "actionable_threat_advisory",
      "target_platform": "gcp_cloud",
  }
  res = filter_cti_advisory_with_gliner(
      "CISA Alert: Active exploitation of Kubernetes API vulnerability"
  )
  assert res["enterprise_relevance"] == "actionable_threat_advisory"
  assert res["target_platform"] == "gcp_cloud"
  assert mock_decide.called
