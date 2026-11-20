"""Agent-callable operational decision tools using GLiNER2.5-Decide.

Exposes fast, deterministic multi-head zero-shot classification tools
for Tier 1 alert triage, specialist agent routing, HITL gatekeeping,
and CTI advisory filtering.
"""

from typing import Any, Dict
from agent_soc_manager.tools.gliner_decide_engine import GLiNERDecideEngine
from agent_soc_manager.tools.gliner_decide_schemas import (
    ALERT_TRIAGE_SCHEMA,
    CTI_APPLICABILITY_SCHEMA,
    HITL_POLICY_GATE_SCHEMA,
    SPECIALIST_ROUTING_SCHEMA,
)


def triage_alert_with_gliner(alert_text: str) -> Dict[str, Any]:
  """Evaluates severity, urgency tier, and initial disposition hypothesis for a security alert.

  Executes a single forward pass without prompt engineering or token
  generation.

  Args:
      alert_text: Raw alert text, syslog payload, or UDM event summary.

  Returns:
      Dict containing 'severity', 'urgency_tier', and 'disposition_hypothesis'.
  """
  engine = GLiNERDecideEngine.get_instance()
  return engine.decide(alert_text, ALERT_TRIAGE_SCHEMA)


def route_case_to_specialist_with_gliner(case_summary: str) -> Dict[str, Any]:
  """Routes an investigation or security alert to the appropriate SOC specialist sub-agent.

  Args:
      case_summary: Summary of the alert, investigation findings, or evidence.

  Returns:
      Dict containing 'assigned_specialist' ('tier2_investigator',
      'threat_hunter', 'cti_researcher', or 'detection_engineer').
  """
  engine = GLiNERDecideEngine.get_instance()
  return engine.decide(case_summary, SPECIALIST_ROUTING_SCHEMA)


def evaluate_hitl_gate_with_gliner(
    proposed_action: str, context: str = ""
) -> Dict[str, Any]:
  """Evaluates whether an action requires human manager approval.

  Also determines whether investigation state is complete before executing
  potentially destructive mitigations.

  Args:
      proposed_action: The action the agent intends to execute (e.g. revoke
        creds, isolate host).
      context: Additional context or justification.

  Returns:
      Dict containing 'requires_human_approval' and 'agent_completion_status'.
  """
  full_prompt = (
      f"Proposed Action: {proposed_action}\nContext: {context}"
      if context
      else proposed_action
  )
  engine = GLiNERDecideEngine.get_instance()
  return engine.decide(full_prompt, HITL_POLICY_GATE_SCHEMA)


def filter_cti_advisory_with_gliner(advisory_text: str) -> Dict[str, Any]:
  """Filters unstructured CTI advisories for enterprise platform relevance and threat category.

  Args:
      advisory_text: Title and content/abstract of a threat advisory or CISA
        alert.

  Returns:
      Dict containing 'enterprise_relevance' and 'target_platform'.
  """
  engine = GLiNERDecideEngine.get_instance()
  return engine.decide(advisory_text, CTI_APPLICABILITY_SCHEMA)
