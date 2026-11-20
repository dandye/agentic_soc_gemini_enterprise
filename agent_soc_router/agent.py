"""SecOps GLiNER Decision Router Agent.

ADK agent integrating GLiNER2.5-Decide multi-head zero-shot operational
classification tools for rapid alert triage, specialist dispatch, and
Human-in-the-Loop (HITL) gatekeeping.
"""

from typing import Any, Dict
from google.adk.agents import Agent
from agent_soc_manager.tools.gliner_decide_tools import (
    evaluate_hitl_gate_with_gliner,
    filter_cti_advisory_with_gliner,
    route_case_to_specialist_with_gliner,
    triage_alert_with_gliner,
)


def lookup_ip_reputation(ip_address: str) -> Dict[str, Any]:
  """Look up threat intelligence reputation for an IP address.

  Args:
      ip_address: IPv4 or IPv6 address to query.

  Returns:
      Dictionary containing threat score, categorization, and verdict.
  """
  if ip_address in ["198.51.100.14", "203.0.113.50", "198.51.100.44"]:
    return {
        "ip": ip_address,
        "reputation": "MALICIOUS",
        "threat_score": 95,
        "threat_actor": "APT29",
        "category": "Command and Control",
        "verdict": "Confirmed malicious C2 node",
    }
  elif ip_address.startswith("192.0.2.") or ip_address.startswith("198.51.100."):
    return {
        "ip": ip_address,
        "reputation": "BENIGN_TEST_RANGE",
        "threat_score": 0,
        "category": "RFC 5737 Documentation / Test Network",
        "verdict": "Benign documentation test range",
    }
  return {
      "ip": ip_address,
      "reputation": "UNKNOWN",
      "threat_score": 10,
      "verdict": "No active threat indicators observed",
  }


def check_host_isolation_status(hostname: str) -> Dict[str, Any]:
  """Check whether an endpoint is currently isolated from the corporate network.

  Args:
      hostname: The hostname of the endpoint to check.

  Returns:
      Dictionary with isolation status, agent connectivity, and timestamp.
  """
  return {
      "hostname": hostname,
      "isolated": False,
      "status": "Online / Connected",
      "last_seen": "2026-09-25T20:00:00Z",
  }


def request_containment_approval(hostname: str, reason: str) -> Dict[str, Any]:
  """Request Human-in-the-Loop (HITL) approval prior to host network isolation.

  Args:
      hostname: Target endpoint hostname to isolate.
      reason: Justification and incident context for containment.

  Returns:
      Approval request ticket ID and pending review status.
  """
  return {
      "ticket_id": "APPROVAL-GLINER-8812",
      "hostname": hostname,
      "action": "NETWORK_ISOLATION",
      "status": "PENDING_ANALYST_CONFIRMATION",
      "blast_radius": "Local endpoint network disconnect; maintains EDR telemetry channel",
      "message": (
          f"Containment request for {hostname} submitted. Awaiting human analyst"
          " authorization."
      ),
  }


SYSTEM_INSTRUCTION = """
You are the SecOps Operational Decision & Routing Specialist Agent.
Your responsibility is to rapidly triage incoming security events, evaluate Human-in-the-Loop policy gates, and route cases to the correct specialist sub-agent using GLiNER2.5-Decide operational classification tools.

Standard Operating Procedures:
1. Operational Alert Triage:
   - For incoming alerts, run triage_alert_with_gliner to obtain deterministic, sub-50ms evaluations for severity, urgency tier, and initial disposition hypothesis.
   - If IP indicators are present, corroborate with lookup_ip_reputation.
   - If the alert is an RFC-5737 documentation test or benign scanner traffic, flag it as false positive/backlog and avoid disruptive actions.

2. Specialist Sub-Agent Routing:
   - Use route_case_to_specialist_with_gliner to assign the incident to the appropriate specialist:
     * tier2_investigator: Lateral movement, persistence, multi-stage attacks.
     * threat_hunter: DNS tunneling, Shannon entropy anomalies, beaconing, prevalence sweeps.
     * cti_researcher: Unstructured threat advisories, CISA alerts, campaign attribution.
     * detection_engineer: Noisy YARA-L rules, parser errors, coverage gaps.

3. Human-in-the-Loop (HITL) Policy Gatekeeping:
   - Before recommending or executing any high-impact action (such as credential revocation or host isolation), run evaluate_hitl_gate_with_gliner to determine if human manager approval is required.
   - When human approval is required, submit an authorization request via request_containment_approval.

4. CTI Advisory Ingestion Gating:
   - When processing external threat reports, run filter_cti_advisory_with_gliner to evaluate enterprise platform relevance (e.g. GCP, Kubernetes) and threat category.

Structure your final response clearly with:
- Operational Decision Summary (Severity, Urgency, Disposition from GLiNER)
- Threat Intelligence Findings & Indicator Analysis
- Policy Gate & HITL Compliance Evaluation
- Assigned Specialist & Dispatch Recommendation
"""


def create_agent(model_name: str = "gemini-2.5-flash") -> Agent:
  """Instantiates and returns the configured SecOps GLiNER Decision Router Agent."""
  return Agent(
      name="soc_decision_router",
      model=model_name,
      instruction=SYSTEM_INSTRUCTION,
      tools=[
          triage_alert_with_gliner,
          route_case_to_specialist_with_gliner,
          evaluate_hitl_gate_with_gliner,
          filter_cti_advisory_with_gliner,
          lookup_ip_reputation,
          check_host_isolation_status,
          request_containment_approval,
      ],
  )


root_agent = create_agent()
