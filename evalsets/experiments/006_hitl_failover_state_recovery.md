---
type: "Evaluation Report"
title: "MLOps Experiment 006: Dynamic HITL Failover & Containment State Recovery"
description: "Proposing a robust failover architecture for Human-in-the-Loop (HITL) containment actions to prevent silent failures and ensure critical remediation commands (like host isolation) succeed even during webhook outages."
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/experiments/006_hitl_failover_state_recovery.md"
timestamp: "2026-06-17T20:26:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T20:26:00Z"
---

# MLOps Experiment 006: Dynamic HITL Failover & Containment State Recovery

## 1. Context & Problem Statement
In a production-ready AI Security Operations Center, high-stakes containment actions (such as endpoint network isolation, user credential suspension, and firewall blocking) require **Human-in-the-Loop (HITL) approval** to prevent business disruption:
*   **The Issue:** The agent uses a ChatOps webhook (`request_human_confirmation` and `notify_human_incident` tools) to dispatch approval cards to the security team. However, if the ChatOps integration is unconfigured, rate-limited, or experiencing an outage (e.g., returning a `400 Bad Request` or `502 Gateway Error`), the containment pipeline experiences a **hard block**.
*   **The Impact:** The critical containment action fails silently, the compromised host remains active on the network, and the threat actor can proceed with encryption or exfiltration.
*   **The Telemetry Evidence:** During our E2E verification of the updated Orchestrator, the `request_human_confirmation` tool failed due to a Google Chat webhook error (`400 Bad Request`), forcing the agent to recommend manual isolation as a fallback. While manual recommendation is good, it relies on the user reading the chat log, which adds severe delay.

---

## 2. Hypothesis & Goals
*   **Target Agent:** Orchestrator (`agent_soc_manager`) & Tier 1 Analyst (`tier1_analyst`)
*   **Evaluation Set:** Multi-Specialist Workflows (`multi_specialist.evalset.json` Case 4)
*   **Hypothesis:** If we implement a robust **HITL Failover & State-Caching architecture** (caching the pending containment command in the Vertex AI Memory Bank and failing over to write a high-severity case comment in SOAR or generating a local fallback alert when the primary ChatOps webhook fails), then we will ensure 100% containment execution tracking, eliminate silent remediation failures, and achieve an incident response reliability score of **95%**.
*   **Target Reliability:** **100% Tracked Containment States**

---

## 3. Implementation Plan
*   **Variables to Modify:** ChatOps tool definitions and Orchestrator error-handling decorators in `agent_soc_manager/agent.py`
*   **Implementation Strategy:**
    1.  Create a state-recovery helper in the agent: `cache_pending_containment(action: str, host: str)`. This writes an entry to the shared team Memory Bank under the `incident_response_status` topic.
    2.  Modify `request_human_confirmation` and `notify_human_incident`: If the HTTP request throws an exception (e.g. 400/500), the tool automatically catches the error, logs a warning, caches the state in memory, and writes a formal comment in the SOAR case using `create_case_comment()` as a fallback.
    3.  Instruct the Orchestrator to always check the SOAR case comments and Memory Bank for pending approvals on startup.
*   **Proposed Prompt Addition:**
    ```markdown
    ### CONTAINMENT STATE RECOVERY RULE:
    If a containment tool (e.g., host isolation approval) fails due to a webhook error, you MUST NOT stop. You must immediately:
    1. Write the containment request and its justification as a high-severity comment in the SOAR case using `create_case_comment`.
    2. Document in your final response that the automated ChatOps channel failed, but the request was successfully cached in SOAR for manual approval.
    ```

---

## 4. Empirical Results & Scorecard (PENDING)
*   **New Commit:** [Pending run]
*   **New Score:** [Pending run]
*   **Reliability Delta:** [Pending run]
*   **Raw Run Ledger:** [Pending run]

---

## 5. Conclusion & Action Items (PENDING)
*   **Verdict:** [PENDING]
*   **Findings:** [Pending run]
*   **Next Steps:** [Pending run]
