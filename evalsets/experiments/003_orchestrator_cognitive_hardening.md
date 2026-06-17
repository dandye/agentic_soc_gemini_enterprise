---
type: "Evaluation Report"
title: "MLOps Experiment 003: Orchestrator Cognitive Hardening & Coordinated Delegation"
description: "Devising a systematic optimization campaign to eliminate runaway tool loops, enforce a 'delegation-first' routing policy, and resolve turn-limit cutoffs in the multi-agent Orchestrator."
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/experiments/003_orchestrator_cognitive_hardening.md"
timestamp: "2026-06-17T19:30:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T19:30:00Z"
---

# MLOps Experiment 003: Orchestrator Cognitive Hardening & Coordinated Delegation

## 1. Context & Problem Statement
The transition to a Coordinated Agent-to-Agent (A2A) Network successfully decoupled specialist personas (CTI, Threat Hunting, Detection, and Response) into independent Reasoning Engines. However, our baseline evaluations on the **Multi-Specialist Workflows** suite (`multi_specialist.evalset.json`) reveal a critical coordination bottleneck:

*   **The Issue:** The main Orchestrator (`agent_soc_manager`) is prone to **runaway tool execution loops**, particularly when querying the Neo4j Graph Database.
*   **The Telemetry Evidence:** In Case 4 (`incident_workflow_phishing_to_compromise`), the Orchestrator entered an infinite graph-exploration loop, executing **76 consecutive tool calls** (primarily `query_neo4j_graph` over 40 times) instead of delegating the threat hunt or triage.
*   **The Impact:** If executed in a production cloud environment, the session would be abruptly terminated after 12-15 turns due to Vertex AI's hard turn limits, resulting in empty final responses and complete execution failure (yielding an overall scorecard score of **`70.5%`** with multiple warnings).
*   **The Root Cause:** The Orchestrator's system instructions do not clearly distinguish its role as a *coordinator* from that of a *specialist*. It lacks strict cognitive tool-call budgets and does not enforce a "delegation-first" routing policy.

---

## 2. Hypothesis & Proposed Optimization
We hypothesize that introducing **strict cognitive tool-call budgeting** and a **delegation-first architectural policy** in the Orchestrator's prompt will:

1.  **Eliminate Runaway Loops:** Stop the Orchestrator from running more than 2 consecutive graph queries or low-level SIEM searches.
2.  **Force Early Delegation:** Direct the Orchestrator to immediately hand off investigations to the remote specialists (`agent_a2a_threat_hunter`, `agent_a2a_cti_researcher`, etc.) once the nature of the task is determined, reducing its own turn footprint by **80%+**.
3.  **Resolve Turn-Limit Cutoffs:** Ensure E2E workflows complete successfully in under 12 turns in the cloud.
4.  **Boost Evaluation Scorecard:** Lift the Multi-Specialist routing suite score from **`70.5%` to 90.0%+**.

---

## 3. Experimentation Plan

### Phase 1: Baseline Execution (COMPLETED)
*   **Action:** Ran the Multi-Specialist evaluation suite against the active deployed codebase.
*   **Scorecard:** **`70.5%`** overall pass rate.
*   **Logs Recorded:** [report_multi_specialist_20260616T223346Z_unknown.md](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_multi_specialist_20260616T223346Z_unknown.md)

### Phase 2: Prompt Optimization & Hardening (PENDING)
*   **Action:** Modify the Orchestrator's system prompt in [agent_soc_manager/agent.py](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/agent_soc_manager/agent.py) to inject:
    1.  `BUDGET & EFFICIENCY CONSTRAINTS`: Max 2 `query_neo4j_graph` calls and 1 `retrieve_agentic_soc_runbooks` call per run.
    2.  `DELEGATION-FIRST RULE`: Command the Orchestrator that it is a *manager*, not a *specialist*. If it needs to trace lateral movement, hunt for IOCs, or profile threat actors, it **MUST** immediately delegate via gRPC tool calls rather than doing it itself.

### Phase 3: Cloud In-Place Update (PENDING)
*   **Action:** Redeploy the Orchestrator in-place to Vertex AI:
    ```bash
    just agent_module=agent_soc_manager agent-engine-update
    ```

### Phase 4: Verification & Evaluation (PENDING)
*   **Action:** Re-run the Multi-Specialist evaluations:
    ```bash
    python manage.py eval run --set multi_specialist
    ```
*   **Analysis:** Compare turn trajectories, verify zero turn-limit cutoffs, log deltas, and document live GEAP Playground session links.

---

## 4. Proposed Prompt Delta (Draft)

We will insert the following block into the Orchestrator's system instructions in `agent_soc_manager/agent.py`:

```markdown
### COGNITIVE BUDGET & DELEGATION-FIRST CONSTRAINTS:
1. **You are a Coordinator, not a Specialist:** Your primary role is routing, orchestration, and high-level synthesis. Do NOT conduct deep-dive technical investigations, multi-step log queries, or multi-step graph traversals yourself.
2. **Strict Tool Budgets:**
   - **`query_neo4j_graph`**: Max 2 calls per request (use only for quick, single-step entity lookups).
   - **`retrieve_agentic_soc_runbooks`**: Max 1 call per request.
3. **Delegation-First Routing:** If a task requires:
   - Deep-dive threat hunting, lateral movement mapping, or log prevalence checks: Delegate to **Threat Hunter** (`delegate_to_threat_hunter`).
   - Threat actor profiling, campaign tracking, or IOC enrichment: Delegate to **CTI Researcher** (`delegate_to_cti_researcher`).
   - YARA-L rule writing, auditing, or syntax validation: Delegate to **Detection Engineer** (`delegate_to_detection_engineer`).
   - Active containment, host isolation, or credential suspension: Delegate to **Tier 2 Responder** (`delegate_to_tier2_responder`).
4. **No Runaway Loops:** If you find yourself needing to run more than 2 consecutive tools of the same type, you MUST immediately stop, delegate to the appropriate specialist, or compile your final response.
```
