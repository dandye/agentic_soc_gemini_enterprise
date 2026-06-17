---
type: "Template"
title: "Agent Experimentation Log Template"
description: "Standardized MLOps template for recording agent prompt and parameter experimentation runs"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/experiments/template.md"
timestamp: "2026-06-17T08:00:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T08:00:00Z"
---

# Experiment [Number]: [Descriptive Title]

---

## 1. Metadata
*   **Target Agent:** [Orchestrator | Threat Hunter | CTI Researcher | Detection Engineer | Tier 2 Responder]
*   **Evaluation Set:** [Name of evaluation set]
*   **Baseline Commit:** [Git commit hash of the baseline code state]
*   **Baseline Score:** [e.g., 69.0%]

---

## 2. Hypothesis & Goals
*   **Context:** [Why are we running this? What is the current gap or failure mode?]
*   **Hypothesis:** [State clearly: "If we vary [X input], then we expect [Y score/trajectory change] because [Z reasoning]."]
*   **Target Score:** [e.g., 100.0%]

---

## 3. Implementation Plan
*   **Variables to Modify:** [Prompts | Grounding | Tools | Model | Architecture]
*   **Files Modified:** [Link to file paths e.g. `agent_a2a_threat_hunter/agent.py`]
*   **Code Delta (Diff):**
    ```diff
    // Insert the clean git diff of your changes here
    ```

---

## 4. Empirical Results & Scorecard
*   **New Commit:** [Git commit hash of the experimental code state]
*   **New Score:** [e.g., 100.0%]
*   **Score Delta:** [e.g., ▲ +31.0% or ▼ -5.0%]
*   **Assertions Passed:**
    *   [X] [Assertion Name e.g., specialist_attribution]
*   **Trajectory Diff:** [List any tool calls added, removed, or reordered]
*   **Raw Run Ledger:** [Link to the raw JSON run log e.g. `evalsets/eval_runs/run_xxx.json`]

---

## 5. Conclusion & Action Items
*   **Verdict:** [MERGED | REJECTED | ITERATING]
*   **Findings:** [Key insights, unexpected behaviors, or lessons learned during the run]
*   **Next Steps:** [Future experiments or refinements suggested by these results]
