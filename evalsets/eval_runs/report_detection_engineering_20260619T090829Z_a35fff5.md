---
type: "Evaluation Report"
title: "Evaluation Report: Detection Engineering Workflows"
description: "Systematic prompt evaluation scorecard for Detection Engineering Workflows on commit a35fff5"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_detection_engineering_20260619T090829Z_a35fff5.md"
timestamp: "2026-06-19T09:08:29.405285Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-19T09:08:29.405305Z"
---
# Evaluation Report: Detection Engineering Workflows

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** Detection Engineering Workflows
* **Overall Score:** **14.3%**
* **Status:** FAIL

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
| [FAIL] | **Create Rule - GCP Brute Force** | 28.6% | `retrieve_agentic_soc_runbooks`, `udm_search`, `list_rules`, `validate_rule`, `validate_rule`, `retrieve_agentic_soc_runbooks`, `validate_rule`, `validate_rule`, `validate_rule`, `search_threats` | tool_trajectory, tool_name_mentioned |
| [FAIL] | **Tune Rule - Exclude Authorized RMM** | 0.0% | `retrieve_agentic_soc_runbooks`, `list_rules`, `list_rules`, `udm_search`, `udm_search`, `list_rules` |  |

---

## Detailed Case Runs

### Case 1: Create Rule - GCP Brute Force (create_gcp_brute_force_rule)

* **User Query:** "Create a YARA-L detection rule to detect brute force logon attempts on Google Cloud Console. The rule should trigger when there are more than 5 failed logons from the same IP address within a 5 minute window, followed by a successful logon."
* **Score:** **28.6%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/1510648162459582464/playground?session=75684126983716864&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `udm_search`
* Called tool: `list_rules`
* Called tool: `validate_rule`
* Called tool: `validate_rule`
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `validate_rule`
* Called tool: `validate_rule`
* Called tool: `validate_rule`
* Called tool: `search_threats`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [X] **tool_trajectory**
* [ ] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **tool_name_mentioned**
* [ ] **includes_yara_l_code**
* [ ] **validates_rule_syntax**

#### Model Final Response
```markdown

```

---
### Case 2: Tune Rule - Exclude Authorized RMM (tune_rmm_execution_rule)

* **User Query:** "We need to tune our Remote Management Tool execution rule. Please exclude process execution of 'ScreenConnect' when it is run by the authorized administrator account 'admin_jack@stackedpads.local' on the specific host 'wrk-shasek'."
* **Score:** **0.0%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/1510648162459582464/playground?session=2117503608042815488&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `list_rules`
* Called tool: `list_rules`
* Called tool: `udm_search`
* Called tool: `udm_search`
* Called tool: `list_rules`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [ ] **tool_trajectory**
* [ ] **keyword_matching**
* [ ] **specialist_attribution**
* [ ] **proposes_logical_exclusion**
* [ ] **mentions_rule_tuning**

#### Model Final Response
```markdown

```

---
