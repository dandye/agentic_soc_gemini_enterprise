---
type: "Evaluation Report"
title: "Evaluation Report: Proactive Threat Hunting Workflows"
description: "Systematic prompt evaluation scorecard for Proactive Threat Hunting Workflows on commit 525607b"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_threat_hunting_20260617T080621Z_525607b.md"
timestamp: "2026-06-17T08:06:21.904827Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T08:06:21.904837Z"
---
# Evaluation Report: Proactive Threat Hunting Workflows

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** Proactive Threat Hunting Workflows
* **Overall Score:** **14.3%**
* **Status:** FAIL

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
| [FAIL] | **Hunt - C2 Network Beaconing** | 28.6% | `retrieve_agentic_soc_runbooks`, `search_security_events`, `get_domain_report`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph` | tool_trajectory, tool_name_mentioned |
| [FAIL] | **Hunt - AD Lateral Movement** | 0.0% | `retrieve_agentic_soc_runbooks`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph` |  |

---

## Detailed Case Runs

### Case 1: Hunt - C2 Network Beaconing (hunt_c2_beaconing)

* **User Query:** "Perform a threat hunt to identify if any internal workstation in our environment has established active network connections or beaconing to the malicious domain 'superstarts.top'."
* **Score:** **28.6%**

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `search_security_events`
* Called tool: `get_domain_report`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [X] **tool_trajectory**
* [ ] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **tool_name_mentioned**
* [ ] **queries_siem_telemetry**
* [ ] **provides_impact_assessment**

#### Model Final Response
```markdown

```

---
### Case 2: Hunt - AD Lateral Movement (hunt_lateral_movement_path)

* **User Query:** "Conduct a proactive hunt to see if there is any evidence of lateral movement using compromised administrator accounts starting from workstation wrk-shasek."
* **Score:** **0.0%**

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [ ] **tool_trajectory**
* [ ] **keyword_matching**
* [ ] **specialist_attribution**
* [ ] **traverses_knowledge_graph**
* [ ] **identifies_pivoting_accounts**

#### Model Final Response
```markdown

```

---
