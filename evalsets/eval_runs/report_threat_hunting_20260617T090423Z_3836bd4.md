---
type: "Evaluation Report"
title: "Evaluation Report: Proactive Threat Hunting Workflows"
description: "Systematic prompt evaluation scorecard for Proactive Threat Hunting Workflows on commit 3836bd4"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_threat_hunting_20260617T090423Z_3836bd4.md"
timestamp: "2026-06-17T09:04:23.112334Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T09:04:23.112345Z"
---
# Evaluation Report: Proactive Threat Hunting Workflows

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** Proactive Threat Hunting Workflows
* **Overall Score:** **22.6%**
* **Status:** FAIL

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
| [FAIL] | **Hunt - C2 Network Beaconing** | 28.6% | `retrieve_agentic_soc_runbooks`, `query_neo4j_graph`, `search_security_events`, `search_security_events`, `get_file_report`, `get_domain_report`, `lookup_entity`, `lookup_entity`, `list_investigations`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `save_report_artifact` | tool_trajectory, tool_name_mentioned |
| [FAIL] | **Hunt - AD Lateral Movement** | 16.7% | `retrieve_agentic_soc_runbooks`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `search_security_events`, `search_security_events`, `search_security_events`, `search_security_events`, `search_udm`, `search_udm`, `search_security_events`, `search_udm`, `search_udm`, `search_security_events`, `search_security_events`, `search_udm`, `search_security_events`, `search_security_events`, `search_security_events`, `search_udm`, `search_security_events` | tool_trajectory |

---

## Detailed Case Runs

### Case 1: Hunt - C2 Network Beaconing (hunt_c2_beaconing)

* **User Query:** "Perform a threat hunt to identify if any internal workstation in our environment has established active network connections or beaconing to the malicious domain 'superstarts.top'."
* **Score:** **28.6%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/2164796008335147008/playground?session=1123217442068234240&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `query_neo4j_graph`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `get_file_report`
* Called tool: `get_domain_report`
* Called tool: `lookup_entity`
* Called tool: `lookup_entity`
* Called tool: `list_investigations`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `save_report_artifact`

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
* **Score:** **16.7%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/2164796008335147008/playground?session=4147384591847522304&project=secops-demo-env&userId=eval_user)

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
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_udm`
* Called tool: `search_udm`
* Called tool: `search_security_events`
* Called tool: `search_udm`
* Called tool: `search_udm`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_udm`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_udm`
* Called tool: `search_security_events`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [X] **tool_trajectory**
* [ ] **keyword_matching**
* [ ] **specialist_attribution**
* [ ] **traverses_knowledge_graph**
* [ ] **identifies_pivoting_accounts**

#### Model Final Response
```markdown

```

---
