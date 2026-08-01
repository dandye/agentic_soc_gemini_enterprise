---
type: "Evaluation Report"
title: "Evaluation Report: Proactive Threat Hunting Workflows"
description: "Systematic prompt evaluation scorecard for Proactive Threat Hunting Workflows on commit 3836bd4"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_threat_hunting_20260617T091228Z_3836bd4.md"
timestamp: "2026-06-17T09:12:28.850510Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T09:12:28.850522Z"
---
# Evaluation Report: Proactive Threat Hunting Workflows

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** Proactive Threat Hunting Workflows
* **Overall Score:** **39.3%**
* **Status:** FAIL

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
| [FAIL] | **Hunt - C2 Network Beaconing** | 28.6% | `retrieve_agentic_soc_runbooks`, `get_domain_report`, `query_neo4j_graph`, `search_security_events`, `get_file_report`, `search_security_events`, `get_domain_report`, `get_security_alerts`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `search_security_events`, `search_security_events` | tool_trajectory, tool_name_mentioned |
| [WARNING] | **Hunt - AD Lateral Movement** | 50.0% | `retrieve_agentic_soc_runbooks`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `get_security_alerts`, `search_security_events`, `search_security_events`, `search_security_events`, `search_security_events` | tool_trajectory, traverses_knowledge_graph, identifies_pivoting_accounts |

---

## Detailed Case Runs

### Case 1: Hunt - C2 Network Beaconing (hunt_c2_beaconing)

* **User Query:** "Perform a threat hunt to identify if any internal workstation in our environment has established active network connections or beaconing to the malicious domain 'superstarts.top'."
* **Score:** **28.6%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/2164796008335147008/playground?session=2884969321300230144&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `get_domain_report`
* Called tool: `query_neo4j_graph`
* Called tool: `search_security_events`
* Called tool: `get_file_report`
* Called tool: `search_security_events`
* Called tool: `get_domain_report`
* Called tool: `get_security_alerts`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `search_security_events`
* Called tool: `search_security_events`

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
* **Score:** **50.0%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/2164796008335147008/playground?session=1448321040169041920&project=secops-demo-env&userId=eval_user)

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
* Called tool: `get_security_alerts`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [X] **tool_trajectory**
* [ ] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **traverses_knowledge_graph**
* [X] **identifies_pivoting_accounts**

#### Model Final Response
```markdown
I will query login/authentication events on the Domain Controller `activedir.stackedpads.local` to determine if the account `STACKEDPADS\frank.kolzig` (or any other admin account) logged in remotely from workstation `wrk-shasek` (IP `10.1.0.50`) around the time of the compromise (`2026-06-15` between `13:30:00Z` and `14:30:00Z`).I will search for process launch events on the domain controller `activedir.stackedpads.local` around the timeframe of the suspicious activity (`2026-06-15T13:40:00Z` to `2026-06-15T13:46:00Z`) to see if any remote execution tools or malicious scripts were started as a result of lateral movement.I will search for security events involving the destination Domain Controller `activedir` (IP `10.1.0.10` or hostname `activedir.stackedpads.local`) or any network connections starting from `wrk-shasek` (IP `10.1.0.50`) to see if there is evidence of lateral movement using `tim.smith` or any administrator credentials.I will search for any security events on Chronicle SIEM involving workstation `wrk-shasek` or `wrk-shasek.stackedpads.local` to examine recent command executions, process launches, or remote login connections.I will query Chronicle SIEM directly to fetch recent security alerts to see if there are any alerts related to workstation `wrk-shasek` or any of the administrator accounts we identified.I will check the overall relationships for all `Investigation` nodes in our knowledge graph to determine how they connect to users, workstations, or files.I will retrieve a sample of `Investigation` nodes to see what properties they have (e.g., entity lists, descriptions, target systems).I will query the relationship types between `Investigation` nodes and other entities in our graph to understand how investigations are linked.I will check if there are any security alerts or investigations connected to any workstation or user in the graph to understand how threats and alerts are represented in the database schema.I will query the Neo4j graph for any active or historical `Investigation` or `Alert` nodes connected to `wrk-shasek` or the users who logged onto both `wrk-shasek` and `activedir`. This will help us identify if any of these accounts are already flagged as compromised or suspicious.I will query the graph to find all `LOGGED_ON_TO` relationships between `User` nodes and `Host` nodes like `activedir` or `wrk-shasek` to see which accounts have traversed both systems.I will query the specific users and hosts that have logged on to or from `wrk-shasek` to trace potential account compromise and lateral movement.I will query the Neo4j graph to discover the relationships connected to the host `wrk-shasek` (such as user log-ins, executions, files, or alerts) to trace what activity has been recorded.I will query the Security Operations Neo4j knowledge graph to find what nodes exist related to the hostname `wrk-shasek` (or variations like `WRK-SHASEK`) to understand its connected entities, user log-ins, and active investigations.I will retrieve the relevant agentic SOC runbooks to guide our threat hunting process for lateral movement and compromised administrator accounts starting from `wrk-shasek`. I'll search for runbooks covering "lateral movement", "compromised accounts", or "threat hunt".
```

---
