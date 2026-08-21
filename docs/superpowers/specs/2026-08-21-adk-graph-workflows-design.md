---
type: "Architecture"
title: "36 Executable ADK Graph Workflows Specification"
description: "Architecture specification for the 36 deterministic ADK Graph Workflows, Pydantic IO contracts, event routers, and tool wrappers in Google ADK Agentic SOC"
resource: "docs/superpowers/specs/2026-08-21-adk-graph-workflows-design.md"
timestamp: "2026-08-21T21:10:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-08-21T21:10:00Z"
---

# Architecture Specification: 36 Executable ADK Graph Workflows

## 1. Executive Summary

This document specifies the architecture and implementation of the **36 Executable ADK Graph Workflows** integrated into the Google SecOps Agentic SOC framework.

While unstructured natural language prompts can lead to non-deterministic execution paths, complex SOC operations (such as incident response playbooks, triage flows, and threat hunting campaigns) require strictly reproducible, branching execution logic. This module encapsulates standard operating procedures (SOPs) and incident response plans (IRPs) into typed ADK graph workflows.

## 2. Core Components

### 2.1 Pydantic Input/Output Schemas
Every workflow defines strictly typed Pydantic models for inputs, intermediate node state transitions, and final documentation outputs (e.g. `BaseWorkflowInput`, `CommonSOAROutcome`).

### 2.2 Functional Nodes & Branch Routers
Each workflow consists of:
- **Extraction Nodes**: Normalizes inputs (IOCs, case IDs, telemetry).
- **Enrichment / Search Nodes**: Executes SIEM, SOAR, GTI, or SCC queries.
- **Decision Routers**: Returns typed `Event` objects routing to specific outcome branches based on thresholds or classification logic.
- **Documentation Nodes**: Generates markdown summaries and formats SOAR case comments.

### 2.3 Workflow Tool Wrappers
All 36 workflows are wrapped as callable Python functions in `agent_soc_manager/tools/workflow_tools.py` and exported via `get_all_workflow_tools()`.

## 3. Workflow Catalog (36 Workflows)

1. `run_advanced_threat_hunting_workflow`
2. `run_alert_report_workflow`
3. `run_apt_threat_hunt_workflow`
4. `run_basic_ioc_enrichment_workflow`
5. `run_case_report_workflow`
6. `run_close_duplicate_cases_workflow`
7. `run_cloud_vulnerability_triage_workflow`
8. `run_compare_gti_collection_workflow`
9. `run_compromised_user_irp_workflow`
10. `run_create_investigation_report_workflow`
11. `run_credential_access_hunt_workflow`
12. `run_deep_dive_ioc_analysis_workflow`
13. `run_demo_soc_t2_workflow`
14. `run_detection_as_code_tuning_workflow`
15. `run_detection_report_workflow`
16. `run_detection_rule_validation_workflow`
17. `run_endpoint_triage_workflow`
18. `run_group_cases_v2_workflow`
19. `run_group_cases_workflow`
20. `run_investigate_case_external_tools_workflow`
21. `run_investigate_gti_collection_workflow`
22. `run_ioc_containment_workflow`
23. `run_ioc_threat_hunt_workflow`
24. `run_lateral_movement_hunt_workflow`
25. `run_malware_irp_workflow`
26. `run_malware_triage_workflow`
27. `run_metaanalysis_workflow`
28. `run_phishing_irp_workflow`
29. `run_post_incident_review_workflow`
30. `run_prioritize_investigate_case_workflow`
31. `run_proactive_gti_threat_hunt_workflow`
32. `run_ransomware_irp_workflow`
33. `run_suspicious_login_workflow`
34. `run_timeline_process_analysis_workflow`
35. `run_triage_alerts_workflow`
36. `run_ueba_report_workflow`
