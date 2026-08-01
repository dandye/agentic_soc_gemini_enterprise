---
type: "Evaluation Comparison Report"
title: "Evaluation Comparison Report: threat_hunting"
description: "Delta analysis between run run_threat_hunting_20260616T212334Z_060ddf0.json and run run_threat_hunting_20260617T080621Z_525607b.json"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/compare_threat_hunting.md"
timestamp: "2026-06-17T08:06:32.629101Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T08:06:32.629109Z"
---
# Evaluation Comparison Report: threat_hunting

> [!NOTE]
> This comparison was compiled automatically by diffing two structured evaluation ledgers and extracting the Git commit delta.

## Executive Summary

* **Evalset ID:** `threat_hunting`
* **Baseline Run:** `run_threat_hunting_20260616T212334Z_060ddf0.json` (Score: **69.0%**)
* **New Run:** `run_threat_hunting_20260617T080621Z_525607b.json` (Score: **14.3%**)
* **Performance Delta:** **-54.8%**

---

## Tool Trajectory Changes

  [REMOVED] Hunt - C2 Network Beaconing: Stopped calling: `get_file_report`, `get_security_alerts`, `search_security_rules`, `get_rule_detections`, `get_ip_address_report`, `get_reference_list`, `save_report_artifact`
  [REMOVED] Hunt - AD Lateral Movement: Stopped calling: `get_security_alerts`, `get_security_alerts`, `search_security_events`, `search_security_events`, `search_security_events`

---

## Grounding & Database Changes

*No changes in database grounding or runbooks between these runs.*

---

## Git Changelog Between Runs

* 525607b docs(eval): rename to Agent Evaluation & Optimization Framework and reframe conceptually
* 5679938 docs(eval): document the experimentation log registry and unified Git-MLOps workflow
* e98268e docs(experiment): initialize experiment log template and record threat hunter attribution run
* 195a0b3 feat(hunter): enforce specialist role sign-off in Threat Hunter instructions
* 5a41428 docs: enforce Google Open Knowledge Format (OKF) standard across all Markdown files
* 52c2ac1 docs(experiment): add systematic agent experimentation playbook and variables catalog
* 4a93b5c docs(eval): add live Multi-Specialist evaluation run to ledger
* 3d1c935 fix(eval): add catch-all exception handler to make test suites highly resilient to remote cloud API transients
* 28ee451 docs(eval): add live SOC Basic Operations evaluation run to ledger
* cb84935 docs(eval): add live Tier 1 Triage evaluation run to ledger
* a98c8cb docs(eval): add live CTI Research evaluation run to ledger
* d123516 docs(eval): add live Incident Response evaluation run to ledger
* 1e2a914 docs(eval): add Neo4j-enabled Threat Hunting evaluation run to ledger

---

## Next Steps
Use this log to correlate codebase modifications directly to prompt performance and tool-use behaviors.
