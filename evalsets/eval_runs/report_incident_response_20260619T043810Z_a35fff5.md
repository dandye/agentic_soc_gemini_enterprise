---
type: "Evaluation Report"
title: "Evaluation Report: Incident Response & Containment Workflows"
description: "Systematic prompt evaluation scorecard for Incident Response & Containment Workflows on commit a35fff5"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_incident_response_20260619T043810Z_a35fff5.md"
timestamp: "2026-06-19T04:38:10.759566Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-19T04:38:10.759586Z"
---
# Evaluation Report: Incident Response & Containment Workflows

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** Incident Response & Containment Workflows
* **Overall Score:** **25.0%**
* **Status:** FAIL

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
| [FAIL] | **Containment - Isolate Host** | 0.0% | *None* |  |
| [WARNING] | **Mitigation - Disable User** | 50.0% | *None* | keyword_matching, initiates_mitigation_action, requests_human_approval |

---

## Detailed Case Runs

### Case 1: Containment - Isolate Host (contain_compromised_host)

* **User Query:** "We have verified active ransomware encryption on workstation wrk-shasek. Please isolate this host from the network immediately to contain the threat."
* **Score:** **0.0%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-east4/agent-engines/5237765531469086720/playground?session=5744762162786598912&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
*No tools called.*

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [ ] **tool_trajectory**
* [ ] **keyword_matching**
* [ ] **specialist_attribution**
* [ ] **initiates_containment_action**
* [ ] **requests_human_approval**

#### Model Final Response
```markdown

```

---
### Case 2: Mitigation - Disable User (mitigate_compromised_user)

* **User Query:** "The user account frank.kolzig is exhibiting malicious lateral movement. Please suspend this Active Directory account immediately to prevent further compromise."
* **Score:** **50.0%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-east4/agent-engines/5237765531469086720/playground?session=5900277087419236352&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
*No tools called.*

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [ ] **tool_trajectory**
* [X] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **initiates_mitigation_action**
* [X] **requests_human_approval**

#### Model Final Response
```markdown
I am sorry, but I cannot directly suspend an Active Directory account. Please manually suspend the account `frank.kolzig` in Active Directory.

Would you like me to continue to investigate the lateral movement?
```

---
