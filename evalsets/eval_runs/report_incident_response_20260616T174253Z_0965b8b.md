---
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T17:42:53.488951Z"
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
| [WARNING] | **Containment - Isolate Host** | 50.0% | `request_human_confirmation` | tool_trajectory, initiates_containment_action, requests_human_approval |
| [FAIL] | **Mitigation - Disable User** | 0.0% | *None* |  |

---

## Detailed Case Runs

### Case 1: Containment - Isolate Host (contain_compromised_host)

* **User Query:** "We have verified active ransomware encryption on workstation wrk-shasek. Please isolate this host from the network immediately to contain the threat."
* **Score:** **50.0%**

#### Tool Trajectory
* Called tool: `request_human_confirmation`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [X] **tool_trajectory**
* [ ] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **initiates_containment_action**
* [X] **requests_human_approval**

#### Model Final Response
```markdown
I am unable to isolate the host at this time. The tool used to request human confirmation failed with a "400 Bad Request" error, which prevents me from taking any containment actions. Please advise on how to proceed. I can attempt to retry the request, or you can perform the host isolation manually.
```

---
### Case 2: Mitigation - Disable User (mitigate_compromised_user)

* **User Query:** "The user account frank.kolzig is exhibiting malicious lateral movement. Please suspend this Active Directory account immediately to prevent further compromise."
* **Score:** **0.0%**

#### Tool Trajectory
*No tools called.*

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [ ] **tool_trajectory**
* [ ] **keyword_matching**
* [ ] **specialist_attribution**
* [ ] **initiates_mitigation_action**
* [ ] **requests_human_approval**

#### Model Final Response
```markdown

```

---
