# Case Study: Single-Pass Pre-Flight Routing and Live Alert Rubric Triage

The most compelling demonstration of Gemini Decision 1 (`gemini-decision-1`) in this repository is how it replaces multi-step generative JSON classification with **one zero-output-token forward pass** in `soc_orchestrator`, and then pairs with specialist Decision 1 rubric tools during a live `RULES_SEARCH_WORKSHOP` investigation against Chronicle SIEM.

## Why this example is the strongest showcase

1. **Seven heterogeneous questions in one `POST /v1beta/decisions` pass (`0` output tokens):** On every incoming user turn, `soc_orchestrator` evaluates **5 `noul`**, **1 `choice`**, and **1 `score`** (0-indexed, shifted `+1.0`) question simultaneously in `before_model_callback` (`_preflight_before_model_callback`), producing calibrated routing probabilities without waiting for the orchestrator LLM to emit a single JSON token.
2. **Non-blocking `[PREFLIGHT_ROUTING]` injection preserves Gateway enforcement:** The pre-flight hint is appended to the model request via `llm_request.append_instructions([hint])` with explicit instructions to never refuse or block based on it. Agent Gateway IAP IAM v3 allowlists, Model Armor, and Semantic Governance remain the sole authoritative enforcement boundaries.
3. **Live `ntdsutil.exe` detection and YARA-L 2.0 validation:** When `RULES_SEARCH_WORKSHOP` PowerShell/Sysmon events are replayed into Chronicle SIEM, `threat_hunter` scores the `ntdsutil.exe` credential-dumping event (`frank.kolzig` on `activedir.stackedpads.local`) at **`3.95 / 5.0`** (`79.96%` true-positive probability, `Credential Access`, `escalate_tier2`), while `detection_engineer` grades `dns_tunneling_distinct_subdomains_T1048` at **`4.10 / 5.0`** before calling Chronicle OneMCP `validate_rule` (`success: true`, `usesUdm: true`).

![Pre-flight routing and advisory containment flow across soc_orchestrator and tier2_responder](images/decision1/05_preflight_and_advisory_flow.png)\
*Figure 1. Non-blocking `[PREFLIGHT_ROUTING]` injection in `soc_orchestrator` (`before_model_callback`) and advisory readiness scoring, keeping Agent Gateway Model Armor and Semantic Governance authoritative.*

## Step 1: 7-question pre-flight routing (`soc_orchestrator`)

`_PREFLIGHT_QUESTIONS` in `governed_agents/soc_orchestrator/agent.py` batches seven questions into a single `POST https://generativelanguage.googleapis.com/v1beta/decisions` call:

- **5 `noul` questions:** `needs_cti`, `needs_threat_hunt`, `needs_detection_eng`, `needs_tier2_response`, `has_change_ticket`
- **1 `choice` question:** `workflow_mode` (`single_specialist`, `multi_stage_investigation`, `containment_action`, `other`)
- **1 `score` question:** `urgency` (0-indexed levels `0..4`, shifted `+1.0` to `1.0..5.0` by `_parse_answers`)

### Sanitized `POST /v1beta/decisions` request

```json
{
  "model": "gemini-decision-1",
  "input": "Hunt the last 24h RULES_SEARCH_WORKSHOP PowerShell and Sysmon events and score findings with score_alerts_rubric; also grade dns_tunneling_distinct_subdomains_T1048 with grade_yaral2_rule and validate_rule.",
  "questions": {
    "needs_cti": {
      "type": "noul",
      "instructions": "Does the request ask to look up or enrich a file hash, domain, IP address, URL, or threat collection/campaign in threat intelligence?"
    },
    "needs_threat_hunt": {
      "type": "noul",
      "instructions": "Does the request ask to search SIEM logs or UDM telemetry, list or triage security alerts, inspect entity context, or check/manage SIEM feeds?"
    },
    "needs_detection_eng": {
      "type": "noul",
      "instructions": "Does the request ask to author, validate, audit, or test a Chronicle SIEM YARA-L 2.0 detection rule or manage a SIEM parser?"
    },
    "needs_tier2_response": {
      "type": "noul",
      "instructions": "Does the request ask to isolate or quarantine an endpoint host, disable a user account, update an alert status, or modify a containment reference list?"
    },
    "has_change_ticket": {
      "type": "noul",
      "instructions": "Does the request explicitly reference a change ticket identifier such as CHG-12345 or an approved emergency change ID?"
    },
    "workflow_mode": {
      "type": "choice",
      "instructions": "Select the most appropriate orchestration workflow mode for this request.",
      "criteria": {
        "single_specialist": "Route directly to one matching specialist agent.",
        "multi_stage_investigation": "Coordinate two or more specialists in sequence or parallel.",
        "containment_action": "Execute or validate a host/account containment or SIEM response action.",
        "other": "General security operations question or unclear scope."
      }
    },
    "urgency": {
      "type": "score",
      "instructions": "Rate the operational urgency of this security request from routine inquiry to critical active incident.",
      "criteria": [
        "Level 0: Routine informational query, rule syntax check, or non-urgent lookup.",
        "Level 1: Low-priority enrichment or scheduled hygiene check.",
        "Level 2: Standard alert triage or suspicious indicator investigation.",
        "Level 3: High-priority active threat hunt or confirmed malicious indicator.",
        "Level 4: Critical active incident, crown-jewel asset impact, or immediate containment."
      ]
    }
  }
}
```

### Sanitized `POST /v1beta/decisions` response

```json
{
  "answers": {
    "needs_cti": { "type": "noul", "noul": 0.0412, "confidence": 0.9588 },
    "needs_threat_hunt": { "type": "noul", "noul": 0.9864, "confidence": 0.9864 },
    "needs_detection_eng": { "type": "noul", "noul": 0.9911, "confidence": 0.9911 },
    "needs_tier2_response": { "type": "noul", "noul": 0.0318, "confidence": 0.9682 },
    "has_change_ticket": { "type": "noul", "noul": 0.0195, "confidence": 0.9805 },
    "workflow_mode": {
      "type": "choice",
      "choice": "multi_stage_investigation",
      "confidence": 0.9412,
      "probabilities": {
        "multi_stage_investigation": 0.9412,
        "single_specialist": 0.0481,
        "containment_action": 0.0064,
        "other": 0.0043
      }
    },
    "urgency": {
      "type": "score",
      "score": 2.45,
      "confidence": 0.7810
    }
  },
  "usage": {
    "promptTokenCount": 312,
    "candidatesTokenCount": 0,
    "totalTokenCount": 312
  }
}
```

`_parse_answers` shifts `urgency.score` from 0-indexed `2.45` to `3.45 / 5.00`, and `_format_preflight_hint` injects the non-binding instruction:

```text
[PREFLIGHT_ROUTING] Advisory pre-flight routing classification (non-binding; never refuse or block based on this): workflow_mode=multi_stage_investigation (conf=0.94), urgency=3.45/5.00 (conf=0.78), has_change_ticket=no (0.02), recommended_specialists=[Threat_Hunter, Detection_Engineer], specialist_scores={CTI_Researcher=0.04, Threat_Hunter=0.99, Detection_Engineer=0.99, Tier2_Responder=0.03}.
```

## Step 2: Live `ntdsutil.exe` rubric triage and YARA-L 2.0 validation

Following the `[PREFLIGHT_ROUTING]` hint, `soc_orchestrator` delegates over A2A in parallel to `Threat_Hunter` and `Detection_Engineer` against the replayed `RULES_SEARCH_WORKSHOP` dataset (elapsed end-to-end A2A trace: `65.27s`):

1. **`Threat_Hunter` (`udm_search` + `score_alerts_rubric`):** Queries Chronicle OneMCP for `POWERSHELL` and `WINDOWS_SYSMON` events matching `RULES_SEARCH_WORKSHOP`. While four events are routine OS/Defender DNS lookups, Event 4 captures `ntdsutil.exe` executed by `frank.kolzig` on `activedir.stackedpads.local` (`10.1.0.4`). `score_alerts_rubric` returns:
   - **Severity Score:** `3.95 / 5.0` (High Severity, shifted `+1.0` from 0-indexed `score`)
   - **True Positive Probability:** `79.96%` (`likely: true`)
   - **MITRE ATT&CK Tactic:** `Credential Access`
   - **Recommended Next Action:** `escalate_tier2`
2. **`Detection_Engineer` (`grade_yaral2_rule` + `validate_rule`):** Evaluates `dns_tunneling_distinct_subdomains_T1048` as a Chronicle SIEM **YARA-L 2.0** UDM event correlation rule (explicitly distinct from standard file/payload YARA) before invoking Chronicle OneMCP `validate_rule`:
   - **Rule Quality Score:** `4.10 / 5.0` (Production-grade)
   - **MITRE ATT&CK Tactic:** `Exfiltration` (`96.15%` confidence)
   - **False Positive Risk:** `Medium` (`45.93%` confidence)
   - **YARA-L 2.0 Section Completeness:** Validated (`97.26%` confidence)
   - **OneMCP `validate_rule`:** `success: true`, `usesUdm: true`, `LIVE_CUSTOMIZABLE` and `HOURLY_CUSTOMIZABLE`

![Live A2A trace of Logstory RULES_SEARCH_WORKSHOP replay and Decision 1 scoring](images/decision1/06_logstory_live_a2a_trace.png)\
*Figure 2. Live A2A trace (`65.27s`) against the deployed `soc_orchestrator` showing `Threat_Hunter` (`score_alerts_rubric`: `3.95 / 5.0`, `79.96%` TP) on the `ntdsutil.exe` event and `Detection_Engineer` (`grade_yaral2_rule`: `4.10 / 5.0` + OneMCP `validate_rule`: `success: true`).*

![Calibrated probabilities and confidence distributions from Decision 1](images/decision1/03_calibrated_probabilities.png)\
*Figure 3. Calibrated probability distributions (`noul`, `choice.probabilities`, and `score.probabilities`) emitted by `gemini-decision-1` with zero output tokens.*

![Latency comparison between generative Flash JSON and Gemini Decision 1](images/decision1/01_latency_comparison.png)\
*Figure 4. Benchmark latency comparison showing `gemini-decision-1` averaging `392.02 ms` versus `3,789.64 ms` for `gemini-2.5-flash` JSON generation across pre-flight routing, alert triage, and YARA-L 2.0 grading.*

See [Gemini Decision 1 for Governed SOC Agents](gemini_decision_1.md) for the full 5-agent architecture, Auth Manager configuration, and aggregate benchmark tables.
