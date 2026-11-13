# Threat Hunter Alert Rubric Triage (`score_alerts_rubric`)

`threat_hunter` pairs read-only Google SecOps (Chronicle SIEM) Universal Data Model (UDM) hunting with `score_alerts_rubric(alerts_json)` in `governed_agents/threat_hunter/triage_tools.py`. Instead of prompting a generative model to emit structured JSON for every alert batch, `score_alerts_rubric` evaluates four heterogeneous rubric questions in a single zero-output-token `POST /v1beta/decisions` forward pass (`gemini-decision-1`).

## Single-pass alert and UDM batch rubric

`_normalize_alerts_input(alerts_json)` pretty-prints valid JSON payloads (with `sort_keys=True`) or preserves raw alert text, bounding the prompt input to `_MAX_INPUT_CHARS = 32000` characters. `score_alerts_rubric` then sends `_ALERT_TRIAGE_QUESTIONS` to `evaluate_decisions` (`governed_agents/threat_hunter/decision_client.py`):

| Question ID | Decision 1 Type | Output Mapping & Semantics | Rubric Options / Scale |
| :--- | :--- | :--- | :--- |
| `severity` | `score` | 0-indexed expected score (`0.0..4.0`) shifted `+1.0` to `severity_score` (`1.0..5.0`) and integer `severity_level` (`1..5`) | `1`: Informational/benign, `2`: Low anomaly, `3`: Medium suspicious, `4`: High likely threat, `5`: Critical active compromise |
| `true_positive` | `noul` | Calibrated probability (`0.0..1.0`) mapped to `likely: score >= 0.5` and `confidence` | True-positive security threat vs. benign administrative activity or false positive |
| `mitre_tactic` | `choice` | Categorical `choice` with calibrated per-tactic probability | `initial_access`, `execution`, `persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection_exfiltration`, `command_and_control`, `other_or_benign` |
| `next_action` | `choice` | Categorical `choice` routing the SOC analyst's next step | `dismiss`, `enrich_cti`, `escalate_tier2`, `tune_yaral2` |

When neither `GEMINI_AUTH_PROVIDER` nor `GEMINI_API_KEY` is configured, `evaluate_decisions` returns `{"enabled": False, ...}` so hermetic CI and unit tests pass without network access.

![Threat Hunter four-question Decision 1 alert rubric comparing the ntdsutil.exe event against a benign admin discovery scan](images/decision1/12_threat_hunter_alert_rubric.png)\
*Figure 1. Single-pass `score_alerts_rubric` breakdown comparing the replayed `ntdsutil.exe` event on `activedir.stackedpads.local` (`3.95 / 5.0` shifted severity, `79.96%` true-positive `noul` probability, `credential_access`, `escalate_tier2`) against a benign admin discovery scan (`1.26 / 5.0`, `2.26%` true-positive probability, `dismiss`).*

## YARA-L 2.0 vs. standard YARA and Gateway boundaries

In both `governed_agents/threat_hunter/agent.py` and the `tune_yaral2` rubric option, `threat_hunter` explicitly distinguishes **Chronicle SIEM YARA-L 2.0** detection rules from **standard YARA** rules:

- **Chronicle SIEM YARA-L 2.0:** Event-correlation rules written against UDM telemetry (`meta`, `events`, and `condition` sections) and inspected via `list_rules`, `get_rule`, and `list_rule_detections`. When a detection rule is noisy or overly broad, `score_alerts_rubric` recommends `tune_yaral2` so Detection Engineering can refine the UDM query.
- **Standard YARA:** File and binary payload pattern-matching rules (`strings` and `condition` sections) used on artifacts rather than SIEM UDM event streams.

`threat_hunter` is strictly read-only on Chronicle OneMCP (`udm_search`, `search_raw_logs`, `translate_udm_query`, `list_security_alerts`, `get_security_alert`, `fetch_alert_data`, `search_entity`, `summarize_entity`, `get_ioc_match`, `list_rules`, `get_rule`, `list_rule_detections`). Mutating tools (`create_rule`, `delete_feed`, `create_reference_list`, `execute_manual_action`) and feed inspection (`list_feeds`) remain in `ADVERTISED_DENIED_TOOLS` so Agent Gateway IAM v3 CEL policies enforce live HTTP 403 denials at the boundary rather than relying on LLM self-refusal.

## Live Logstory `RULES_SEARCH_WORKSHOP` replay

To validate `score_alerts_rubric` against realistic Windows enterprise telemetry, we replayed the Logstory `RULES_SEARCH_WORKSHOP` dataset into the test Google SecOps tenant:

- **Ingested telemetry volumes:** `POWERSHELL` (`3,791+` events), `WINEVTLOG` (`6,975+` events), and `WINDOWS_SYSMON` (`6,350+` events).
- **Live A2A hunt (`ntdsutil.exe`):** Querying Chronicle OneMCP via `udm_search` surfaced routine OS/Defender DNS lookups alongside a credential-dumping event where user `frank.kolzig` executed `ntdsutil.exe` on `activedir.stackedpads.local` (`10.1.0.4`).
- **Rubric output:** `score_alerts_rubric` scored the `ntdsutil.exe` batch at **`3.95 / 5.0`** (`severity_level: 4`, High Severity), **`79.96%`** true-positive probability (`likely: true`), **`Credential Access`** (`mitre_tactic: "credential_access"`), and **`escalate_tier2`** (`next_action`).

![Live A2A trace of Logstory RULES_SEARCH_WORKSHOP replay and Decision 1 scoring](images/decision1/06_logstory_live_a2a_trace.png)\
*Figure 2. Live A2A trace against the deployed `soc_orchestrator` showing `threat_hunter` retrieving replayed `RULES_SEARCH_WORKSHOP` events and scoring the `ntdsutil.exe` activity at `3.95 / 5.0` (`79.96%` TP, `Credential Access`, `escalate_tier2`).*

![Calibrated probabilities and confidence distributions from Decision 1](images/decision1/03_calibrated_probabilities.png)\
*Figure 3. Calibrated probability distributions (`noul`, `choice.probabilities`, and `score` levels) produced by `gemini-decision-1` without generating output tokens.*

## Sanitized `POST /v1beta/decisions` request and response

### Sanitized request (`score_alerts_rubric`)

```json
{
  "model": "gemini-decision-1",
  "input": "Evaluate the following Chronicle SIEM security alerts or UDM events:\n\n{\n  \"event_id\": \"sysmon-ntdsutil-004\",\n  \"log_type\": \"WINDOWS_SYSMON\",\n  \"dataset\": \"RULES_SEARCH_WORKSHOP\",\n  \"principal\": {\n    \"hostname\": \"activedir.stackedpads.local\",\n    \"ip\": \"10.1.0.4\",\n    \"user\": {\n      \"userid\": \"frank.kolzig\"\n    }\n  },\n  \"target\": {\n    \"process\": {\n      \"command_line\": \"ntdsutil.exe \\\"ac i ntds\\\" \\\"ifm\\\" \\\"create full c:\\\\temp\\\\ntds_dump\\\" q q\",\n      \"file\": {\n        \"full_path\": \"C:\\\\Windows\\\\System32\\\\ntdsutil.exe\"\n      }\n    }\n  }\n}",
  "questions": {
    "severity": {
      "type": "score",
      "instructions": "Score the overall security severity of this Chronicle SIEM alert or UDM event batch.",
      "criteria": [
        "Informational or benign activity with no security impact.",
        "Low severity anomaly or policy notice requiring routine review.",
        "Medium severity suspicious activity warranting analyst investigation.",
        "High severity likely threat activity with potential host or account impact.",
        "Critical severity active compromise, lateral movement, or data exfiltration."
      ]
    },
    "true_positive": {
      "type": "noul",
      "instructions": "Determine whether this alert or UDM event batch represents a true positive security threat rather than benign administrative activity or a false positive."
    },
    "mitre_tactic": {
      "type": "choice",
      "instructions": "Select the primary MITRE ATT&CK tactic represented by this alert or UDM event batch.",
      "criteria": {
        "initial_access": "Phishing, exploit public-facing application, or external remote service entry.",
        "execution": "Command and scripting interpreter, PowerShell, WMI, or malicious binary execution.",
        "persistence": "Scheduled tasks, registry run keys, new accounts, or startup modifications.",
        "privilege_escalation": "Token manipulation, sudo abuse, UAC bypass, or elevation to admin or SYSTEM.",
        "defense_evasion": "Log clearing, process hollowing, disabling security tools, or obfuscation.",
        "credential_access": "LSASS dumping, brute force, Kerberoasting, or credential harvesting.",
        "discovery": "Network scanning, account or domain enumeration, or host reconnaissance.",
        "lateral_movement": "SMB, WinRM, RDP, or SSH pivoting or remote service execution across hosts.",
        "collection_exfiltration": "Staging archives, unusual outbound transfers, or DNS or HTTP exfiltration.",
        "command_and_control": "Beaconing, C2 callbacks, or anomalous external encrypted channels.",
        "other_or_benign": "Other tactic not listed above, or benign or inconclusive activity."
      }
    },
    "next_action": {
      "type": "choice",
      "instructions": "Select the recommended next SOC triage action for this alert or UDM event batch.",
      "criteria": {
        "dismiss": "Benign or clear false positive; close or deprioritize without further escalation.",
        "enrich_cti": "Suspicious indicators present; enrich IPs, domains, or hashes via CTI before escalating.",
        "escalate_tier2": "High-confidence threat or active compromise; escalate to Tier 2 for containment.",
        "tune_yaral2": "Noisy or overly broad Chronicle SIEM YARA-L 2.0 detection rule; send to Detection Engineering for tuning."
      }
    }
  }
}
```

### Sanitized response (`score_alerts_rubric`)

```json
{
  "answers": {
    "severity": {
      "type": "score",
      "score": 2.95,
      "confidence": 0.8412
    },
    "true_positive": {
      "type": "noul",
      "noul": 0.7996,
      "confidence": 0.7996
    },
    "mitre_tactic": {
      "type": "choice",
      "choice": "credential_access",
      "confidence": 0.9145,
      "probabilities": {
        "credential_access": 0.9145,
        "execution": 0.0482,
        "privilege_escalation": 0.0211,
        "discovery": 0.0094,
        "other_or_benign": 0.0068
      }
    },
    "next_action": {
      "type": "choice",
      "choice": "escalate_tier2",
      "confidence": 0.8834,
      "probabilities": {
        "escalate_tier2": 0.8834,
        "enrich_cti": 0.0891,
        "tune_yaral2": 0.0182,
        "dismiss": 0.0093
      }
    }
  },
  "usage": {
    "promptTokenCount": 428,
    "candidatesTokenCount": 0,
    "totalTokenCount": 428
  }
}
```

`score_alerts_rubric` shifts `answers.severity.score` (`2.95`) by `+1.0` to `3.95` (`severity_level: 4`), sets `true_positive.likely: true` (`0.7996 >= 0.5`), and returns `mitre_tactic: "credential_access"` and `next_action: "escalate_tier2"`.

See [Gemini Decision 1 for Governed SOC Agents](gemini_decision_1.md) for the full 5-agent architecture and [Case Study: Single-Pass Pre-Flight Routing and Live Alert Rubric Triage](gemini_decision_1_case_study.md) for the end-to-end `soc_orchestrator` walkthrough.
