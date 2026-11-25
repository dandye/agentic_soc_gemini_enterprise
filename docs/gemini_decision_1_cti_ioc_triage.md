# CTI Unstructured & Multimodal Triage with Gemini Decision 1

In `governed_agents/cti_researcher/`, the Cyber Threat Intelligence (CTI) Researcher specialist pairs deterministic Google Threat Intelligence (VirusTotal v3) indicator lookups with `triage_unstructured_cti_artifact(content, mime_type="text/plain")` to evaluate **unstructured threat prose, OSINT reports, PDFs, and screenshots** in **one zero-output-token forward pass** using Gemini Decision 1 (`gemini-decision-1` on `https://generativelanguage.googleapis.com/v1beta/decisions`).

By architectural design (`terraform/50-policies-egress.tf`), `cti_researcher` is laterally isolated to external threat intelligence: its SPIFFE workload identity is permitted egress only to `https://www.virustotal.com`, `generativelanguage.googleapis.com`, `agentidentitycredentials.googleapis.com`, and Vertex AI, with zero access to internal Chronicle SIEM/SOAR MCP endpoints or containment tools.

## Multimodal and unstructured CTI triage (`triage_unstructured_cti_artifact`)

While structured GTI/VirusTotal v3 detection counts are already deterministic, analysts frequently paste raw OSINT advisories, incident PDFs, or dashboard screenshots. `triage_unstructured_cti_artifact(content, mime_type="text/plain")` in `governed_agents/cti_researcher/gti_tools.py` routes those artifacts to `evaluate_decisions`:

- **Text artifacts (`text/*`):** Passed directly as a formatted string.
- **Binary/multimodal artifacts (`image/*`, `application/pdf`, `audio/*`, `video/*`):** Normalized in `decision_client.py` into the `v1beta/decisions` multimodal `input` schema (`{"type": "text", "text": ...}` plus `{"type": "image"|"document"|"audio"|"video", "data": "<base64>", "mime_type": "..."}`).

It evaluates **five structured questions** in a single forward pass:

| Question key | Type | Output / Range | Purpose in CTI triage |
| --- | --- | --- | --- |
| `is_actionable_threat` | `noul` | Probability in `[0.0, 1.0]` (`>= 0.5` -> `true`) | Distinguishes concrete, actionable threats from informational or benign content. |
| `threat_category` | `choice` | `malware_delivery`, `command_and_control`, `phishing_credential_theft`, `scanning_exploitation`, `benign_infrastructure`, `other_or_unknown` | Primary threat category plus calibrated `threat_category_confidence`. |
| `severity` | `score` | `1.0–5.0` (0-indexed `0..4` shifted `+1.0`) | Operational threat severity from informational (`1`) to critical (`5`). |
| `requires_immediate_hunt` | `noul` | Probability in `[0.0, 1.0]` (`>= 0.5` -> `true`) | Indicates whether internal SIEM/UDM threat hunting is warranted. |
| `confidence_score` | `score` | `1.0–5.0` (0-indexed `0..4` shifted `+1.0`) | Triage confidence based on technical detail and corroboration in the artifact. |

In the v3 live benchmark (`cti_artifact` workload), `gemini-decision-1` achieved **`100.0%` accuracy** (`177/177` overall vs. `96.6%` for `gemini-3.8-flash` `thinkingBudget=0`) and **`247.11 ms`** overall mean latency (**`13.0x` faster** than `gemini-3.8-flash`'s `3,218.01 ms`) with **zero output tokens**.

![Unstructured and multimodal CTI artifact triage flow using Gemini Decision 1](images/decision1/11_cti_ioc_classification.png)\
*Figure 1. `triage_unstructured_cti_artifact` flow in `governed_agents/cti_researcher/gti_tools.py`, evaluating unstructured prose, PDFs (`type: "document"`), and screenshots (`type: "image"`) with zero output tokens.*

![Output tokens, cost, and modeled end-to-end savings comparison between generative Flash and Gemini Decision 1](images/decision1/02_tokens_and_cost.png)\
*Figure 2. Aggregate output tokens (`0` vs. `2,051`; `2.04x` input token footprint `23,694` vs. `11,622`) and total cost (`$0.002369` vs. `$0.008614`, `3.6x` lower) comparing `gemini-decision-1` against `gemini-3.8-flash` (`thinkingBudget=0`) across governed SOC workloads.*

## Auth Manager (300s TTL cache) and `AgentSkill` registration

### Runtime credential retrieval (`AuthProviderCredentialsServiceClient`)

No static API keys are stored in Terraform state or container environment variables. Instead, `terraform/20-authmanager.tf` provisions two separate Agent Platform Auth Manager providers and `terraform/41-agents.tf` injects only their resource names into `cti_researcher`:

1. **`GTI_AUTH_PROVIDER` (`<prefix>-gti-api-key`):** Holds the VirusTotal v3 API key and grants `roles/agentidentity.user` exclusively to `cti_researcher`.
2. **`GEMINI_AUTH_PROVIDER` (`<prefix>-gemini-api-key`):** Holds the Gemini Decisions API key and grants `roles/agentidentity.user` to all five governed Reasoning Engines.

At tool-call time, `governed_agents/cti_researcher/decision_client.py` resolves the Gemini credential in `_get_gemini_api_key()` with a **300-second in-memory TTL cache** (`GEMINI_AUTH_TOKEN_TTL_SECONDS`) and a shared module-level `httpx.Client` (`_get_http_client()`):

- When `GEMINI_AUTH_PROVIDER` is set, it calls `retrieve_credentials(RetrieveCredentialsRequest(auth_provider=provider_name, user_id="cti_researcher"))` against `agentidentitycredentials.googleapis.com` using the agent's SPIFFE workload identity.
- If `GEMINI_AUTH_PROVIDER` is unset, it falls back to `GEMINI_API_KEY`; if neither is configured, `evaluate_decisions` returns `{"enabled": False, ...}` so hermetic unit tests run without network access.

### A2A `AgentSkill` registration

In `governed_agents/cti_researcher/agent.py`, `triage_unstructured_cti_artifact` is attached to `cti_llm.tools` and advertised on the A2A `AgentCard` (`create_agent_card`, materialized in `terraform/agentcards/cti_researcher.json`) alongside the three GTI lookup skills (`enrich_file_hash`, `enrich_network_ioc`, `inspect_threat_collection`):

```python
AgentSkill(
    id="triage_unstructured_cti_artifact",
    name="Unstructured and multimodal CTI artifact triage",
    description=(
        "Evaluates unstructured threat prose, OSINT reports, PDFs, or "
        "screenshots in a single zero-output-token pass to classify "
        "actionability, threat category, 1-5 severity, immediate hunt "
        "urgency, and 1-5 confidence."
    ),
    tags=["cti", "triage", "multimodal", "decision", "osint"],
    examples=["Triage this OSINT advisory PDF or threat screenshot"],
)
```

![Agent card skill matrix across all five governed Reasoning Engines](images/decision1/09_live_agent_cards_skills.png)\
*Figure 3. Skill matrix across `terraform/agentcards/*.json` highlighting `triage_unstructured_cti_artifact` on `cti_researcher_agent` alongside `preflight_routing_triage`, `threat_hunter` `after_tool_callback` filtering, and clean `detection_engineer` and `tier2_responder` baselines.*

## Sanitized `POST /v1beta/decisions` multimodal payload

### Sanitized request (`image/png` or `application/pdf` artifact)

```json
{
  "model": "gemini-decision-1",
  "input": [
    {
      "type": "text",
      "text": "Triage this unstructured CTI artifact (image/png) for threat intelligence and SOC actionability."
    },
    {
      "type": "image",
      "data": "<BASE64_ENCODED_ARTIFACT>",
      "mime_type": "image/png"
    }
  ],
  "questions": {
    "is_actionable_threat": {
      "type": "noul",
      "instructions": "True if the artifact describes a concrete, actionable cyber threat, active campaign, or malicious infrastructure relevant to SOC defense; false if informational, benign, or unactionable."
    },
    "threat_category": {
      "type": "choice",
      "instructions": "Select the primary threat category described in the artifact.",
      "criteria": {
        "malware_delivery": "Payload hosting, dropper, downloader, or malicious executable distribution.",
        "command_and_control": "Command-and-control server, beaconing domain/IP, or covert exfiltration channel.",
        "phishing_credential_theft": "Phishing lure, credential harvesting infrastructure, or brand impersonation.",
        "scanning_exploitation": "Vulnerability scanner, brute-force source, or active exploit delivery.",
        "benign_infrastructure": "Legitimate CDN, cloud provider, DNS resolver, or trusted enterprise service.",
        "other_or_unknown": "Threat category does not match the above options or insufficient data is present."
      }
    },
    "severity": {
      "type": "score",
      "instructions": "Rate operational threat severity from lowest (level 0) to critical (level 4) based on impact and urgency.",
      "criteria": [
        "Informational or benign: no active threat or operational impact.",
        "Low severity: minor reconnaissance or low-impact opportunistic activity.",
        "Moderate severity: suspicious campaign or commodity malware requiring standard triage.",
        "High severity: confirmed active malware, C2, or targeted intrusion activity.",
        "Critical severity: active ransomware, zero-day exploitation, or crown-jewel compromise."
      ]
    },
    "requires_immediate_hunt": {
      "type": "noul",
      "instructions": "True if the artifact warrants immediate internal SIEM/UDM threat hunting across endpoints, network logs, or DNS telemetry; false otherwise."
    },
    "confidence_score": {
      "type": "score",
      "instructions": "Rate triage confidence from lowest (level 0) to highest (level 4) based on technical detail and corroboration in the artifact.",
      "criteria": [
        "Very low confidence: vague, unreadable, or minimal threat context.",
        "Low confidence: unverified claims with sparse technical indicators.",
        "Moderate confidence: plausible threat reporting with partial technical detail.",
        "High confidence: detailed TTPs, IOCs, or clear malware/campaign attribution.",
        "Very high confidence: comprehensive technical evidence with corroborated attribution."
      ]
    }
  }
}
```

### Sanitized response

```json
{
  "answers": {
    "is_actionable_threat": { "type": "noul", "noul": 0.9410, "confidence": 0.9410 },
    "threat_category": {
      "type": "choice",
      "choice": "command_and_control",
      "confidence": 0.9125,
      "probabilities": {
        "command_and_control": 0.9125,
        "malware_delivery": 0.0540,
        "phishing_credential_theft": 0.0180,
        "scanning_exploitation": 0.0095,
        "other_or_unknown": 0.0040,
        "benign_infrastructure": 0.0020
      }
    },
    "severity": { "type": "score", "score": 2.95, "confidence": 0.8510 },
    "requires_immediate_hunt": { "type": "noul", "noul": 0.9180, "confidence": 0.9180 },
    "confidence_score": { "type": "score", "score": 3.12, "confidence": 0.8740 }
  },
  "usage": {
    "promptTokenCount": 518,
    "candidatesTokenCount": 0,
    "totalTokenCount": 518
  }
}
```

`triage_unstructured_cti_artifact` shifts `severity` (`2.95` + `1.0` = `3.95 / 5.0`) and `confidence_score` (`3.12` + `1.0` = `4.12 / 5.0`), sets `is_actionable_threat: true` and `requires_immediate_hunt: true`, and returns `threat_category: "command_and_control"` with `candidatesTokenCount: 0`.

See [Gemini Decision 1 for Governed SOC Agents](gemini_decision_1.md) for the full architecture, Auth Manager configuration, and aggregate v2 benchmark tables.
