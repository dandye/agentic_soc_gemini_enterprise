# Tier-2 Responder: Advisory Containment Readiness and Semantic Governance

The Tier-2 Incident Responder (`tier2_responder`) uses [Gemini Decision 1](https://ai.google.dev/gemini-api/docs/decisions) (`gemini-decision-1`) via `assess_containment_readiness` to score endpoint and identity containment requests in **one zero-output-token pass** while preserving a hard architectural invariant: **`advisory_only: True`**. Python tools never self-refuse or block containment execution. Instead, every proposed containment call still reaches the Agent Gateway so Vertex AI Semantic Governance (`terraform/65-semantic-governance.tf`) remains the sole authoritative policy enforcement boundary.

![Advisory containment readiness architecture showing Decision 1 scoring and Agent Gateway Semantic Governance enforcement](images/decision1/14_tier2_advisory_containment.png)\
*Figure 1. Architecture of `tier2_responder.assess_containment_readiness` (`advisory_only: True`), showing single-pass Decision 1 metadata scoring (`asset_tier`, `evidence_sufficiency`, `has_change_ticket`, `requires_human_approval`) without blocking Python calls, leaving Agent Gateway Semantic Governance (`case_4a` deny vs. `case_4b` allow on `DC-PROD-01`) authoritative at the boundary.*

## Single-pass readiness scoring (`assess_containment_readiness`)

Defined in `governed_agents/tier2_responder/response_tools.py`, `assess_containment_readiness(target, action_type, evidence_summary, change_ticket="")` normalizes the target hostname or identity, proposed action (`isolate_endpoint_host`, `disable_compromised_account`, or `block_malicious_ioc`), evidence summary, and optional `CHG-*` ticket into a structured `input_text` payload and batches four questions in `_CONTAINMENT_READINESS_QUESTIONS` into a single `POST /v1beta/decisions` request:

| Question ID | Decision 1 type | Values / scale | Purpose |
| --- | --- | --- | --- |
| `asset_tier` | `choice` | `workstation`, `server`, `tier0_crown_jewel`, `unknown` | Classifies the target asset or identity (for example `WKSTN-*`, `SRV-*`/`APP-*`, or Tier-0 Domain Controllers `DC-*`/`PROD-DC-*` and privileged accounts `admin@*`/`krbtgt`). |
| `evidence_sufficiency` | `score` | 0-indexed `0..4`, shifted `+1.0` to `1.0–5.0` | Grades corroborating alert, indicator, and telemetry strength from no verifiable evidence (`1.0`) to high-confidence confirmed compromise (`5.0`). |
| `has_change_ticket` | `noul` | Probability `0.0–1.0` (`has_change_ticket_noul`) | Evaluates whether an emergency change-control ticket matching `CHG-<digits>` is present. |
| `requires_human_approval` | `noul` | Probability `0.0–1.0` (`requires_human_approval_noul`) | Estimates whether human change-control approval is needed (such as Tier-0 Crown Jewel infrastructure or privileged directory accounts without an emergency `CHG-` ticket). |

When `evidence_sufficiency` returns a 0-indexed `score` from the Decisions API, `assess_containment_readiness` applies `round(float(raw_score) + 1.0, 2)` so the returned `evidence_sufficiency_score` aligns with the `1.0–5.0` operational rubric.

### Sanitized `POST /v1beta/decisions` request

```json
{
  "model": "gemini-decision-1",
  "input": "Proposed Containment Action: isolate_endpoint_host\nTarget: DC-PROD-01\nChange Ticket: NONE\nEvidence Summary: Suspected Kerberoasting activity targeting service principal accounts from WKSTN-FIN-042.",
  "questions": {
    "asset_tier": {
      "type": "choice",
      "instructions": "Classify the target asset or identity tier for this containment request.",
      "criteria": {
        "workstation": "Standard end-user workstation, laptop, or client endpoint (for example WKSTN-* or standard user account).",
        "server": "Standard application, file, database, or member server (for example SRV-* or APP-*) that is not Tier-0 identity infrastructure.",
        "tier0_crown_jewel": "Tier-0 Crown Jewel identity or infrastructure asset such as Domain Controllers (DC-*, PROD-DC-*), root certificate authorities, identity providers, or privileged directory accounts (admin@*, krbtgt).",
        "unknown": "Target naming and context are insufficient to determine the asset tier."
      }
    },
    "evidence_sufficiency": {
      "type": "score",
      "instructions": "Score how sufficient the incident evidence summary is to justify the proposed containment action.",
      "criteria": [
        "No verifiable alert, indicator, or compromise evidence provided.",
        "Weak or circumstantial indicator only without corroborating telemetry.",
        "Moderate single-source alert or indicator match needing more context.",
        "Strong corroborated detection or confirmed malicious activity.",
        "High-confidence confirmed compromise with explicit alert, indicator, and attribution."
      ]
    },
    "has_change_ticket": {
      "type": "noul",
      "instructions": "Does the containment request include a valid emergency change-control ticket ID matching CHG-<digits>?"
    },
    "requires_human_approval": {
      "type": "noul",
      "instructions": "Does this containment action require human change-control approval before execution, such as Tier-0 Crown Jewel infrastructure or privileged directory accounts without an emergency CHG- ticket?"
    }
  }
}
```

### Sanitized `POST /v1beta/decisions` response

```json
{
  "answers": {
    "asset_tier": {
      "type": "choice",
      "choice": "tier0_crown_jewel",
      "confidence": 0.9941,
      "probabilities": {
        "tier0_crown_jewel": 0.9941,
        "server": 0.0042,
        "workstation": 0.0011,
        "unknown": 0.0006
      }
    },
    "evidence_sufficiency": {
      "type": "score",
      "score": 2.35,
      "confidence": 0.7640
    },
    "has_change_ticket": {
      "type": "noul",
      "noul": 0.0085,
      "confidence": 0.9915
    },
    "requires_human_approval": {
      "type": "noul",
      "noul": 0.9924,
      "confidence": 0.9924
    }
  },
  "usage": {
    "promptTokenCount": 248,
    "candidatesTokenCount": 0,
    "totalTokenCount": 248
  }
}
```

`assess_containment_readiness` shifts `evidence_sufficiency.score` from `2.35` to **`3.35 / 5.0`** and returns `advisory_only: True` with `enforcement_note`: `"Advisory metadata only. Agent Gateway Semantic Governance enforces containment policy."`

## Why `advisory_only: True` is a hard architectural invariant

Neither `response_tools.py` nor the `tier2_responder` system instruction in `governed_agents/tier2_responder/agent.py` is permitted to block or self-refuse containment calls (`isolate_endpoint_host`, `disable_compromised_account`, or `block_malicious_ioc` readiness checks / Chronicle reference-list IOC updates). Specifically:

1. **No Python-side policy enforcement:** `isolate_endpoint_host(hostname, reason, change_ticket="")` and `disable_compromised_account(username, reason, change_ticket="")` intentionally contain zero conditional checks on `DC-*`, `PROD-DC-*`, `admin@*`, or `CHG-*`. Every `assess_containment_readiness` return payload hardcodes `"advisory_only": True`.
2. **No LLM self-refusal:** `INSTRUCTION` in `governed_agents/tier2_responder/agent.py` explicitly mandates: *"You refuse NOTHING yourself... If an operator asks to isolate `DC-PROD-01` or disable `admin@example.com` without a `CHG-*` ticket, you MUST still emit the `isolate_endpoint_host` or `disable_compromised_account` tool call so Semantic Governance evaluates and blocks the action at the gateway. Self-refusing in prose hides the security control."*
3. **Authoritative Gateway enforcement (`case_4a` vs. `case_4b`):** Because `tier2_responder` always emits the proposed tool call on `:generateContent`, the Agent Gateway inline `CONTENT_AUTHZ` callout to the Vertex AI Semantic Governance Policy Engine (`terraform/65-semantic-governance.tf`) inspects the natural-language intent at the boundary:
   - **`case_4a_sgp_crown_jewel_deny`:** Isolating `DC-PROD-01` for suspected Kerberoasting activity without a `CHG-*` ticket is blocked at the Agent Gateway by the Tier-0 Crown Jewel Change-Control policy.
   - **`case_4b_sgp_crown_jewel_allow`:** Isolating `DC-PROD-01` for confirmed Active Directory Golden Ticket compromise under approved emergency change ticket `CHG-20261105` passes Semantic Governance and executes `isolate_endpoint_host`.
4. **Fail-safe offline behavior:** When neither `GEMINI_AUTH_PROVIDER` nor `GEMINI_API_KEY` is configured, `decision_client.py` returns `{"enabled": False, ...}` and `assess_containment_readiness` returns `advisory_only: True` with `decision_model_enabled: False` so unit tests and containment workflows remain deterministic.

![Live smoke test and Auth Manager verification summary showing case_4a deny and case_4b allow](images/decision1/08_live_smoke_and_authmanager.png)\
*Figure 2. Live 6/6 `just governance-smoke-test` verification including `case_4a_sgp_crown_jewel_deny` (Tier-0 `DC-PROD-01` blocked without `CHG-*`) and `case_4b_sgp_crown_jewel_allow` (`DC-PROD-01` allowed with `CHG-20261105`), alongside Auth Manager (`agw-secops-gemini-api-key`) and `generativelanguage.googleapis.com` binding.*

## Governance, Auth Manager, and `AgentSkill` registration

`tier2_responder` operates under two independent Agent Gateway controls (`terraform/50-policies-egress.tf` and `terraform/65-semantic-governance.tf`) and authenticates its Decision 1 calls without static API keys:

- **Auth Manager (`GEMINI_AUTH_PROVIDER`):** `governed_agents/tier2_responder/decision_client.py` exchanges the container's SPIFFE workload identity token via `google.auth.default()` at `https://agentidentitycredentials.googleapis.com/v1/<provider>/credentials:retrieve` (`userId: "tier2_responder"`) to fetch the Gemini API key into process memory at call time.
- **IAM v3 tool allowlist:** Permits Chronicle SIEM alert triage and containment reference-list updates (`list_security_alerts`, `get_security_alert`, `update_security_alert`, `fetch_alert_data`, `search_entity`, `summarize_entity`, `get_ioc_match`, `udm_search`, `get_reference_list`, `create_reference_list`, `update_reference_list`), while denying ingestion admin tools (`delete_feed`, `activate_parser`) at the gateway.
- **`AgentSkill` registration:** `agent_card` in `governed_agents/tier2_responder/agent.py` registers `assess_containment_readiness` alongside `endpoint_and_account_containment` and `siem_alert_and_reference_list_response`, advertising advisory readiness scoring to `soc_orchestrator` over A2A.

![End-to-end architecture of Gemini Decision 1 across all five governed SOC agents](images/decision1/04_architecture_decision1_soc.png)\
*Figure 3. End-to-end architecture showing `tier2_responder` alongside `soc_orchestrator` and the other specialist agents authenticating via Agent Platform Auth Manager (`GEMINI_AUTH_PROVIDER`) and egressing through `agw-secops-egress` to `generativelanguage.googleapis.com`.*

See [Gemini Decision 1 for Governed SOC Agents](gemini_decision_1.md) for the full 5-agent architecture and benchmark summary, and [Case Study: Single-Pass Pre-Flight Routing and Live Alert Rubric Triage](gemini_decision_1_case_study.md) for the `soc_orchestrator` pre-flight routing walkthrough.
