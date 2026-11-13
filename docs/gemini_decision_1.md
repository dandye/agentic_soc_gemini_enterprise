# Gemini Decision 1 for Governed SOC Agents

[Gemini Decision 1](https://ai.google.dev/gemini-api/docs/decisions) (`gemini-decision-1` on `https://generativelanguage.googleapis.com/v1beta/decisions`) is a non-generative classification, scoring, and routing model purpose-built for structured triage. Instead of generating free-form JSON text tokens, Decision 1 evaluates one input payload against a dictionary of questions in a single forward pass and returns calibrated probabilities (`noul`), discrete labels (`choice`), and expected ordinal scores (`score`) with **zero output tokens**.

This guide documents how Decision 1 is integrated into the governed SecOps stack under `governed_agents/` where it eliminates downstream LLM turns and filters high-volume telemetry before the generative model runs, how credentials and egress are governed via Agent Platform Auth Manager and the egress Agent Gateway, and what the apples-to-apples live benchmark (`thinkingBudget=0`) and Logstory replay demonstrate.

## Architecture across the governed SOC stack

Every Decision 1 call in `governed_agents/` uses a lightweight `httpx` REST client (`decision_client.py`) rather than modifying the pinned `google-adk==2.13.0` or `google-genai==2.34.0` dependencies. Each client reuses a module-level `httpx.Client` (and loop-scoped `httpx.AsyncClient` in `soc_orchestrator`) and caches Auth Manager credentials in memory with a 300-second TTL (`GEMINI_AUTH_TOKEN_TTL_SECONDS`). When neither `GEMINI_AUTH_PROVIDER` nor `GEMINI_API_KEY` is configured, the client returns `{"enabled": False, ...}` so hermetic CI and unit tests pass without network access.

![Architecture diagram of Gemini Decision 1 integrated into the governed SOC stack behind the egress Agent Gateway and Auth Manager](images/decision1/04_architecture_decision1_soc.png)\
*Figure 1. End-to-end architecture showing `soc_orchestrator` `LlmResponse` short-circuit routing, `threat_hunter` `after_tool_callback` pre-LLM UDM noise filtering, `cti_researcher` unstructured/multimodal CTI triage, and clean `detection_engineer` and `tier2_responder` baselines behind `agw-secops-egress`.*

| Agent | Decision 1 integration | What it replaces or avoids | Enforcement boundary |
| --- | --- | --- | --- |
| `soc_orchestrator` | `before_model_callback` (`_preflight_before_model_callback`) evaluates 6 questions (`4 noul`, `1 choice`, `1 score`) | On initial user turns (`len(contents) == 1`) with `workflow_mode == "single_specialist"` and exactly one specialist `noul >= 0.90`, returns `LlmResponse(function_call=...)` directly—bypassing `gemini-4-hydrogen` on the routing turn | Never blocks or self-refuses; falls back to `[PREFLIGHT_ROUTING]` hint on multi-stage or ambiguous turns |
| `threat_hunter` | `after_tool_callback` (`_filter_udm_events_after_tool_callback`) on `udm_search` and `list_security_alerts` | Evaluates each returned UDM event/alert in parallel without `[:32000]` truncation: drops `P(tp) < 0.30` noise before `threat_hunter_llm`, keeps `0.30–0.85` with `decision1_triage` metadata, tags `>= 0.85` with `[HIGH_CONFIDENCE_ESCALATE]` | Read-only Chronicle OneMCP hunt allowlist (`roles/chronicle.viewer`) |
| `cti_researcher` | `triage_unstructured_cti_artifact(content, mime_type="text/plain")` | Evaluates unstructured threat prose, OSINT reports, PDFs, and screenshots (`type: "text"`, `"image"`, `"document"`) in one pass | Lateral isolation to `www.virustotal.com`, `generativelanguage.googleapis.com`, and `agentidentitycredentials.googleapis.com` |
| `detection_engineer` | Clean baseline (no Decision 1 tool) | Uses Chronicle OneMCP `validate_rule` and `evaluate_rule_coverage` directly instead of redundant LLM grading | Chronicle OneMCP validation allowlist; explicitly distinguishes **YARA-L 2.0** from standard YARA |
| `tier2_responder` | Clean baseline (no Decision 1 tool) | Executes containment tools directly without in-container self-gating | Agent Gateway Semantic Governance enforces Tier-0 Crown Jewel policy (`DC-*`, `admin@*`) |

![Pre-flight short-circuit routing and pre-LLM UDM noise filtering flow](images/decision1/05_preflight_and_advisory_flow.png)\
*Figure 2. `soc_orchestrator` `LlmResponse` short-circuit bypassing `gemini-4-hydrogen` on decisive single-specialist turns and `threat_hunter` `after_tool_callback` dropping low-signal UDM noise (`P(tp) < 0.30`) before `gemini-3.8-flash` runs.*

![Agent card skill matrix across all five governed Reasoning Engines](images/decision1/09_live_agent_cards_skills.png)\
*Figure 3. Updated `terraform/agentcards/*.json` skill inventory across all five governed Reasoning Engines (`preflight_routing_triage`, `triage_unstructured_cti_artifact`, `after_tool_callback` UDM filter, and clean `detection_engineer` and `tier2_responder` baselines).*

### YARA-L 2.0 vs. standard YARA

Across `soc_orchestrator`, `threat_hunter`, and `detection_engineer`, the stack explicitly distinguishes **YARA-L 2.0** from **standard YARA**:

- **YARA-L 2.0 (Chronicle SIEM UDM):** Event correlation rules evaluated over Unified Data Model (UDM) telemetry with `meta`, `events`, `match`, `outcome`, and `condition` sections, validated authoritatively by Chronicle OneMCP `validate_rule`.
- **Standard YARA:** File, memory, or binary payload pattern-matching rules using `strings` and `condition` over raw bytes or artifacts—not Chronicle SIEM UDM event rules.

## Auth Manager and Agent Gateway egress

No static Gemini API key is placed in container environment variables or Terraform state:

1. **Auth Manager (`terraform/20-authmanager.tf`):** `terraform_data.gemini_auth_provider` creates the `agw-secops-gemini-api-key` AuthProvider in Agent Platform Auth Manager from `TF_VAR_gemini_api_key` (never written to state). `terraform_data.gemini_auth_provider_grant` sequentially grants `roles/agentidentity.user` on that provider to all five agents' SPIFFE workload identities.
2. **Runtime credential retrieval with 300s TTL cache (`GEMINI_AUTH_PROVIDER`):** `terraform/41-agents.tf` injects `GEMINI_AUTH_PROVIDER` (the resource name) into each Reasoning Engine. At call time, `decision_client.py` exchanges the agent's SPIFFE workload identity token at `https://agentidentitycredentials.googleapis.com/v1/<provider>/credentials:retrieve` and caches the token in process memory for 300 seconds (`GEMINI_AUTH_TOKEN_TTL_SECONDS`).
3. **Default-deny Agent Gateway (`terraform/10-registry-endpoints.tf`):** `generativelanguage.googleapis.com` is registered in `google_api_hosts_global` (as `<region>-g-generativelanguage`) alongside `agentidentitycredentials.googleapis.com` so engines reach the Decisions API through `agw-secops-egress` without opening arbitrary egress.

![Live smoke test and Auth Manager verification summary](images/decision1/08_live_smoke_and_authmanager.png)\
*Figure 4. Live 6/6 `just governance-smoke-test` verification and Auth Manager (`agw-secops-gemini-api-key`) + `generativelanguage.googleapis.com` Agent Registry binding.*

![Live Agent Gateway telemetry showing allowed egress hosts and denied unregistered tool calls](images/decision1/10_live_gateway_telemetry.png)\
*Figure 5. Live `scripts/governance/verify_logs.sh` gateway telemetry confirming `200 ALLOWED` egress to `generativelanguage.googleapis.com`, `agentidentitycredentials.googleapis.com`, and `chronicle.googleapis.com` alongside `403 DENY` enforcement for disallowed MCP tools.*

## The three Decision 1 question types

Every Decision 1 request batches multiple questions against a single `input` payload (either text or multimodal `type: "text"` / `"image"` / `"document"` parts) using three structured primitives:

1. **`noul` (binary probability):** Returns a calibrated probability in `[0.0, 1.0]` plus `confidence`. Used for specialist routing flags (`needs_cti`, `needs_threat_hunt`, `needs_detection_eng`, `needs_tier2_response`), `true_positive` noise-drop/escalation thresholds (`< 0.30` / `>= 0.85`), `is_actionable_threat`, and `requires_immediate_hunt`.
2. **`choice` (single-label classification):** Evaluates a `dict[str, str]` of label descriptions and returns the winning `choice`, `confidence`, and full `probabilities` distribution over all labels. Used for `workflow_mode`, `threat_category`, `mitre_tactic`, and `next_action`.
3. **`score` (0-indexed ordinal rubric + `+1.0` shift):** Evaluates an ordered `list[str]` of rubric levels. Because Decision 1 returns a **0-indexed** expected score (`0.0` to `N-1`), `decision_client.py` preserves `raw_score` and shifts `score = raw_score + 1.0` to align with 1–5 operational scales (`1.0–5.0` for `urgency`, `severity`, and `confidence_score`).

![Decision 1 question types diagram showing noul, choice, and 0-indexed score with +1.0 shift across the refactored agents](images/decision1/07_decision1_question_types.png)\
*Figure 6. The three Decision 1 question types (`noul`, `choice`, and 0-indexed `score` shifted `+1.0` to a `1.0–5.0` operational scale) mapped across `soc_orchestrator`, `threat_hunter`, and `cti_researcher`.*

![Calibrated probabilities and confidence distributions from Decision 1](images/decision1/03_calibrated_probabilities.png)\
*Figure 7. Calibrated per-label probability distributions and confidence scores returned by Decision 1 across routing, UDM filtering, and unstructured CTI triage.*

## Logstory `RULES_SEARCH_WORKSHOP` end-to-end replay

To validate Decision 1 against realistic security telemetry in the test Google SecOps tenant, we replayed the Logstory `RULES_SEARCH_WORKSHOP` dataset (Windows PowerShell, Windows Event Log, and Sysmon process/network events) into Chronicle SIEM and ran live A2A queries against the deployed `soc_orchestrator`:

- **`threat_hunter` (`_filter_udm_events_after_tool_callback`):** Retrieved the replayed `RULES_SEARCH_WORKSHOP` PowerShell/Sysmon events via Chronicle OneMCP `udm_search`. Routine OS/Defender DNS lookups (`P(tp) < 0.30`) are filtered before the LLM runs, while the `ntdsutil.exe` credential-dumping event (`frank.kolzig` on `activedir.stackedpads.local`) is tagged `[HIGH_CONFIDENCE_ESCALATE]` with `severity_score = 3.95 / 5.0`, `79.96%` true-positive probability, `credential_access`, and `escalate_tier2`.
- **`detection_engineer` (`validate_rule`):** Validates `dns_tunneling_distinct_subdomains_T1048` directly via Chronicle OneMCP `validate_rule` (`success: true`, `usesUdm: true`).

![Live A2A trace of Logstory RULES_SEARCH_WORKSHOP replay and Decision 1 filtering](images/decision1/06_logstory_live_a2a_trace.png)\
*Figure 8. Live A2A trace against the deployed `soc_orchestrator` showing `RULES_SEARCH_WORKSHOP` PowerShell/Sysmon UDM hunting and Chronicle OneMCP `validate_rule` (`success: true`).*

## Live apples-to-apples benchmark (`thinkingBudget=0`)

`scripts/governance/benchmark_decision1.py` benchmarks `gemini-3.8-flash` with `thinkingBudget=0` (`39` calls across `13` cases × `3` iterations) against `gemini-decision-1` (`$0.10/1M` input, `$0.00/1M` output) across the three refactored SOC workloads (`preflight`, `udm_filter`, and `cti_artifact`):

| Metric | Generative (`gemini-3.8-flash`, `thinkingBudget=0`) | Gemini Decision 1 (`gemini-decision-1`) | Improvement |
| --- | --- | --- | --- |
| Calls | `39` | `39` | — |
| Total input tokens | `11,622` | `23,694` | `2.04x` input token footprint (no output tokens) |
| Total output tokens | `2,051` | `0` | **100% eliminated** |
| Mean latency (ms) | `3,218.01 ms` | `247.11 ms` | **13.0x faster** |
| p50 latency (ms) | `3,231.06 ms` | `212.03 ms` | **15.2x faster** |
| p95 latency (ms) | `4,595.49 ms` | `404.58 ms` | **11.4x faster** |
| Estimated cost (USD) | `$0.008614` | `$0.002369` | **3.6x cheaper** |
| Label accuracy | `96.6%` (`171/177`) | `100.0%` (`177/177`) | **100.0% accuracy** (`0` mismatches vs. 6 generative 0-indexing drift misses on `severity`) |
| Calibrated probabilities | `False` | `True` | Native probability & confidence outputs |

### Modeled end-to-end agent savings (estimates)

The following end-to-end savings are **modeled estimates** derived from the benchmarked fast-path triggers rather than direct end-to-end wall-clock measurements:

- **Orchestrator short-circuit (`preflight`):** `6/12` calls bypassed `gemini-4-hydrogen`, saving an estimated ~`12,120` tokens and ~`19,200 ms` of orchestrator reasoning latency.
- **Pre-LLM UDM noise drop (`udm_filter`):** `9/18` events dropped (`P(tp) < 0.30`) and `9/18` fast-escalated (`P(tp) >= 0.85`), saving an estimated ~`4,050` downstream `gemini-3.8-flash` input tokens.

![Latency comparison between generative Flash with thinkingBudget=0 and Gemini Decision 1](images/decision1/01_latency_comparison.png)\
*Figure 9. Apples-to-apples latency comparison (`gemini-3.8-flash` `thinkingBudget=0` vs. `gemini-decision-1`) across `39` live calls: `247.11 ms` vs. `3,218.01 ms` mean (`13.0x`), `212.03 ms` vs. `3,231.06 ms` p50 (`15.2x`), and `404.58 ms` vs. `4,595.49 ms` p95 (`11.4x`).*

![Output tokens, cost, and modeled end-to-end savings comparison between generative Flash and Gemini Decision 1](images/decision1/02_tokens_and_cost.png)\
*Figure 10. Aggregate token footprint (`0` vs. `2,051` output tokens; `23,694` vs. `11,622` input tokens), cost (`$0.002369` vs. `$0.008614`, `3.6x` lower), `100.0%` (`177/177`) vs. `96.6%` (`171/177`) accuracy, and modeled `gemini-4-hydrogen` bypass and UDM noise-drop savings.*

## Running the benchmark and tests

```bash
# Offline unit tests (short-circuit routing, after_tool_callback UDM filter, multimodal CTI triage)
.venv/bin/python -m pytest -o addopts="" tests/test_governed_agents.py

# Dry-run the Decision 1 benchmark (validates payloads without API calls)
.venv/bin/python scripts/governance/benchmark_decision1.py --dry-run

# Live apples-to-apples benchmark (requires GEMINI_API_KEY or ADC + GEMINI_AUTH_PROVIDER)
.venv/bin/python scripts/governance/benchmark_decision1.py --gen-model gemini-3.8-flash --iterations 3 --json-out /tmp/bench_live_v3.json
```

See [Case Study: Single-Pass Pre-Flight Short-Circuit and Pre-LLM UDM Filtering](gemini_decision_1_case_study.md) for sanitized `POST /v1beta/decisions` JSON payloads, or dive into the per-specialist guides:

- [CTI Unstructured & Multimodal Triage (`cti_researcher`)](gemini_decision_1_cti_ioc_triage.md)
- [Threat Hunting Pre-LLM UDM Filter (`threat_hunter`)](gemini_decision_1_threat_hunting.md)

For deployment and architecture details, see [Agent Governance: Deploy, Verify, Operate](agent_governance.md) and [Agent governance design notes](agent_governance_design.md).
