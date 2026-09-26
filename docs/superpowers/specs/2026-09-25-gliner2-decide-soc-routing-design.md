# GLiNER2.5-Decide Multi-Head Operational Classification & SOC Routing Engine
**Design Specification**

## 1. Executive Summary
This design specification defines the architecture, data schemas, and agent integration for incorporating **Fastino's GLiNER2.5-Decide** into `agentic_soc_agentspace`. Unlike classic GLiNER (which performed token-level span extraction for Cyber Threat Intelligence entities in `nlp_capstone`), `GLiNER2.5-Decide` is a 340M DeBERTa-v3-large classifier specialized for zero-shot, multi-head operational decisions executed in a single forward pass (~10–30 ms on CPU/GPU) without prompt templates or autoregressive token generation.

In `agentic_soc_agentspace`, the engine provides an ultra-fast, local gatekeeper and decision router for:
1. **Tier 1 Alert Triage:** Instant severity categorization, urgency scoring, and disposition hypothesis.
2. **Specialist Sub-Agent Dispatch:** Case routing to `tier2_investigator`, `threat_hunter`, `cti_researcher`, or `detection_engineer`.
3. **Human-in-the-Loop (HITL) Gatekeeping:** Autonomous pre-authorization checks before high-impact mitigation and investigation completion gating.
4. **CTI Ingestion Filtering:** Cloud relevance and threat type gating on unstructured threat feeds prior to heavy pipeline processing.

## 2. Architecture & Components

```
 Raw Alert / Case / CTI Text
             │
             ▼
┌───────────────────────────────────────────────┐
│     GLiNERDecideEngine (Thread-Safe Singleton)│
│  - Lazy-loaded `fastino/GLiNER2.5-Decide`     │
│  - In-process CPU/GPU execution via `gliner2` │
│  - Configurable Decision Schemas              │
└──────────────────────┬────────────────────────┘
                       │
       ┌───────────────┼───────────────┬────────────────┐
       ▼               ▼               ▼                ▼
┌──────────────┐┌──────────────┐┌──────────────┐┌──────────────┐
│ Alert Triage ││ Agent Dispatch││  HITL Gate   ││ CTI Relevance│
│ - Severity   ││ - Specialist ││ - Human Sign ││ - Cloud Plat │
│ - Urgency    ││   Assignment ││ - Completion ││ - Threat Type│
│ - Hypothesis ││              ││   Status     ││              │
└──────────────┘└──────────────┘└──────────────┘└──────────────┘
```

### 2.1 Core Engine (`agent_soc_manager/tools/gliner_decide_engine.py`)
* **Class:** `GLiNERDecideEngine`
* **Lifecycle:** Thread-safe singleton (`get_instance()`) with lazy-loaded PyTorch model in process memory.
* **Device Selection:** Auto-selects CUDA if available; defaults cleanly to CPU for sub-50 ms edge execution.
* **Fallback / Offline Mode:** Gracefully handles missing local weights or offline test runners by providing deterministic heuristics or mock outputs during unit testing.
* **Core Method:**
  ```python
  def decide(self, text: str, schema: dict[str, Any], **kwargs) -> dict[str, Any]: ...
  ```

### 2.2 Standard SOC Decision Schemas (`agent_soc_manager/tools/gliner_decide_schemas.py`)
1. **`ALERT_TRIAGE_SCHEMA`:**
   * `severity`: `["critical", "high", "medium", "low", "informational"]`
   * `urgency_tier`: `["p1_immediate_containment", "p2_same_shift_triage", "p3_investigative_backlog"]`
   * `disposition_hypothesis`: `["true_positive_malicious", "benign_scanner_traffic", "rfc5737_test_artifact", "known_false_positive"]`
2. **`SPECIALIST_ROUTING_SCHEMA`:**
   * `assigned_specialist`: `["tier2_investigator", "threat_hunter", "cti_researcher", "detection_engineer"]`
3. **`HITL_POLICY_GATE_SCHEMA`:**
   * `requires_human_approval`: `["requires_soc_manager_approval", "safe_autonomous_investigation"]`
   * `agent_completion_status`: `["investigation_complete", "insufficient_evidence_pivot_required", "blocked_awaiting_telemetry"]`
4. **`CTI_APPLICABILITY_SCHEMA`:**
   * `enterprise_relevance`: `["actionable_threat_advisory", "unrelated_vendor_patch", "general_awareness"]`
   * `target_platform`: `["gcp_cloud", "kubernetes", "windows_ad", "linux_endpoints", "saas_identity"]`

### 2.3 Agent Tools Interface (`agent_soc_manager/tools/gliner_decide_tools.py`)
* Functional tools callable directly by the ADK orchestrator or ReAct sub-agents:
  * `triage_alert_with_gliner(alert_text: str) -> dict[str, Any]`
  * `route_case_to_specialist_with_gliner(case_summary: str) -> dict[str, Any]`
  * `evaluate_hitl_gate_with_gliner(proposed_action: str, context: str) -> dict[str, Any]`
  * `filter_cti_advisory_with_gliner(advisory_text: str) -> dict[str, Any]`

### 2.4 Colab / Jupyter Experimentation Notebook
* Location: `notebooks/gliner2_5_decide_soc_routing.ipynb`
* Reproduces and benchmarks all 4 SOC operational decision heads on representative Chronicle UDM alerts, false positive RFC-5737 tests, and CISA advisories.

## 3. Constraints & Dependencies
* Python: `>=3.11`
* Package: `gliner2[local]`, `torch>=2.2`, `transformers>=4.46`
* Tests: Fully isolated pytest test suite with 100% pass rate.
