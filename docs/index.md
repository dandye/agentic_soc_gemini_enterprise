# Agentic SOC for Gemini Enterprise

End-to-end multi-agent Security Operations Center (SOC) platform built on the Google Agent Development Kit (ADK), Vertex AI Agent Engine, Google Security Operations (Chronicle SIEM and SOAR), Wiz Cloud Security Graph, Google Threat Intelligence (GTI), AlloyDB `pgvector`, and Gemini Enterprise.

```{grid} 1 2 2 3
:gutter: 3

:::{grid-item-card} Getting Started & Gemini Enterprise Hub
:link: setup
:link-type: doc

Configure Google Cloud APIs, Vertex AI Reasoning Engines, 3LO OAuth Interactions API passthrough, `GLiNER 2.5` (373.5 ms CPU router), evolved `Gemma` Tier-1 triage, and Gemini Enterprise registration.
:::

:::{grid-item-card} Multi-Agent SOC & Wizard_Agent
:link: architecture
:link-type: doc

Coordinate `SOC_Orchestrator`, `tier1_analyst` (`SkillToolset` runbooks), `Wizard_Agent` (Wiz Cloud Graph & Attack Path MCP), `Threat_Hunter`, `CTI_Researcher`, `Detection_Engineer` (Chronicle SIEM YARA-L 2.0), and `Tier2_Responder`.
:::

:::{grid-item-card} Multi-Store Grounding & 5D Memory
:link: grounding_architecture
:link-type: doc

Ground investigations across AlloyDB `pgvector` (258 cases, 1,183 entities, 5D similarity profiles), Neo4j Attack Graphs, Dataplex Threat Actor Glossaries, Elasticsearch, RAG runbooks, and Vertex Memory Bank.
:::

:::{grid-item-card} Sandboxed Python & Google Chat ChatOps
:link: code_execution_architecture
:link-type: doc

Execute DGA entropy, C2 beacon jitter, and dropper forensics inside Cloud MicroVM/gVisor Python sandboxes, paired with 55 HMAC-SHA256 Google Chat ChatOps approval cards.
:::

:::{grid-item-card} Evaluation & AQuA Quality Loop
:link: evaluations
:link-type: doc

Measure agent quality across 10 `.evalset.json` suites (54 cases including 25 multi-turn pivots), Cloud Trace AQuA outer-loop diagnostics, a 3-persona simulator, and the 30% to 95% Expert benchmark.
:::

:::{grid-item-card} Agent Gateway & Decision 1 Governance
:link: agent_governance
:link-type: doc

Enforce keyless SPIFFE identities, default-deny Agent Gateway egress, IAM v3 CEL allowlists (`agw-secops-wiz-tools`), Model Armor, `CHG-*` Semantic Governance, sub-300 ms `gemini-decision-1` v2 guards, and `$0/hr` idle scale-to-zero.
:::
```

## Documentation Sections

```{toctree}
:maxdepth: 2
:caption: Overview & Setup

welcome
setup
commands
troubleshooting
```

```{toctree}
:maxdepth: 2
:caption: Architecture & Multi-Store Grounding

architecture
grounding_architecture
databases
alloydb_gcp_deployment_guide
alloydb_similarity_engine_summary
similarity_profiles
knowledge_catalog_vs_neo4j
threat_actor_glossary
```

```{toctree}
:maxdepth: 2
:caption: Sandboxed Analytics & ChatOps

code_execution_architecture
chatops_chat_app
```

```{toctree}
:maxdepth: 2
:caption: Evaluation & AQuA Quality Loop

evaluations
adk_evals_framework_guide
experimentation_playbook
aqua_goal
```

```{toctree}
:maxdepth: 2
:caption: Agent Governance & Decision 1 Guards

agent_governance
agent_governance_design
gemini_decision_1
gemini_decision_1_benchmarks
gemini_decision_1_case_study
gemini_decision_1_cti_ioc_triage
gemini_decision_1_threat_hunting
gemini_decision_1_v2_workflows
gemini_decision_1_simple_demos
gemini_decision_1_v2_injection_guard
gemini_decision_1_v2_tool_pruning
gemini_decision_1_v2_bayes_gate
gemini_decision_1_v2_multimodal_ingress
agent_governance_troubleshooting
```

```{toctree}
:maxdepth: 2
:caption: Reference & Roadmap

reference/README
reference/memory
reference/methodologies/threat_hunting/bulk_domain_hunting
future_work
superpowers/specs/2026-08-31-vertex-code-execution-sandbox-design
superpowers/plans/2026-08-31-vertex-code-execution-sandbox
superpowers/plans/2026-11-06-agent-governance-stack
```
