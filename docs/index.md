# Agentic SOC for Gemini Enterprise

Autonomous multi-agent Security Operations Center (SOC) reference architecture built on the Google Agent Development Kit (ADK), Vertex AI Agent Engine, Google Security Operations (Chronicle SIEM & SOAR), Google Threat Intelligence (GTI), and Gemini Enterprise.

```{grid} 1 2 2 2
:gutter: 3

:::{grid-item-card} Getting Started & Setup
:link: setup
:link-type: doc

Configure Google Cloud APIs, Vertex AI Reasoning Engines, Secret Manager credentials, OAuth 3LO bindings, and Gemini Enterprise registration.
:::

:::{grid-item-card} Governed Multi-Agent Stack
:link: agent_governance
:link-type: doc

Deploy and verify the default-deny egress Agent Gateway, per-agent SPIFFE workload identities, IAM v3 CEL tool allowlists, inline Model Armor, and Semantic Governance policies.
:::

:::{grid-item-card} Gemini Decision 1 Triage & Routing
:link: gemini_decision_1
:link-type: doc

Zero-output-token `LlmResponse` pre-flight short-circuit routing, pre-LLM UDM noise filtering, multimodal/unstructured CTI triage, and Auth Manager egress across the governed SOC stack.
:::

:::{grid-item-card} Multi-Agent Architecture & Grounding
:link: architecture
:link-type: doc

Explore the coordinated A2A Orchestrator and specialist agents (`cti_researcher`, `threat_hunter`, `detection_engineer`, `tier2_responder`), AlloyDB pgvector similarity search, and Neo4j attack graphs.
:::

:::{grid-item-card} Evaluation & Quality Assurance
:link: evaluations
:link-type: doc

Run offline governance harnesses, live A2A smoke suites, ADK rubric evaluations, and Ambient Quality Agent (AQuA) production trace diagnostics.
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
:caption: Agent Governance

agent_governance
agent_governance_design
gemini_decision_1
gemini_decision_1_case_study
gemini_decision_1_cti_ioc_triage
gemini_decision_1_threat_hunting
agent_governance_troubleshooting
```

```{toctree}
:maxdepth: 2
:caption: Architecture & Grounding

architecture
grounding_architecture
databases
alloydb_gcp_deployment_guide
alloydb_similarity_engine_summary
similarity_profiles
knowledge_catalog_vs_neo4j
threat_actor_glossary
code_execution_architecture
chatops_chat_app
```

```{toctree}
:maxdepth: 2
:caption: Evaluation & Experimentation

evaluations
adk_evals_framework_guide
experimentation_playbook
aqua_goal
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
