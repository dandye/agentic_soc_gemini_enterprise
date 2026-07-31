---
type: "Architecture"
title: "AlloyDB Detection Reports Grounding & Multi-Modal Similarity Engine"
description: "Executive summary of Chronicle investigation harvesting, AlloyDB pgvector schema, Vertex AI embeddings, multi-modal similarity scoring profiles, and hybrid report generation."
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/docs/alloydb_similarity_engine_summary.md"
timestamp: "2026-07-31T00:05:00Z"
provenance:
  source_type: "manual"
  source_tool: "Antigravity"
  timestamp: "2026-07-31T00:05:00Z"
---

# AlloyDB Detection Reports Grounding & Multi-Modal Similarity Engine

### 1. Chronicle Investigation Harvesting
- **Telemetry Harvesting**: Harvested all **258** available Chronicle SIEM security investigations from the **SecOps-Lab** tenant (`secops-demo-env`, requesting up to 500), outputting 258 fully adjudicated investigation reports (132 `FALSE_POSITIVE`, 126 `TRUE_POSITIVE`) into [investigations/](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/investigations/).
- **Metadata Extraction**: Extracted and normalized investigation summaries, alert contexts, MITRE ATT&CK tactics/techniques, entity instances, and triage steps into structured Markdown files conforming to Open Knowledge Format (OKF).

---

### 2. AlloyDB & pgvector Database Architecture
- **Schema Design & Provisioning**: Created PostgreSQL/AlloyDB relational schema in [installation_scripts/manage_alloydb.py](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/installation_scripts/manage_alloydb.py) with the `pgvector` extension enabled:
  - `detection_reports`: Core investigation records, verdicts, confidences, steps, summaries, and dense vectors (`vector(768)`).
  - `detection_alerts`: Associated Chronicle alerts, MITRE tactics/techniques, and rule descriptions.
  - `detection_entities`: Extracted entities (hosts, IPs, hashes, users, files) with investigation-specific context.
- **Data Ingestion**: Ingested 258 detection reports, 258 linked alerts, and 1,183 entity records (spanning 38 distinct entity values).

---

### 3. Vertex AI 768-Dimensional Vector Embeddings
- **Dense Text Embeddings**: Integrated Google Vertex AI [`TextEmbeddingModel`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/installation_scripts/manage_alloydb.py#L142) (`text-embedding-004`) to generate 768-dimensional embeddings for 100% of detection reports (258/258).
- **HNSW Indexing**: Created an approximate nearest-neighbor index (`idx_detection_reports_embedding_hnsw`) using Hierarchical Navigable Small World graphs (`USING hnsw (embedding vector_cosine_ops)`) for sub-millisecond similarity scans.

---

### 4. Multi-Modal Composite Similarity Engine
Developed a 2-stage retrieval and scoring algorithm in [`AlloyDBManager.find_similar`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/installation_scripts/manage_alloydb.py#L895) evaluating five orthogonal security dimensions:
1. **Semantic Vector Cosine ($S_{\text{sem}}$)**: Vector similarity across attack descriptions via pgvector cosine distance.
2. **Weighted Entity Overlap ($S_{\text{ent}}$)**: Inverse Document Frequency (IDF) weighted Jaccard index prioritizing rare indicators over ubiquitous binaries.
3. **Behavioral MITRE TTPs ($S_{\text{ttp}}$)**: Hierarchical overlap across tactics (30%) and specific sub-techniques (70%).
4. **Investigation Flow Steps ($S_{\text{flow}}$)**: Step-by-step structural overlap across analytical action fingerprints.
5. **Temporal Campaign Decay ($S_{\text{time}}$)**: Exponential recency scoring with a 14-day half-life ($\tau = 14\text{ days}$).

---

### 5. Parameterized Similarity Profiles
Implemented five operational scoring profiles in [`SIMILARITY_PROFILES`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/installation_scripts/manage_alloydb.py#L35):
- `balanced` (Default: 35% Sem, 30% Ent, 20% TTP, 10% Flow, 5% Time): General triage and precedent matching.
- `threat-hunt` (45% TTP, 35% Sem, 10% Flow, 5% Time, 5% Ent): Cross-host threat actor and tradecraft campaign tracking.
- `compromise-pivot` (45% Ent, 30% Time, 15% Sem, 5% Flow, 5% TTP): Host compromise blast radius and lateral movement tracing.
- `false-positive` (40% Ent, 25% TTP, 20% Sem, 10% Flow, 5% Time): Recurring benign administrative pattern deduplication.
- `semantic` (60% Sem, 15% Flow, 15% TTP, 5% Ent, 5% Time): Exploratory behavioral and conceptual attack discovery.

---

### 6. Hybrid Similarity Reporting with Vertex AI Gemini Synthesis
- **Deterministic Framework**: Programmatically constructs OKF-compliant Markdown reports featuring exact sub-score tables, shared indicator matrices, and direct links to historical investigation documents.
- **AI Narrative Synthesis**: Calls Vertex AI **Gemini 2.5 Flash** via [`AlloyDBManager.generate_similarity_report`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/installation_scripts/manage_alloydb.py#L1450) to produce executive campaign correlation narratives, cross-host infrastructure overlap analyses, verdict discrepancy evaluations (e.g. contrasting `FALSE_POSITIVE` vs `TRUE_POSITIVE`), and actionable SOC triage recommendations.

---

### 7. Interface & Tooling Integrations
- **CLI Commands ([manage.py](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/manage.py))**:
  - `python manage.py alloydb ingest` / `embed` / `info` / `profiles`
  - `python manage.py alloydb search "MSBuildShell" [--semantic]`
  - `python manage.py alloydb find-similar <INV_ID> --profile threat-hunt --explain`
  - `python manage.py alloydb report <INV_ID> --profile threat-hunt --ai`
- **Developer Workflows ([justfile](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/justfile))**:
  - `just alloydb-find-similar <INV_ID> 5 threat-hunt`
  - `just alloydb-report <INV_ID> 5 threat-hunt`
  - `just alloydb-profiles`
- **Autonomous SOC Agent ([agent_soc_manager/agent.py](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/agent_soc_manager/agent.py))**:
  - Registered [`find_similar_alloydb_investigations`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/agent_soc_manager/agent.py#L1500) into the Orchestrator and Tier 1 Analyst toolsets with profile parametrization support.
