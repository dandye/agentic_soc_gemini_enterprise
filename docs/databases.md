---
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T14:45:00Z"
---
# Telemetry Database Grounding

To provide high-performance grounding for security playbooks and historical threat relationships, the Orchestrator and Threat Hunter connect directly to dedicated Google Compute Engine (GCE) database instances.

## Elasticsearch Runbook Grounding

When the agent triages an alert and needs to look up an Incident Response Plan (IRP), a playbook, or a corporate security guideline, it queries your GCE Elasticsearch VM directly over HTTP port `9200`.

- **Index Name:** `agentic-soc-runbooks`
- **Data Content:** Over **3,405 document chunks** parsed from local markdown runbooks in the `external/ai-runbooks` submodule.
- **Why Elasticsearch?** Bypasses the vector embedding/RAG retrieval limitations, offering lightning-fast full-text keyword searches across detailed runbooks.

If `ELASTICSEARCH_GROUNDING_ENABLED=True` is set in your `.env` file, the Orchestrator registers the `search_knowledge_base` tool, routing all runbook searches to the Elasticsearch VM. If `False` or unset, the agent falls back to standard Vertex AI RAG.

## Neo4j Security Operations Knowledge Graph

When the Threat Hunter or Orchestrator needs to map out lateral movement, identify all active alerts associated with a compromised user, or list all processes executed by a malicious file hash, it queries your GCE Neo4j Graph Database VM over the **Bolt protocol (port 7687)**.

- **Data Source:** Sourced and compiled from historical Chronicle SIEM telemetry and case files in `harvested_investigations/knowledge_graph.json`.
- **Ingested Graph Scale:** **1,148 nodes** (representing Cases, Alerts, Users, Hosts, Files, Domains) and **7,789 edges** (representing relationships like `LOGGED_INTO`, `EXECUTED`, `TRIGGERED`, `COMMUNICATED_WITH`).

The Threat Hunter registers the `query_neo4j_graph` tool, allowing it to traverse complex multi-hop entities in milliseconds.

## Ingesting the Knowledge Graph

To populate your live GCE Neo4j database instance with the local harvested investigations, you must run the graph ingestion command. This will connect to the Bolt URI, set up uniqueness constraints for quick lookups, and load the entire graph in batches:

```bash
# Verify connection to the Neo4j VM
just neo4j-test

# Ingest the flat knowledge graph JSON into Neo4j
just neo4j-ingest
```
