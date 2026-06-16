---
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T14:45:00Z"
---
# CLI Command Reference

This project implements a **Dual CLI Interface** with identical capabilities. Developers can manage deployments, database connections, and telemetry harvesting using either the traditional `justfile` or the unified, type-safe Python CLI (`manage.py`).

## 1. Deployments & Updates

Manage Reasoning Engine containers in Vertex AI:

### using justfile:
```bash
just agent-engine-deploy                # Deploys the Orchestrator agent
just agent-engine-update                # In-place update of agent code (retains memory)
just agent-engine-test query="T1003"    # Test deployed agent with a natural language query
```

### using Python CLI:
```bash
python manage.py agent-engine deploy    # Deploys the Orchestrator agent
python manage.py agent-engine update    # In-place update of agent code
python manage.py agent-engine test      # Test deployed agent
```

---

## 2. Elasticsearch Grounding Index

Manage your GCE Elasticsearch runbooks index:

### using justfile:
```bash
just elastic-info                       # View index statistics and document count
just elastic-create                     # Recreate the index (deletes existing first)
just elastic-sync recreate="true"       # Synchronize local runbooks into Elasticsearch
just elastic-search query="ransomware"  # Directly query the Elasticsearch index
```

### using Python CLI:
```bash
python manage.py elastic info           # View index statistics
python manage.py elastic create         # Recreate the index
python manage.py elastic sync           # Sync runbooks
python manage.py elastic search         # Query the index
```

---

## 3. Neo4j Graph Database

Manage your GCE Neo4j Graph Database:

### using justfile:
```bash
just neo4j-test                         # Test Bolt connection to Neo4j VM
just neo4j-ingest                       # Ingest knowledge_graph.json nodes and edges
just neo4j-clear                        # Delete all data (nodes & edges) from Neo4j
just neo4j-start                        # Start a local Neo4j container via Podman
just neo4j-stop                         # Stop the local Neo4j container
```

### using Python CLI:
```bash
python manage.py neo4j test-connection  # Test connection to Neo4j VM
python manage.py neo4j ingest           # Ingest knowledge graph
python manage.py neo4j clear            # Delete all data in Neo4j database
```
