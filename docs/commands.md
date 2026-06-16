---
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T15:30:00Z"
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

---

## 4. Gemini Enterprise Agent Platform (GEAP) & Apps

Register, link, and manage your agent applications in the Gemini Enterprise Agent Platform:

### using justfile:
```bash
just agentspace-register                # Register agent with the platform
just agentspace-update                  # Update platform agent configuration
just agentspace-verify                  # Verify configuration and status
just agentspace-delete                  # Delete agent from the platform
just agentspace-url                     # Display the platform UI URL for your app
just agentspace-test query="T1003"      # Test search/chat functionality directly
just agentspace-link-agent              # Link the deployed Reasoning Engine agent with OAuth
just agentspace-unlink-agent            # Unlink the agent from the platform

# App and Datastore management
just agentspace-create-app app_name="My App" type="SOLUTION_TYPE_CHAT"  # Create a new platform app
just datastore-list                     # List all data stores in the project
just datastore-create name="my-store"   # Create a new Search/Chat data store
```

### using Python CLI:
```bash
python manage.py agentspace register    # Register agent with the platform
python manage.py agentspace verify      # Verify configuration and status
python manage.py agentspace delete      # Delete agent from the platform
python manage.py agentspace url         # Display platform UI URL
python manage.py agentspace search      # Test search/chat functionality
python manage.py agentspace link-agent  # Link the deployed agent with OAuth

# App and Datastore management
python manage.py agentspace create-app  # Create a new platform app
python manage.py datastore list         # List all data stores
python manage.py datastore create       # Create a new data store
```

---

## 5. OAuth Configuration

Manage secure user authentication (OAuth) for the Gemini Enterprise Agent Platform:

### using justfile:
```bash
just oauth-setup client_secret=secret.json  # Setup OAuth client from Google Cloud credentials
just oauth-create-auth                  # Create OAuth authorization in Discovery Engine
just oauth-verify                       # Verify OAuth authorization status
just oauth-delete                       # Delete OAuth authorization
just full-deploy-with-oauth             # Run Setup -> Deploy -> OAuth -> Link in one go
```

### using Python CLI:
```bash
python manage.py oauth setup secret.json    # Setup OAuth client
python manage.py oauth create-auth      # Create OAuth authorization
python manage.py oauth verify           # Verify OAuth status
python manage.py oauth delete           # Delete OAuth authorization
```

---

## 6. RAG & GCS Document Syncing

Synchronize security runbooks and Incident Response Plans (IRPs) with Google Cloud Storage and Vertex AI RAG:

### using justfile:
```bash
just sync-runbooks                      # Complete E2E Sync: Validate -> GCS Upload -> RAG Import -> Prune
just sync-runbooks-validate             # Validate local markdown runbooks (size, blocks, formatting)
just sync-runbooks-gcs                  # Sync only valid runbooks to GCS, deleting orphaned files
just sync-runbooks-prune                # Prune files from RAG Corpus that no longer exist in GCS

# Direct RAG & GCS operations
just rag-list                           # List all active RAG corpora
just rag-create name="Runbooks"         # Create a new RAG corpus
just rag-import                         # Import all files from GCS to active RAG corpus
just gcs-list                           # List files in your GCS staging bucket
just gcs-upload file.pdf                # Upload specific files to GCS staging bucket
```

### using Python CLI:
```bash
python manage.py rag sync-runbooks      # Complete E2E runbook sync
python manage.py rag validate-md        # Validate local markdown runbooks
python manage.py rag sync-gcs           # Sync local runbooks to GCS
python manage.py rag prune-corpus       # Prune orphaned files from RAG corpus

# Direct RAG & GCS operations
python manage.py rag list               # List active RAG corpora
python manage.py rag create "Name"      # Create a new RAG corpus
python manage.py gcs list               # List GCS files
python manage.py gcs upload file.pdf    # Upload specific files to GCS
```

---

## 7. Secret & Credentials Management

Securely store your external service account keys in Google Cloud Secret Manager:

### using justfile:
```bash
just secret-upload                      # Upload the Chronicle service account JSON key
just secret-verify                      # Verify Secret Manager access to the service account
```

### using Python CLI:
```bash
python manage.py secret upload          # Upload the service account JSON key
python manage.py secret verify          # Verify Secret Manager access
```

---

## 8. Evaluation & Latency Profiling

Run comprehensive benchmark tests on your agents and profile their response latency:

### using justfile:
```bash
just eval                               # Run all agent evaluation sets (SOC Basic, CTI, Tier 1, Multi)
just eval-basic                         # Run basic operations evalset
just eval-cti                           # Run CTI research evalset
just eval-tier1                         # Run Tier 1 triage evalset
just eval-multi                         # Run multi-specialist routing evalset

# Latency profiling
just profile-latency                    # Profile agent latency (single run)
just profile-latency-runs runs=5        # Profile latency across multiple runs
just profile-latency-rag                # Profile RAG query latency only
just profile-latency-cti                # Profile CTI specialist latency only
```

### using Python CLI:
```bash
python manage.py eval                   # Run agent evaluations
python manage.py profile                # Run latency profiling
```

---

## 9. Telemetry Harvesting

Retrieve and enrich security cases and detection alerts from Chronicle SIEM for local offline analysis:

### using justfile:
```bash
just harvest                            # Harvest both investigations and detections
just harvest-investigations             # Harvest historical security cases
just harvest-detections                  # Harvest active alerting detections
```

### using Python CLI:
```bash
python manage.py harvest investigations  # Harvest security cases
python manage.py harvest detections      # Harvest alerting detections
```
