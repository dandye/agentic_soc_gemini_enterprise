---
type: "Documentation"
title: "Setup Guide"
description: "This guide will walk you through setting up your local Python environment, resolving dependency locks, and configuring the staged."
resource: "docs/setup.md"
timestamp: "2026-08-01T16:24:01Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T15:30:00Z"
---
# Getting Started & Setup Guide

This guide will walk you through setting up your local Python environment, resolving dependency locks, and configuring the staged environment variables.

## Local Environment Setup

To begin, clone the repository (including submodules) and initialize your python virtual environment:

```bash
# Clone the repository including submodules
git clone --recursive <repository-url>
cd agentic_soc_gemini_enterprise

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate
```

### macOS / Airlock Installation
If you are developing on macOS behind an Airlock private registry lock, your dependency installations may fail with `401 Unauthorized` errors. Bypass the private registry lock by installing packages directly from the public PyPI index:

```bash
.venv/bin/pip install --index-url https://pypi.org/simple -r requirements.txt
```

## Environment Configuration

Copy the environment template file to `.env`:

```bash
cp .env.example .env
```

The system loads its credentials from this file. Configuration is organized by deployment stage:

### Stage 1: Prerequisites (Set BEFORE deployment)
These variables are required to deploy the Reasoning Engines and connect to your Google Cloud infrastructure:
- `GCP_PROJECT_ID`: Your Google Cloud Project ID (e.g. `secops-demo-env`).
- `GCP_PROJECT_NUMBER`: Your Google Cloud Project Number.
- `GCP_LOCATION`: Active region for Reasoning Engines (e.g. `us-east4` or `us-central1`).
- `GCP_STAGING_BUCKET`: GCS bucket for Reasoning Engine builds (with `gs://` prefix).
- `CHRONICLE_CUSTOMER_ID`: Your Chronicle SIEM Customer UUID.
- `CHRONICLE_SERVICE_ACCOUNT_PATH`: Path to the service account JSON key file.

### Stage 2: Database Grounding & VMs
These variables are required to connect the Orchestrator and Threat Hunter to your GCE database instances:
- `ELASTICSEARCH_GROUNDING_ENABLED`: Set to `True` to route runbook searches directly to Elasticsearch. Defaults to `False`.
- `ELASTICSEARCH_URL`: Elasticsearch API URL (e.g. `http://${ELASTICSEARCH_VM_IP}:9200`).
- `ELASTICSEARCH_USER` / `ELASTICSEARCH_PASSWORD`: Elasticsearch credentials.
- `NEO4J_URI`: Neo4j Bolt connection URI (e.g. `bolt://${NEO4J_VM_IP}:7687`).
- `NEO4J_USER` / `NEO4J_PASSWORD`: Neo4j credentials.

### Stage 3: Deployment & Integration Outputs
These variables are auto-populated after running deployment and registration scripts:
- `AGENT_ENGINE_RESOURCE_NAME`: The deployed Orchestrator reasoning engine path.
- `AGENTSPACE_AGENT_ID`: The registered Gemini Enterprise Agent Platform ID.
- `AGENTSPACE_APP_ID`: The target Gemini Enterprise application ID.

### Stage 4: OAuth Outputs
These variables are required to link your agent with the Gemini Enterprise Agent Platform using secure user authentication:
- `OAUTH_AUTH_ID`: The generated OAuth authorization ID from Discovery Engine.
- `OAUTH_CLIENT_ID`: The Google Cloud OAuth client ID.
- `OAUTH_CLIENT_SECRET`: The Google Cloud OAuth client secret.
- `OAUTH_AUTH_URI`: The OAuth authorization URI.
- `OAUTH_TOKEN_URI`: The OAuth token exchange URI.
