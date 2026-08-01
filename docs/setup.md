---
type: "Documentation"
title: "Setup Guide"
description: "This guide will walk you through setting up your local Python environment, resolving dependency locks, and configuring the staged."
resource: "docs/setup.md"
timestamp: "2026-08-01T22:09:35Z"
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
- `GEM_ENT_AGENT_ID`: The registered Gemini Enterprise Agent Platform ID.
- `GEM_ENT_APP_ID`: The target Gemini Enterprise application ID.

### Stage 4: OAuth Outputs
These variables are required to link your agent with the Gemini Enterprise Agent Platform using secure user authentication:
- `OAUTH_AUTH_ID`: The generated OAuth authorization ID from Discovery Engine.
- `OAUTH_CLIENT_ID`: The Google Cloud OAuth client ID.
- `OAUTH_CLIENT_SECRET`: The Google Cloud OAuth client secret.
- `OAUTH_AUTH_URI`: The OAuth authorization URI.
- `OAUTH_TOKEN_URI`: The OAuth token exchange URI.

## Service Accounts & IAM

Four distinct identities interact with this platform. Granting the wrong set to the wrong identity is the most common deployment failure, so they are documented separately. Official references: [Agent Engine set-up: identity and permissions](https://docs.cloud.google.com/agent-builder/agent-engine/set-up#identity-and-permissions) and [custom service accounts](https://cloud.google.com/agent-builder/agent-engine/set-up#custom-service-account).

### Required APIs

Enable these on the project before deploying:

| API | Purpose |
|---|---|
| `aiplatform.googleapis.com` | Vertex AI / Agent Engine (Reasoning Engines) |
| `discoveryengine.googleapis.com` | Gemini Enterprise apps and agent registration |
| `storage.googleapis.com` | Staging and artifact buckets |
| `iam.googleapis.com` | Service-account management and role grants |
| `secretmanager.googleapis.com` | Chronicle credential storage (`just secret-upload`) |
| `securitycenter.googleapis.com` | Optional -- SCC findings integration |

### 1. The deployer (you)

The human or CI identity that runs `just agent-engine-deploy` and `manage.py gem-ent register` needs:

| Role | Why |
|---|---|
| `roles/aiplatform.user` | Create and manage Reasoning Engines |
| `roles/storage.admin` | Manage the staging bucket |
| `roles/iam.serviceAccountUser` | Attach service accounts to agents |
| `roles/discoveryengine.admin` | Create Gemini Enterprise apps, register agents |
| `roles/securitycenter.admin` | Optional -- only if using SCC tools |

Verify the first two with `python manage.py vertex check`; it reads the project IAM policy and reports which required roles your active credential holds.

### 2. End users of the Gemini Enterprise app

People who *use* the deployed app need all four of the following. Missing `discoveryengine.editor` produces the misleading error "Couldn't create a session. Contact admin for permissions."

| Role | Why |
|---|---|
| `roles/aiplatform.user` | Invoke the Reasoning Engine |
| `roles/aiplatform.viewer` | Read engine metadata |
| `roles/discoveryengine.editor` | Create chat sessions (the non-obvious one) |
| `roles/discoveryengine.viewer` | Read the app |

### 3. Google-managed service agents

Google creates these automatically; they follow the pattern `service-${GCP_PROJECT_NUMBER}@gcp-sa-<service>.iam.gserviceaccount.com` (project **number**, not project ID). They still need explicit role grants in your project, which `python manage.py iam setup` applies (use `--dry-run` first; `iam verify` and `iam list-roles` inspect current state):

| Service agent | Roles granted | Purpose |
|---|---|---|
| `gcp-sa-aiplatform-re` | `roles/aiplatform.user` | Reasoning Engine queries the RAG corpus during agent execution |
| `gcp-sa-discoveryengine` | `roles/aiplatform.user`, `roles/aiplatform.viewer` | Gemini Enterprise calls the ADK agent |
| `gcp-sa-dialogflow` | `roles/aiplatform.user` | Conversational runtime invokes the Reasoning Engine |

**Known escalation (issue #14):** some RAG-corpus operations at execution time have required `roles/aiplatform.admin` on the `gcp-sa-aiplatform-re` agent. `iam setup` deliberately grants least-privilege `aiplatform.user`; if agent-side RAG calls fail with permission errors after setup, escalate that one agent:

```bash
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:service-${GCP_PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com" \
  --role="roles/aiplatform.admin"
```

Whether the granted set can be trimmed further is untested (tracked in issue #16's notes).

### 4. The Chronicle service account (customer-managed)

The SecOps MCP tools authenticate to Chronicle SIEM/SOAR with a key you provide -- either as a file (`CHRONICLE_SERVICE_ACCOUNT_PATH` in Stage 1) or, preferred for deployment, uploaded to Secret Manager with `just secret-upload` and referenced via `CHRONICLE_SERVICE_ACCOUNT_SECRET`. This SA is granted roles in your *Chronicle* project by your SecOps administrator; it needs no roles in the agent project.
