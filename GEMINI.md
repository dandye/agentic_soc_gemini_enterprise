---
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T14:31:00Z"
---
# GEMINI.md

This file provides guidance to Gemini Code Assist when working with code in this repository.

## Code Style and Communication

**CRITICAL: Never use emojis. Anywhere. Ever.**
- No emojis in code comments
- No emojis in commit messages
- No emojis in pull request descriptions
- No emojis in code review comments
- No emojis in documentation
- Emojis are unprofessional and must not be used in any context

### Markdown Open Knowledge Format (OKF) & Provenance Metadata
All Markdown (`.md`) files created or modified in the workspace must include a standard YAML frontmatter block at the absolute top of the file conforming to Google's **Open Knowledge Format (OKF)** extended with our custom provenance tracking schema:
```yaml
---
type: "Playbook" | "Evaluation Report" | "Glossary" | "Architecture" | "Troubleshooting" | "Documentation" | "other"
title: "Descriptive Document Title"
description: "A concise summary of the document's purpose and contents"
resource: "file:///absolute/path/to/file.md"
timestamp: "ISO-8601-UTC-timestamp-of-creation-or-last-update"
provenance:
  source_type: "api_response" | "python_generated" | "generative_ai" | "manual" | "mcp_tool"
  source_tool: "name_of_script_tool_or_model"
  timestamp: "ISO-8601-UTC-timestamp"
---
```



## Project Overview

This is a security operations (SOC) agent system built with Google Vertex AI Agent Development Kit (ADK). It deploys AI agents to Google Cloud with integrated access to Chronicle SIEM, SOAR, Google Threat Intelligence, Security Command Center, and RAG-based runbook retrieval through the Model Context Protocol (MCP).

## Common Commands

### Development and Testing

Local development with ADK Web (no deployment needed):
```bash
cd soc_agent
GOOGLE_GENAI_USE_VERTEXAI=True \
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json \
GOOGLE_CLOUD_PROJECT=your-project-id \
GOOGLE_CLOUD_LOCATION=us-central1 \
adk web
```

Run tests:
```bash
python test_agent_engine.py  # Test deployed agent
python test_schema_validation.py  # Validate MCP schemas
```

### Deployment Commands

Deploy agent to Agent Engine (using justfile):
```bash
just agent-engine-deploy  # Initial deployment
just agent-engine-update  # PREFERRED: In-place update of agent code (retains memory/sessions)
just agent-engine-redeploy  # FULL DESTRUCTIVE REBUILD (Ask user before running this!)
just agentspace-register  # Register with Gemini Enterprise Agent Platform
just full-deploy-with-oauth  # Complete deployment with OAuth
```

Deploy agent to Agent Engine (using Python CLI):
```bash
python manage.py agent-engine list
python manage.py agentspace register
python manage.py workflow full-deploy
python manage.py workflow status
```

### Creating Gemini Enterprise Agent Platform Apps

CRITICAL: When creating apps via API/CLI (not console UI), you MUST include --app-type APP_TYPE_INTRANET and --industry-vertical GENERIC for the app to be visible in the Gemini Enterprise web UI. See https://cloud.google.com/gemini/enterprise/docs/create-app

```bash
# Correct way to create an app via CLI
python manage.py agentspace create-app \
  --name "My Agent App" \
  --type SOLUTION_TYPE_CHAT \
  --no-datastore \
  --app-type APP_TYPE_INTRANET \
  --industry-vertical GENERIC
```

### RAG Corpus Management

```bash
just rag-list  # List all RAG corpora
just rag-create "Security Runbooks"  # Create new corpus
python manage.py rag list --verbose
python manage.py rag create "name" --description "desc"
```

### Elasticsearch, Neo4j & AlloyDB Database Grounding Management

Manage Elasticsearch runbook grounding:
```bash
just elastic-info                  # Show stats about the Elasticsearch grounding index
just elastic-create                # Recreate the Elasticsearch index (deletes existing first)
just elastic-sync recreate="true"   # Sync local runbooks into Elasticsearch
just elastic-search query="malware" # Directly query the Elasticsearch index
```

Manage Neo4j Graph Database:
```bash
just neo4j-test                    # Test connection to the GCE Neo4j database instance
just neo4j-ingest                  # Ingest nodes and edges from local knowledge_graph.json
just neo4j-clear                   # Clear all data (nodes and relationships) from Neo4j
just neo4j-start                   # Start a local Neo4j database container via Podman
just neo4j-stop                    # Stop the local Neo4j database container
```

Manage AlloyDB Detection Reports Grounding:
```bash
just alloydb-test                  # Test connection to the AlloyDB / PostgreSQL instance
just alloydb-init                  # Initialize AlloyDB schema, extensions, and indexes
just alloydb-ingest                # Ingest all harvested detection reports into AlloyDB
just alloydb-embed                 # Generate Vertex AI 768-dim vector embeddings
just alloydb-search "MSBuildShell" # Search detection reports in AlloyDB (keyword)
just alloydb-search-semantic "powershell download cradle" # Semantic vector search via text-embedding-004
just alloydb-find-similar <INV_ID> 5 threat-hunt # Multi-modal similarity engine with profiles
just alloydb-report <INV_ID> 5 threat-hunt # Generate similarity Markdown report with AI threat synthesis
just alloydb-profiles              # List all predefined similarity scoring profiles
just alloydb-info                  # Show statistics and metadata about detection reports
just alloydb-clear                 # Clear all detection reports from AlloyDB
just alloydb-start                 # Start a local AlloyDB / pgvector container via Podman
just alloydb-stop                  # Stop the local AlloyDB container
```

Using the Python CLI:
```bash
python manage.py elastic info
python manage.py elastic search "malware response"
python manage.py neo4j test-connection
python manage.py neo4j ingest
python manage.py alloydb test-connection
python manage.py alloydb ingest
python manage.py alloydb embed
python manage.py alloydb search "MSBuildShell"
python manage.py alloydb search "powershell download cradle" --semantic
python manage.py alloydb find-similar <INV_ID> --profile threat-hunt --explain
python manage.py alloydb report <INV_ID> --profile threat-hunt --ai
python manage.py alloydb profiles
python manage.py alloydb info
```

### Environment Management

```bash
just setup  # Setup environment
just check-prereqs  # Validate configuration
just status  # Check system status
python manage.py setup  # Alternative Python CLI setup
```

> [!TIP]
> **macOS / Airlock Dependency Installation:**
> If you encounter `401 Unauthorized` errors or package resolution failures (e.g., with `pyopenssl` or `elasticsearch` returning `from versions: none`) due to Airlock private registry locks, bypass the private registry by installing packages directly from the public PyPI index:
> ```bash
> .venv/bin/pip install --index-url https://pypi.org/simple -r requirements.txt
> ```

## Architecture

### Core Multi-Agent Architecture

The system is designed as a **Coordinated Agent-to-Agent (A2A) Network** consisting of five specialized agents, each packaged as a standalone ADK Reasoning Engine:

1. **Orchestrator (`agent_soc_manager`)**
   - **Role:** Main entry point for the user. Coordinates investigations, triages incoming alerts, and delegates complex tasks to remote specialists via gRPC.
   - **Model:** `gemini-3.1-pro-preview`
   - **Tools:** Integration with SOAR, Security Command Center, Neo4j Graph Database, and Elasticsearch/RAG runbook grounding.
   - **Sub-agents:** Hosts a local, in-process **Tier 1 SOC Analyst** sub-agent for initial telemetry triaging.

2. **CTI Researcher (`agent_a2a_cti_researcher`)**
   - **Role:** Threat intelligence specialist. Researches threat actors, malware families, and profiles campaigns.
   - **Model:** `gemini-2.5-flash`
   - **Tools:** Direct integration with Google Threat Intelligence (VirusTotal) MCP server and Vertex AI RAG.

3. **Detection Engineer (`agent_a2a_detection_engineer`)**
   - **Role:** Detection lifecycle specialist. Translates threat behaviors into SIEM detection rules and validates coverage.
   - **Model:** `gemini-2.5-pro`
   - **Tools:** Chronicle SIEM rule management and validation.

4. **Threat Hunter (`agent_a2a_threat_hunter`)**
   - **Role:** Proactive hunting specialist. Hunts for active IOCs and TTPs across security telemetry.
   - **Model:** `gemini-2.5-pro`
   - **Tools:** Chronicle SIEM UDM search, threat intelligence caching, and Neo4j graph queries.

5. **Tier 2 Responder (`agent_a2a_tier2`)**
   - **Role:** Incident responder specialist. Performs containment actions, host isolation, and active mitigation.
   - **Model:** `gemini-2.5-pro`
   - **Tools:** SOAR integrations, manual actions, and playbook executions.

### MCP Integration Pattern

MCP servers are configured as `McpToolset` instances with stdio connections:

```python
tool = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command='uv',
            args=["--directory", "./mcp-security/server/...", "run", "server.py"],
            env={"KEY": "value"}
        ),
        timeout=60000
    ),
    errlog=None
)
```

All MCP servers are in the `mcp-security/` git submodule and use `uv` for dependency management.

### Environment Configuration

The project uses a staged configuration approach:

**Stage 1 (Prerequisites)**: Set in `.env` before deployment
- `GCP_PROJECT_ID`, `GCP_PROJECT_NUMBER`, `GCP_LOCATION`
- `GCP_STAGING_BUCKET` (with `gs://` prefix)
- `CHRONICLE_PROJECT_ID`, `CHRONICLE_CUSTOMER_ID`, `CHRONICLE_SERVICE_ACCOUNT_PATH`
- `SOAR_URL`, `SOAR_API_KEY`
- `GTI_API_KEY`, `RAG_CORPUS_ID`
- Optional: `CHRONICLE_REGION`, `DEBUG`, `RAG_SIMILARITY_TOP_K`, `RAG_DISTANCE_THRESHOLD`
- **Database Grounding Variables (Optional)**:
  - `ELASTICSEARCH_GROUNDING_ENABLED`: Set to `True` to route runbook searches directly to Elasticsearch. Defaults to `False` (falling back to Vertex AI RAG).
  - `ELASTICSEARCH_URL`: Elasticsearch API URL (e.g., `http://${ELASTICSEARCH_VM_IP}:9200`).
  - `ELASTICSEARCH_USER`: Elasticsearch username (e.g., `elastic`).
  - `ELASTICSEARCH_PASSWORD`: Elasticsearch user password.
  - `ELASTICSEARCH_INDEX`: Elasticsearch runbooks index name (e.g., `agentic-soc-runbooks`).
  - `NEO4J_URI`: Neo4j Bolt connection URI (e.g., `bolt://${NEO4J_VM_IP}:7687`).
  - `NEO4J_USER`: Neo4j username (e.g., `neo4j`).
  - `NEO4J_PASSWORD`: Neo4j user password.

**Stage 2 (Deployment Outputs)**: Generated by `just agent-engine-deploy`
- `AGENT_ENGINE_RESOURCE_NAME`

**Stage 3 (Integration Outputs)**: Generated by `just agentspace-register`
- `AGENTSPACE_AGENT_ID`, `AGENTSPACE_APP_ID`

**Stage 4 (OAuth Outputs)**: Generated by `just oauth-setup`
- `OAUTH_AUTH_ID`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_AUTH_URI`, `OAUTH_TOKEN_URI`

### Dual CLI Interface

The project has two management interfaces with identical functionality:

1. **justfile** - Traditional just-based interface
   - `just agent-engine-list`, `just agentspace-register`, etc.
   - Uses Python scripts in `installation_scripts/`

2. **Python CLI (manage.py)** - Typer-based unified CLI
   - `python manage.py agent-engine list`
   - `python manage.py agentspace register`
   - Better for cross-platform, type safety, autocomplete

Both interfaces call the same underlying Python modules in `installation_scripts/`.

## Project Structure

```
.
├── agent_soc_manager/          # Orchestrator & Tier 1 Analyst agent module
│   └── agent.py                # Main orchestrator entry point (exports root_agent)
├── agent_a2a_cti_researcher/   # CTI Researcher remote agent module
├── agent_a2a_detection_engineer/# Detection Engineer remote agent module
├── agent_a2a_threat_hunter/    # Threat Hunter remote agent module
├── agent_a2a_tier2/            # Tier 2 Incident Responder remote agent module
├── manage.py                   # Unified Typer CLI (alternative to justfile)
├── installation_scripts/       # Management utilities
│   ├── manage_agent_engine.py  # Packaging & deployment to Vertex AI Agent Engine
│   ├── manage_agentspace.py    # GEAP registration and application linking
│   ├── manage_elasticsearch.py # Elasticsearch grounding index management
│   ├── manage_neo4j.py         # Neo4j Graph Database ingestion and tests
│   ├── manage_oauth.py         # OAuth configuration for GEAP
│   ├── manage_rag.py           # Vertex AI RAG corpus sync and management
│   └── harvest_investigations.py # Chronicle SIEM telemetry and case harvesting
├── external/                   # Git submodules for runbooks and atomic actions
│   ├── adk_runbooks/           # ADK guidelines, atomic runbooks, and schemas
│   └── ai-runbooks/            # Security runbooks, guidelines, and IRPs
├── harvested_investigations/   # Local telemetry & harvested incident files
│   └── knowledge_graph.json    # Compiled nodes/edges ready for Neo4j ingestion
├── justfile                    # Just-based developer interface
├── .env                        # Environment configuration (git-ignored)
├── .env.example                # Environment template and documentation
└── requirements.txt            # Python dependencies
```

## Key Implementation Details

### Agent Creation Flow

Every agent follows a consistent ADK Reasoning Engine instantiation pattern:
1. The agent's `agent.py` (e.g., `agent_soc_manager/agent.py`) defines a `create_agent()` function.
2. Loads configuration from `.env` using `python-dotenv`.
3. Initializes the Google GenAI SDK with project, location, and staging bucket settings.
4. Dynamically registers tools (MCP servers, RAG, custom functions, or A2A gRPC stubs) based on active flags (e.g., `ELASTICSEARCH_GROUNDING_ENABLED`).
5. Instantiates an `Agent` object with the designated model, tools, and system instructions.
6. Exports the instantiated agent as `root_agent` at the module level for compatibility with ADK deployment commands.

### Agent-to-Agent (A2A) Coordinated Routing
When the Orchestrator needs to delegate a task to a remote specialist, it calls a custom tool (e.g., `delegate_to_tier2_responder`). Under the hood, this tool:
- Dynamically resolves the specialist's Reasoning Engine resource name from `.env`.
- Obtains a regional gRPC client (`RoutingEngineClient`) in the correct GCP region (preventing regional gRPC mismatch).
- Invokes the remote agent in-session, preserving context, and returns the structured result back to the Orchestrator's prompt.

### Database Grounding Architecture
- **Elasticsearch Grounding (`search_knowledge_base`):** If `ELASTICSEARCH_GROUNDING_ENABLED=True`, the Orchestrator registers the direct Elasticsearch search tool. This bypasses RAG and queries your GCE Elasticsearch VM directly over port 9200, enabling rapid searching of playbooks and harvested telemetry.
- **Neo4j Graph Database (`query_neo4j_graph`):** Connects to your GCE Neo4j VM over Bolt protocol on port 7687 to traverse complex threat relationships, alerting paths, and entity associations.
- **AlloyDB Detection Reports Grounding (`query_alloydb_detection_reports`):** If `ALLOYDB_GROUNDING_ENABLED=True`, the Orchestrator and Tier 1 Analyst register the AlloyDB tool to query historical Chronicle detection reports, past investigation verdicts, full-text summaries, alert contexts, and affected entities.

## Modifying the Agents

To modify any agent in the A2A network, navigate to its respective directory (e.g., `agent_soc_manager/` or `agent_a2a_cti_researcher/`):

### Changing the Model
Edit the model parameter in the agent's `agent.py`:
```python
agent = Agent(
    model="gemini-3.1-pro-preview",  # or gemini-2.5-pro, gemini-2.5-flash, etc.
    ...
)
```

### Adding/Removing Tools
Edit the agent's `agent.py`:
1. Define your new tool function or configure a new MCP server toolset in `create_agent()`.
2. Add any required credentials or connection variables to `.env`.
3. Add the tool to the `tools` list passed to the `Agent()` constructor.

### Updating System Instructions
Edit the `instruction` string passed to the `Agent()` constructor in the agent's `agent.py`.

## Testing Approach

### Local Testing (Fastest)
To test any agent locally without deploying it to Google Cloud:
```bash
cd agent_soc_manager  # Or agent_a2a_cti_researcher, etc.
adk web
```
Opens a local ADK Web UI at http://localhost:8000 for instant, interactive testing and rapid prompt engineering iteration.

### Integration Testing
```bash
python test_agent_engine.py
```
Tests the deployed Agent Engine instance using the resource name from `.env`.

### MCP Server Testing
```bash
cd mcp-security/server/secops/secops_mcp
uv run server.py
```
Tests individual MCP server in isolation.

## Dependencies and Tools

- **Python 3.10+** required
- **uv**: Used to run all MCP servers (installed in MCP server directories)
- **Google ADK**: Agent development framework (`google-adk`)
- **Vertex AI SDK**: `google-cloud-aiplatform[agent-engines]`
- **MCP Protocol**: Model Context Protocol client/server (`mcp`)

## Code Quality Tools

This project uses a modern code quality stack for maintaining security-critical code:

### Development Tools
```bash
pip install -r requirements-dev.txt
```

**Installed tools:**
- **pyink**: Code formatting (Google Python Style Guide)
- **ruff**: Fast linting, import sorting, security checks (replaces isort, bandit, flake8)
- **mypy**: Static type checking
- **pytest + pytest-cov**: Testing with coverage reporting
- **pip-audit**: Dependency vulnerability scanning
- **pre-commit**: Git hook management

### Running Code Quality Checks

**Pre-commit hooks (runs automatically on git commit):**
```bash
pre-commit run --all-files  # Run all hooks manually
```

**Individual tools:**
```bash
ruff check .                 # Linting
ruff check --fix .           # Auto-fix issues
ruff format .                # Check formatting (not used, pyink handles this)
pyink .                      # Format code
mypy .                       # Type checking
pytest                       # Run tests with coverage
pip-audit                    # Scan dependencies
```

### CI/CD Pipeline

The `.github/workflows/code-quality.yml` workflow runs four parallel jobs on every PR:

1. **Pre-commit Hooks**: ruff, pyink, mypy, trailing whitespace, EOF, YAML checks
2. **Type Checking**: mypy static analysis
3. **Security Scanning**: ruff security rules (S checks) + pip-audit
4. **Tests and Coverage**: pytest with Codecov integration

### Configuration Files

- **pyproject.toml**: Configuration for pyink, mypy, pytest, ruff
- **.pre-commit-config.yaml**: Pre-commit hook definitions
- **requirements-dev.txt**: Development dependencies

## Troubleshooting

Common issues:
- **"AGENT_ENGINE_RESOURCE_NAME not set"**: Run `just agent-engine-deploy` first
- **MCP server timeout**: Check service account path and credentials
- **RAG retrieval not working**: Verify `RAG_CORPUS_ID` format and permissions
- **OAuth expired**: Run `just client_secret=client_secret.json oauth-setup`

Debug commands:
```bash
just status  # Check all configuration
gcloud logging tail "resource.type=aiplatform.googleapis.com/ReasoningEngine"  # View logs
python -c "from dotenv import load_dotenv; import os; load_dotenv(); print(os.getenv('GCP_PROJECT_ID'))"  # Verify env
```

## Important Notes

- This is a **worktree** (`harvest_detection_reports` branch) - changes here are isolated.
- The runbooks repositories under `external/` are **git submodules** - keep them updated with `git submodule update --init --recursive`.
- Always validate your `.env` database and credentials configuration before deploying.
- Service account JSON credentials must be accessible to both the agent and MCP servers.
