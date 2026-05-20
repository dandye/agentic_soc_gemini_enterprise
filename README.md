> [!WARNING]
> One user has reported ~$30/day expense in Spanner and a concern that it is due to the RAG Corpus from this project. I do not see this in my own projects but I am investigating further. In the meantime, please carefully monitor your expenses.

# Google Vertex AI Agent with MCP Security Tools

Deploy security-focused AI agents to Google Cloud with integrated access to Chronicle, SOAR, Threat Intelligence, and Security Command Center through the Model Context Protocol (MCP).

[![Watch the video](https://img.youtube.com/vi/KB2dJQEpjsw/maxresdefault.jpg)](https://www.youtube.com/watch?v=KB2dJQEpjsw)

## Table of Contents

- [Quick Start](#quick-start)
- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Deployment Workflow](#deployment-workflow)
- [Configuration](#configuration)
- [Usage](#usage)
- [AgentSpace Integration](#agentspace-integration)
- [Makefile Reference](#makefile-reference)
- [Python CLI (Alternative Interface)](#python-cli-alternative-interface)
- [Project Structure](#project-structure)
- [Development](#development)
  - [Local Development with ADK Web](#local-development-with-adk-web)
  - [Testing Individual MCP Servers](#testing-individual-mcp-servers)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Best Practices](#best-practices)
- [Documentation](#documentation)
- [Support](#support)

## Quick Start

### Option 1: Local Development (Recommended for Getting Started)

```bash
# Clone and setup
git clone --recurse-submodules https://github.com/dandye/agentic_soc_agentspace.git
cd agentic_soc_agentspace

# Configure environment
cp .env.example .env
# Edit .env with your Google Cloud credentials

# Install dependencies in a virtual env
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run locally with ADK Web (instant, no deployment needed!)
cd soc_agent
GOOGLE_GENAI_USE_VERTEXAI=True \
GOOGLE_APPLICATION_CREDENTIALS=/path/to/your/service-account.json \
GOOGLE_CLOUD_PROJECT=your-project-id \
GOOGLE_CLOUD_LOCATION=us-central1 \
adk web
```

This opens an interactive web UI at `http://localhost:8000` where you can test all features instantly. See [Local Development with ADK Web](#local-development-with-adk-web) for details.

### Option 2: Production Deployment to Agent Engine

```bash
# After completing the setup above:

# 1. Verify Vertex AI setup (one-time verification)
python manage.py vertex verify

# 2. Configure IAM permissions (one-time setup)
python manage.py iam setup

# 3. Deploy to Agent Engine
make agent-engine-deploy
```

For detailed deployment instructions, see the [Deployment Workflow](#deployment-workflow) section below.

### Available Commands

The Makefile provides a comprehensive set of commands for managing your deployment:

![Makefile Help Output](https://github.com/user-attachments/assets/a11f6f3f-f03e-4380-ab45-5e2ed19dfcfe)

Run `make help` to see this interactive command reference.

## Overview

This project enables you to:
- Deploy AI agents to Google Vertex AI Agent Engine with security tool access
- Integrate with Google Security Operations (Chronicle) for threat detection
- Connect to SOAR platforms for automated response workflows
- Access Google Threat Intelligence for IOC analysis
- Monitor cloud security posture via Security Command Center

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   main.py       │───▶│  Vertex AI       │───▶│   MCP Security      │
│   Agent Creator │    │  Agent Engine    │    │   Tools (stdio)     │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
                               │                        │
┌─────────────────┐            │                ┌───────▼───────┐
│test_agent_engine│◀───────────┘                │ • Chronicle   │
│    Testing      │                             │ • SOAR        │
└─────────────────┘                             │ • GTI         │
                                                │ • SCC         │
                                                └───────────────┘
```

## Prerequisites

### System Requirements
- **Python 3.10+** installed locally
- **4GB RAM** minimum
- **Git** with submodules support
- **Google Cloud SDK** installed and configured

### Google Cloud Requirements
- **Active GCP project** with billing enabled
- **Project ID and Project Number** available

### Required APIs
Enable these APIs in your project:
```bash
gcloud services enable aiplatform.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable discoveryengine.googleapis.com
gcloud services enable securitycenter.googleapis.com  # If using SCC tools
```

### Required IAM Permissions

**Your account needs these roles:**
- `roles/aiplatform.user` - Create and manage AI Platform resources
- `roles/storage.admin` - Manage staging bucket
- `roles/iam.serviceAccountUser` - Create service accounts for agent
- `roles/discoveryengine.admin` - Manage AgentSpace and register agents (includes agents.manage permission)
- `roles/securitycenter.admin` - Access Security Command Center (if using)

**IMPORTANT:** The `roles/discoveryengine.admin` role is required to register agents with AgentSpace (provides the `agents.manage` permission). Regular users can use registered agents but cannot register new ones.

#### Service Account Configuration

**Quick Setup (Recommended):**

Use the IAM management CLI to configure all required service account permissions automatically:

```bash
# Setup all required IAM permissions for AgentSpace
python manage.py iam setup

# Verify permissions are configured correctly
python manage.py iam verify

# Preview changes before applying (optional)
python manage.py iam setup --dry-run --verbose
```

**What this configures:**

1. **AI Platform Reasoning Engine Service Agent**
   - Service Account: `service-{PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com`
   - Role: `roles/aiplatform.user`
   - Purpose: Query RAG corpus during agent execution
   - Fixes: `403 PERMISSION_DENIED` error for `aiplatform.ragCorpora.query`

2. **Discovery Engine Service Account**
   - Service Account: `service-{PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com`
   - Roles: `roles/aiplatform.user`, `roles/aiplatform.viewer`
   - Purpose: Call ADK agent from AgentSpace
   - Fixes: Agent registered but cannot be invoked from Gemini Enterprise UI

**Manual Setup (Alternative):**

If you prefer to configure permissions manually using gcloud:

```bash
# Get your project number
GCP_PROJECT_NUMBER=$(gcloud projects describe $GCP_PROJECT_ID --format="value(projectNumber)")

# 1. AI Platform Reasoning Engine Service Agent (for RAG access)
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:service-${GCP_PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"

# 2. Discovery Engine Service Account (for AgentSpace integration)
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:service-${GCP_PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
  --member="serviceAccount:service-${GCP_PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com" \
  --role="roles/aiplatform.viewer"
```

**Verification:**

You can verify the configuration in the [IAM Console](https://console.cloud.google.com/iam-admin/iam) by checking "Include Google-provided role grants" to view Google-managed service accounts, or use the CLI:

```bash
# List all roles for a service account
python manage.py iam list-roles aiplatform-re
python manage.py iam list-roles discoveryengine
```

See [Google Cloud IAM Service Agents documentation](https://cloud.google.com/iam/docs/service-agents) for more details about Google-managed service accounts.

### Authentication Setup
```bash
GCP_PROJECT_ID=your-project-id
gcloud auth application-default login
gcloud config set project $GCP_PROJECT_ID
gcloud auth application-default set-quota-project $GCP_PROJECT_ID
```

## Installation

### 1. Clone Repository (note that the submodule is checked out too)
```bash
git clone --recurse-submodules https://github.com/dandye/agentic_soc_agentspace.git
cd agentic_soc_agentspace
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your configuration
# NOTE: Some vars, like `AGENT_ENGINE_RESOURCE_NAME`, are generated by make targets (i.e. `make agent-engine-deploy`)
#  so they are not available to you yet.
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Deploy Agent
```bash
make agent-engine-deploy
# Or directly: python main.py
```

### 5. Update .env with deployment outputs

1. Set `AGENT_ENGINE_RESOURCE_NAME` in .env (output from deployment)

### 6. Create AgentSpace App (Optional)

**Option A: Using the Web UI (Recommended)**
1. Navigate to [Google Cloud Console](https://console.cloud.google.com)
2. Go to **Vertex AI > Search & Conversation > Apps**
3. Click **Create App**
4. Select **Agent** as the app type
5. Configure with your preferred settings
6. Copy the App ID and add to `.env` as `AGENTSPACE_APP_ID`

**Option B: Using the CLI (Advanced)**

> [!IMPORTANT]
> **CRITICAL**: When creating apps via the API, you MUST include `--app-type APP_TYPE_INTRANET` and `--industry-vertical GENERIC` for apps to appear in the Gemini Enterprise web UI. Without these fields, apps may be created successfully via API but will not be visible in the console UI.
>
> See the [official Google Cloud documentation](https://cloud.google.com/gemini/enterprise/docs/create-app) for details.

```bash
# Create app with proper visibility settings
python manage.py agentspace create-app \
  --name "My Security Agent" \
  --type SOLUTION_TYPE_CHAT \
  --no-datastore \
  --app-type APP_TYPE_INTRANET \
  --industry-vertical GENERIC
```

### 7. Register Agent with AgentSpace

```bash
make agentspace-register
```

## Deployment Workflow

The deployment process consists of four stages:

### Stage 0: Prerequisites Verification and Setup (One-time Setup)

Before deploying, verify and configure your Google Cloud environment:

#### Step 1: Verify Vertex AI Setup

Run the comprehensive verification check:

```bash
python manage.py vertex verify
```

This verifies:
- Environment variables are set correctly
- Application Default Credentials are configured
- GCP project is accessible
- Required APIs are enabled
- Vertex AI can initialize
- Your user account has required IAM roles

**If checks fail:**
```bash
# Fix authentication
gcloud auth application-default login
gcloud auth application-default set-quota-project PROJECT_ID

# Enable required APIs
python manage.py vertex enable-apis

# Or manually:
gcloud services enable aiplatform.googleapis.com storage.googleapis.com \
  cloudbuild.googleapis.com compute.googleapis.com discoveryengine.googleapis.com
```

#### Step 2: Configure IAM Service Account Permissions

Configure required service account permissions for AgentSpace integration:

```bash
# Setup IAM permissions (run once per project)
python manage.py iam setup

# Verify configuration
python manage.py iam verify
```

This configures:
- AI Platform Reasoning Engine Service Agent (for RAG access)
- Discovery Engine Service Account (for calling agents from AgentSpace)

See [Required IAM Permissions](#required-iam-permissions) for details.

### Stage 1: Prerequisites (User Configuration)
Set these variables in your `.env` file before deployment:

**Required Core Variables:**
- `GCP_PROJECT_ID` - Your Google Cloud Project ID
- `GCP_PROJECT_NUMBER` - Your Google Cloud Project Number (numeric ID)
- `GCP_LOCATION` - Deployment region (e.g., us-central1)
- `GCP_STAGING_BUCKET` - GCS bucket name with gs:// prefix (e.g., gs://my-bucket)

**Required Security Tools:**
- Chronicle SIEM: `CHRONICLE_PROJECT_ID`, `CHRONICLE_CUSTOMER_ID`, `CHRONICLE_SERVICE_ACCOUNT_PATH`
- SOAR: `SOAR_URL`, `SOAR_API_KEY`
- Threat Intelligence: `GTI_API_KEY` (Google Threat Intelligence/VirusTotal)
- RAG Corpus: `RAG_CORPUS_ID` (full resource name)

**Optional Variables (have sensible defaults):**
- `CHRONICLE_REGION` - Chronicle region (default: "us")
- `DEBUG` - Enable debug logging (default: False)
- `RAG_SIMILARITY_TOP_K` - RAG retrieval top-k results (default: 10)
- `RAG_DISTANCE_THRESHOLD` - RAG vector distance threshold (default: 0.6)

### Stage 2: Deployment Outputs
Run `make agent-engine-deploy` and save the generated `AGENT_ENGINE_RESOURCE_NAME` from the output to your `.env`.

### Stage 3: Integration Outputs
Run `make agentspace-register` and save the generated `AGENTSPACE_AGENT_ID` to your `.env`.

## Configuration

See [.env.example](.env.example) for all environment variables with comprehensive documentation. Key variables are documented in the Deployment Workflow section above.

For migration from v1.x to v2.0, see [BREAKING_CHANGES.md](BREAKING_CHANGES.md).

## Usage

### Deploy New Agent
```bash
# Full deployment with all tools
make agent-engine-deploy
```

### Test Deployed Agent
```bash
# After setting AGENT_ENGINE_RESOURCE_NAME in .env from deployment output
python test_agent_engine.py
```

### Example Queries
```python
"List soar cases"
"What are the recent security alerts?"
"Analyze IOCs for domain malicious.com"
"Show Security Command Center findings"
"Investigate user account compromise indicators"
"Find a runbook titled Malware IRP"
```

### Workflow Commands
- `make full-deploy` - Complete standard deployment
- `make full-deploy-with-oauth` - Deployment with OAuth
- `make redeploy-all` - Redeploy and update AgentSpace

## RAG Corpus Management

Create and manage RAG (Retrieval-Augmented Generation) corpora for document search:

```bash
# List all RAG corpora
make rag-list

# List with detailed information
make rag-list VERBOSE=1

# Create a new RAG corpus
make rag-create NAME="Security Runbooks"

# Get corpus information
make rag-info RAG_CORPUS_ID=projects/PROJECT/locations/LOCATION/ragCorpora/CORPUS_ID

# Delete a corpus
make rag-delete RAG_CORPUS_ID=projects/PROJECT/locations/LOCATION/ragCorpora/CORPUS_ID
```

**Note:** After creating a RAG corpus, save the resource name to your `.env` as `RAG_CORPUS_ID`.

## Data Store Management (Optional - Legacy)

Discovery Engine data stores are available for AgentSpace apps but RAG is the recommended approach:

```bash
# List data stores
make datastore-list

# Create a data store
make datastore-create NAME="Security Data" TYPE=SOLUTION_TYPE_SEARCH
```

## AgentSpace Integration

> [!IMPORTANT]
> **APP_TYPE_INTRANET Required**: When creating apps programmatically via the API/CLI, you MUST include `appType=APP_TYPE_INTRANET` and `industryVertical=GENERIC` for apps to be visible in the Gemini Enterprise web UI. Apps created through the console UI include these fields automatically. See the [official documentation](https://cloud.google.com/gemini/enterprise/docs/create-app).

**Option 1: Create via Console (Recommended)**
1. **Create AgentSpace App** - Via [Console](https://console.cloud.google.com)
   - Navigate to Vertex AI > Search & Conversation > Apps
   - Click **Create App** and select **Agent** type
   - Configure with your preferred settings
   - Note: The agent uses RAG for document retrieval, not Discovery Engine data stores
2. **Copy App ID** to `.env` as `AGENTSPACE_APP_ID`

**Option 2: Create via CLI (Advanced)**
```bash
python manage.py agentspace create-app \
  --name "Security Agent" \
  --type SOLUTION_TYPE_CHAT \
  --no-datastore \
  --app-type APP_TYPE_INTRANET \
  --industry-vertical GENERIC
```

**After creating the app:**
3. **Register agent**: `make agentspace-link-agent` (add OAuth with `make oauth-setup` first if needed)
4. **Verify**: `make agentspace-verify`

## Makefile Commands

Run `make help` to see all available commands with descriptions (shown in image above).

### Key Environment Flags
- `FORCE=1` - Skip confirmation prompts
- `V=1` - Verbose output
- `INDEX=n` - Specify item index

**Example:** `FORCE=1 make agentspace-register`

## Python CLI (Alternative Interface)

In addition to the Makefile, this project provides a unified Python CLI built with Typer that offers the same functionality with additional benefits like type safety, autocomplete, and programmatic access.

### Quick Start

```bash
# Show all available commands
python manage.py --help

# Check system status
python manage.py workflow status

# List agent engines
python manage.py agent-engine list

# Register with AgentSpace
python manage.py agentspace register
```

### CLI Structure

The CLI is organized into subcommand groups:

```
python manage.py
├── agent-engine    # Manage Agent Engine instances
├── agentspace      # Manage AgentSpace apps and agents
├── vertex          # Verify and manage Vertex AI setup
├── iam             # Manage IAM permissions for service accounts
├── oauth           # Manage OAuth authorizations
├── datastore       # Manage data stores
├── rag             # Manage RAG corpora
├── workflow        # Composite workflows
├── setup           # Environment setup
└── version         # Version information
```

### Common Commands

**Agent Engine Management:**
```bash
python manage.py agent-engine list
python manage.py agent-engine delete --index 1
python manage.py agent-engine delete --resource "projects/.../reasoningEngines/..." --force
```

**Vertex AI Setup:**
```bash
python manage.py vertex verify              # Verify complete setup
python manage.py vertex verify --skip-apis  # Skip API checks
python manage.py vertex enable-apis         # Enable required APIs
python manage.py vertex check-quota         # Display quota information
```

**AgentSpace Management:**
```bash
python manage.py agentspace register
python manage.py agentspace update
python manage.py agentspace verify
python manage.py agentspace link-agent
python manage.py agentspace list-agents
```

**IAM Permissions Management:**
```bash
python manage.py iam setup                    # Configure all required permissions
python manage.py iam setup --dry-run          # Preview changes without applying
python manage.py iam setup --verbose          # Show detailed information
python manage.py iam verify                   # Verify all permissions are configured
python manage.py iam list-roles aiplatform-re # List roles for AI Platform RE
python manage.py iam list-roles discoveryengine # List roles for Discovery Engine
```

**RAG Corpus Management:**
```bash
python manage.py rag list --verbose
python manage.py rag create "Security Runbooks" --description "SOC procedures"
python manage.py rag info "projects/.../ragCorpora/..."
python manage.py rag delete "projects/.../ragCorpora/..." --force
```

**OAuth Management:**
```bash
python manage.py oauth setup client_secret.json
python manage.py oauth create-auth
python manage.py oauth verify
```

**Workflow Commands:**
```bash
# Complete deployment with OAuth
python manage.py workflow full-deploy

# Redeploy everything
python manage.py workflow redeploy-all

# Check system status
python manage.py workflow status
```

### Command Mapping: Makefile to Python CLI

| Makefile Command | Python CLI Equivalent |
|-----------------|----------------------|
| `make agent-engine-list` | `python manage.py agent-engine list` |
| `make agent-engine-delete-by-index INDEX=1` | `python manage.py agent-engine delete --index 1` |
| `make agentspace-register` | `python manage.py agentspace register` |
| `make agentspace-register FORCE=1` | `python manage.py agentspace register --force` |
| `make oauth-setup CLIENT_SECRET=x.json` | `python manage.py oauth setup x.json` |
| `make rag-list` | `python manage.py rag list` |
| `make rag-create NAME="x"` | `python manage.py rag create "x"` |
| `make full-deploy-with-oauth` | `python manage.py workflow full-deploy` |
| `make status` | `python manage.py workflow status` |

### Benefits Over Makefile

- **Type Safety**: Typer provides parameter validation and type checking
- **Autocomplete**: Shell completion for all commands and options
- **Better Help**: Rich formatted help with detailed descriptions
- **Cross-Platform**: Works on all platforms without Make dependency
- **Programmatic Use**: Can be imported and used as a Python library
- **Consistent API**: All commands follow the same pattern

### Environment File Support

All commands support custom environment files:

```bash
python manage.py --env-file .env.prod agent-engine list
python manage.py --env-file .env.staging workflow status
```

### Shell Autocomplete

Install autocomplete for your shell:

```bash
# Bash
python manage.py --install-completion bash

# Zsh
python manage.py --install-completion zsh

# Fish
python manage.py --install-completion fish
```

### Detailed Documentation

For comprehensive CLI documentation including all commands, options, and examples, see [MANAGE_CLI_USAGE.md](MANAGE_CLI_USAGE.md).

## Project Structure

```
├── main.py                    # Agent creation and deployment
├── test_agent_engine.py       # Testing interface
├── DEPLOYMENT_GUIDE.md        # Detailed deployment instructions
├── requirements.txt           # Python dependencies
├── Makefile                   # Automation workflows
├── .env.example               # Environment template with documentation
├── .gitmodules                # Git submodule configuration
├── installation_scripts/
│   ├── install.sh             # Cloud deployment setup (installs `uv`)
│   ├── manage_agent_engine.py # Agent management utilities
│   ├── manage_agentspace.py   # Agentspace configuration
│   └── manage_oauth.py        # OAuth setup utilities
└── mcp-security/              # MCP security servers (submodule)
    └── server/
        ├── mcp-server-soar/
        ├── mcp-server-secops/
        ├── mcp-server-gti/
        └── mcp-server-scc/
```

## Development

### Code Quality and Testing

This project uses a modern code quality stack to maintain security-critical code:

**Install development tools:**
```bash
pip install -r requirements-dev.txt
```

**Pre-commit hooks (automatic on git commit):**
```bash
pre-commit install              # Install hooks
pre-commit run --all-files      # Run manually
```

**Run code quality checks:**
```bash
ruff check .                    # Linting and security checks
ruff check --fix .              # Auto-fix issues
pyink .                         # Format code (Google style)
mypy .                          # Type checking
pytest                          # Run tests with coverage
pip-audit                       # Dependency vulnerability scan
```

**Tools used:**
- **pyink**: Code formatting (Google Python Style Guide)
- **ruff**: Fast linting, import sorting, security checks
- **mypy**: Static type checking
- **pytest**: Testing with coverage reporting
- **pip-audit**: Dependency vulnerability scanning

**CI/CD:** All PRs run automated checks for linting, type checking, security scanning, and test coverage.

### Customizing the Agent

Edit `main.py` to customize:

```python
# Change model
model = "gemini-2.5-flash"  # or gemini-2.5-pro

# Modify system prompt
instruction = "Your custom security analyst instructions..."

# Select specific tools
tools = [secops_tool, soar_tool]  # Choose tools as needed
```

### Adding New MCP Tools

1. Add tool configuration to `MCPToolset` in `main.py`
2. Update `extra_packages` with server path
3. Modify installation script if needed

### Local Development with ADK Web

The fastest way to develop and test your agent locally is using `adk web`, which provides an interactive web UI without deploying to Agent Engine.

#### Running ADK Web

From the `soc_agent` directory, run:

```bash
cd soc_agent

GOOGLE_GENAI_USE_VERTEXAI=True \
GOOGLE_APPLICATION_CREDENTIALS=/path/to/your/service-account.json \
GOOGLE_CLOUD_PROJECT=your-project-id \
GOOGLE_CLOUD_LOCATION=us-central1 \
adk web
```

Replace the values:
- `/path/to/your/service-account.json` - Path to your Chronicle service account JSON file (same as `CHRONICLE_SERVICE_ACCOUNT_PATH` in .env)
- `your-project-id` - Your GCP project ID (same as `GCP_PROJECT_ID` in .env)
- `us-central1` - Your GCP location (same as `GCP_LOCATION` in .env)

The web UI will open at `http://localhost:8000` where you can:
- Chat with your agent in real-time
- Test MCP tool integrations (Chronicle, SOAR, GTI, SCC)
- Query the RAG corpus for runbooks and procedures
- See tool calls and responses as they happen
- Iterate on your agent configuration without redeployment

#### Why Use ADK Web?

**Benefits:**
- **Instant feedback**: No 10-15 minute deployment wait time
- **Cost effective**: No Agent Engine hosting costs during development
- **Full feature parity**: All MCP tools and RAG retrieval work locally
- **Easy debugging**: See tool calls and responses in real-time
- **Rapid iteration**: Modify agent.py and restart immediately

**When to use Agent Engine instead:**
- Production deployments
- Integration with AgentSpace
- Multi-user access
- Persistent conversation history
- Autoscaling requirements

### Testing Individual MCP Servers

You can also test MCP servers in isolation:

```bash
# Test MCP servers locally
cd mcp-security/server/secops-soar/secops_soar_mcp
uv run server.py
```
Success looks like:
```
2025-09-15 16:39:39,549 - INFO - __main__ - main - Starting SecOps SOAR MCP server
2025-09-15 16:39:39,817 - INFO - __main__ - get_enabled_integrations_set - No --integrations flag provided. No integrations are enabled.
2025-09-15 16:39:39,818 - INFO - __main__ - register_tools - Starting dynamic tool registration...
2025-09-15 16:39:39,824 - INFO - __main__ - register_tools - Finished scanning marketplace directory.
```
(and then hanging as it is waiting for input)

#### Validate configuration
```bash
python -c "from dotenv import load_dotenv; import os; load_dotenv(); print(os.getenv('GCP_PROJECT_ID'))"
```

## Troubleshooting

### Common Issues & Quick Fixes

| Issue | Solution |
|-------|----------|
| **403/401 Auth Error** | `gcloud auth application-default login` |
| **API not enabled** | `gcloud services enable aiplatform.googleapis.com` |
| **Bucket not found** | `gsutil mb -p $GCP_PROJECT_ID $GCP_STAGING_BUCKET` |
| **MCP module missing** | `git submodule update --init --recursive` |
| **KeyError: GCP_PROJECT_ID** | Check `.env` exists with correct variable names (v2.0+) |
| **Agent not in AgentSpace** | `make agentspace-verify` then `make agentspace-link-agent` |
| **OAuth expired** | `make oauth-setup CLIENT_SECRET=client_secret.json` |
| **Agent not responding** | Check logs: `gcloud logging tail "resource.type=aiplatform.googleapis.com/ReasoningEngine"` |
| **SOAR connection failed** | Verify URL: `curl -I "${SOAR_URL}/api/external/v1/health"` |

### Quick Debug Commands

```bash
gcloud logging tail "resource.type=aiplatform.googleapis.com/ReasoningEngine"  # Watch logs
make agentspace-test  # Test components
```

## FAQ

**Can I use this without SOAR?**
Yes. All security tool integrations are optional.

**What AI models are supported?**
The default is gemini-2.5-flash but you can use any model suppored by Vertex AI Model Garden and ADK. Configure in `main.py`.

**How do I update the agent?**
```bash
git pull && make agent-engine-deploy && make agentspace-update
```

**What are the costs?**
Vertex AI charges per API call. Security products require separate licensing.

## Best Practices

- **Security**: Use Secret Manager for credentials, enable audit logging, apply least-privilege IAM
- **Development**: Separate dev/staging/prod projects, version control all configuration
- **Operations**: Set budget alerts, backup configurations, monitor quotas

## Documentation

- [MCP Security Docs](mcp-security/README.md) - Security tool documentation
- [Google Vertex AI Docs](https://cloud.google.com/vertex-ai/docs) - Platform documentation
- [MCP Protocol](https://modelcontextprotocol.io/) - Protocol specification

## Support

### Getting Help
- [GitHub Issues](https://github.com/dandye/agentic_soc_agentspace/issues) - Report bugs or request features
- [Stack Overflow](https://stackoverflow.com/questions/tagged/vertex-ai) - Community support
- [Google Cloud Support](https://console.cloud.google.com/support) - Production issues

### Resources
- [Vertex AI Docs](https://cloud.google.com/vertex-ai/docs) - Google Cloud documentation
- [MCP Protocol](https://modelcontextprotocol.io/) - Model Context Protocol specification
- [Chronicle Docs](https://cloud.google.com/chronicle/docs) - SIEM documentation
- [Security Command Center](https://cloud.google.com/security-command-center/docs) - Cloud security docs
