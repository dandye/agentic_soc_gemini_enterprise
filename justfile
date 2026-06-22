set dotenv-load := true

# Default environment file
env_file := ".env"

# Agent module selection (default: agent_soc_manager for Pro model)
agent_module := "agent_soc_manager"

# Verbosity control
v := "0"
verbose := if v == "1" { "--verbose" } else { "" }

# Python executable (use venv if available)
export PYTHONPATH := "."
python := if path_exists(".venv") == "true" { ".venv/bin/python" } else if path_exists("venv") == "true" { "venv/bin/python" } else { "python3" }

# Management scripts
manage_agentspace := "installation_scripts/manage_agentspace.py"
manage_agent_engine := "installation_scripts/manage_agent_engine.py"
manage_oauth := "installation_scripts/manage_oauth.py"
manage_datastore := "installation_scripts/manage_datastore.py"
manage_rag := "installation_scripts/manage_rag.py"
manage_gcs := "installation_scripts/manage_gcs.py"
manage_vertex_ai := "installation_scripts/manage_vertex_ai.py"
manage_models := "installation_scripts/manage_models.py"
manage_secret := "installation_scripts/manage_secret.py"
manage_harvest := "installation_scripts/harvest_investigations.py"
manage_elastic := "installation_scripts/manage_elasticsearch.py"
manage_eval := "installation_scripts/manage_eval.py"
manage_neo4j := "installation_scripts/manage_neo4j.py"

# Global options for GCS / RAG / Data Store (override on command line)
bucket := ""
path := ""
recursive := "0"
preserve_structure := "0"
overwrite := "0"
prefix := ""
uri := ""
force := "false"
dry_run := "false"
location := ""
storage_class := ""
client_secret := ""
creds := ""
index := ""
resource := ""
runs := ""

# Default goal
default:
    @{{ python }} installation_scripts/print_help.py {{ justfile() }}


# Validate Stage 1 prerequisites
check-prereqs:
    #!/usr/bin/env bash
    set -a; [ -f "{{env_file}}" ] && source "{{env_file}}"; set +a
    if [ -z "$GCP_PROJECT_ID" ]; then echo "ERROR: GCP_PROJECT_ID not set in {{env_file}}"; exit 1; fi
    if [ -z "$GCP_LOCATION" ]; then echo "ERROR: GCP_LOCATION not set in {{env_file}}"; exit 1; fi
    if [ -z "$GCP_STAGING_BUCKET" ]; then echo "ERROR: GCP_STAGING_BUCKET not set in {{env_file}}"; exit 1; fi
    echo "Stage 1 prerequisites validated"

# Validate Stage 2 deployment outputs
check-deploy:
    #!/usr/bin/env bash
    set -a; [ -f "{{env_file}}" ] && source "{{env_file}}"; set +a
    if [ -z "$AGENT_ENGINE_RESOURCE_NAME" ]; then echo "ERROR: AGENT_ENGINE_RESOURCE_NAME not set - run 'just agent-engine-deploy' first"; exit 1; fi
    echo "Stage 2 deployment outputs validated"

# Validate Stage 3 integration requirements
check-integration: check-deploy
    #!/usr/bin/env bash
    set -a; [ -f "{{env_file}}" ] && source "{{env_file}}"; set +a
    if [ -z "$AGENTSPACE_APP_ID" ]; then echo "WARNING: AGENTSPACE_APP_ID not set - required for Gemini Enterprise Agent Platform operations"; fi
    echo "Stage 3 integration requirements checked"

# Install Python dependencies
install:
    {{ python }} -m pip install -r requirements.txt

# Set up environment and install dependencies
setup:
    #!/usr/bin/env bash
    if [ ! -f "{{ env_file }}" ]; then
        echo "Creating {{ env_file }} file from template..."
        cp .env.example "{{ env_file }}"
        echo "Please edit {{ env_file }} with your configuration"
    fi
    just -f {{ justfile() }} install

# Clean up temporary files and cache
clean:
    find . -type f -name "*.pyc" -delete
    find . -type d -name "__pycache__" -delete
    find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true

# Deploy agent engine (use agent_module=soc_agent_flash for Flash)
agent-engine-deploy description="": check-prereqs
    {{ python }} {{ manage_agent_engine }} deploy --agent-module {{ agent_module }} {{ if description != "" { "--description " + quote(description) } else { "" } }}
    @echo "========================================"
    @echo "Agent deployment complete - check output above for resource details"
    @echo "========================================"

# Update existing agent engine in-place (preserves memory bank)
agent-engine-update description="": check-deploy
    {{ python }} {{ manage_agent_engine }} update --agent-module {{ agent_module }} {{ if description != "" { "--description " + quote(description) } else { "" } }}
    @echo "========================================"
    @echo "Agent update complete - check output above for resource details"
    @echo "========================================"

# Deploy Pro agent (gemini-3.1-pro-preview)
agent-engine-deploy-pro: check-prereqs
    just -f {{ justfile() }} agent_module=agent_soc_manager agent-engine-deploy

# Deploy Tier 2 agent (incident responder specialist)
agent-engine-deploy-tier2: check-prereqs
    just -f {{ justfile() }} agent_module=agent_a2a_tier2 agent-engine-deploy

# Deploy Threat Hunter agent (proactive hunting specialist)
agent-engine-deploy-threat-hunter: check-prereqs
    just -f {{ justfile() }} agent_module=agent_a2a_threat_hunter agent-engine-deploy

# Deploy CTI Researcher agent (threat intelligence specialist)
agent-engine-deploy-cti-researcher: check-prereqs
    just -f {{ justfile() }} agent_module=agent_a2a_cti_researcher agent-engine-deploy

# Deploy Detection Engineer agent (detection lifecycle specialist)
agent-engine-deploy-detection-engineer: check-prereqs
    just -f {{ justfile() }} agent_module=agent_a2a_detection_engineer agent-engine-deploy
# Deploy agent engine and intelligently delete older versions
agent-engine-deploy-and-delete description="": check-prereqs
    {{ python }} {{ manage_agent_engine }} deploy --agent-module {{ agent_module }} {{ if description != "" { "--description " + quote(description) } else { "" } }}

# Test the deployed agent engine (use agent_module=agent_a2a_tier2 for Tier 2)
agent-engine-test query="":
    {{ python }} {{ manage_agent_engine }} test --agent-module {{ agent_module }} {{ if query != "" { "--query " + quote(query) } else { "" } }}

# Dump raw conversation history for a cloud session
agent-engine-session-dump session_id user_id="eval_user":
    {{ python }} {{ manage_agent_engine }} session-dump --agent-module {{ agent_module }} --user-id {{ user_id }} {{ session_id }}

# Pre-warm MCP server connections to reduce cold start latency
agent-engine-warmup: check-deploy
    {{ python }} {{ manage_agent_engine }} warmup

# Register agent with Gemini Enterprise Agent Platform (use force=true to force re-register)
agentspace-register force="false": check-integration
    #!/usr/bin/env bash
    if [ "{{ force }}" = "true" ] || [ "{{ force }}" = "1" ]; then
        {{ python }} {{ manage_agentspace }} register --force --env-file {{ env_file }}
    else
        {{ python }} {{ manage_agentspace }} register --env-file {{ env_file }}
        echo "========================================"
        echo "REGISTRATION COMPLETE - Save this value to .env:"
        echo "========================================"
        echo "Check the output above for:"
        echo "  AGENTSPACE_AGENT_ID=<numeric_id>"
        echo "========================================"
    fi

# Update existing Gemini Enterprise Agent Platform agent configuration
agentspace-update: check-integration
    {{ python }} {{ manage_agentspace }} update --env-file {{ env_file }}

# Verify Gemini Enterprise Agent Platform agent configuration and status
agentspace-verify: check-integration
    {{ python }} {{ manage_agentspace }} verify --env-file {{ env_file }}

# Delete agent from Gemini Enterprise Agent Platform (use force=true to delete without confirmation)
agentspace-delete force="false":
    #!/usr/bin/env bash
    if [ "{{ force }}" = "true" ] || [ "{{ force }}" = "1" ]; then
        {{ python }} {{ manage_agentspace }} delete --force --env-file {{ env_file }}
    else
        {{ python }} {{ manage_agentspace }} delete --env-file {{ env_file }}
    fi

# Display Gemini Enterprise Agent Platform UI URL
agentspace-url:
    {{ python }} {{ manage_agentspace }} url --env-file {{ env_file }}

# Test Gemini Enterprise Agent Platform search functionality (use: just agentspace-test "your query")
agentspace-test query="":
    #!/usr/bin/env bash
    if [ -n "{{ query }}" ]; then
        {{ python }} {{ manage_agentspace }} search --query {{ quote(query) }} --env-file {{ env_file }}
    else
        {{ python }} {{ manage_agentspace }} search --env-file {{ env_file }}
    fi

# Ensure the Gemini Enterprise Agent Platform engine has a data store configured
agentspace-datastore:
    {{ python }} {{ manage_agentspace }} ensure-datastore --env-file {{ env_file }}

# Link deployed agent to Gemini Enterprise Agent Platform with OAuth
agentspace-link-agent: check-integration
    @{{ python }} {{ manage_agentspace }} link-agent --env-file {{ env_file }}
    @echo "========================================"
    @echo "AGENT LINK COMPLETE - Save this value to .env:"
    @echo "========================================"
    @echo "Check the output above for:"
    @echo "  AGENTSPACE_AGENT_ID=<numeric_id>"
    @echo "========================================"

# Unlink agent from Gemini Enterprise Agent Platform (use agent_id for specific agent, force=true to skip confirmation)
agentspace-unlink-agent agent_id="" force="false":
    #!/usr/bin/env bash
    ARGS=""
    if [ "{{ force }}" = "true" ] || [ "{{ force }}" = "1" ]; then
        ARGS="--force"
    fi
    if [ -n "{{ agent_id }}" ]; then
        ARGS="$ARGS --agent-id {{ quote(agent_id) }}"
    fi
    {{ python }} {{ manage_agentspace }} unlink-agent $ARGS --env-file {{ env_file }}

# Update agent configuration in Gemini Enterprise Agent Platform
agentspace-update-agent:
    {{ python }} {{ manage_agentspace }} update-agent-config --env-file {{ env_file }}

# List all agents in Gemini Enterprise Agent Platform app
agentspace-list-agents:
    {{ python }} {{ manage_agentspace }} list-agents --env-file {{ env_file }}

# List all apps in Gemini Enterprise Agent Platform collection
agentspace-list-apps:
    {{ python }} {{ manage_agentspace }} list-apps --env-file {{ env_file }}

# Create a new Gemini Enterprise Agent Platform app (use: just agentspace-create-app "My App" "SOLUTION_TYPE_SEARCH")
agentspace-create-app app_name="" type="" data_store="" enable_chat="0":
    #!/usr/bin/env bash
    echo "Creating new Gemini Enterprise Agent Platform app..."
    echo "Options:"
    echo "  app_name='<name>' - App display name"
    echo "  type=<type> - Solution type"
    echo "  data_store=<id> - Data store ID to associate"
    echo "  enable_chat=1 - Enable chat features (for SOLUTION_TYPE_CHAT)"
    ARGS=""
    if [ -n "{{ app_name }}" ]; then
        ARGS="$ARGS --name {{ quote(app_name) }}"
    fi
    if [ -n "{{ type }}" ]; then
        ARGS="$ARGS --type {{ quote(type) }}"
    fi
    if [ -n "{{ data_store }}" ]; then
        ARGS="$ARGS --data-store {{ quote(data_store) }}"
    fi
    if [ "{{ enable_chat }}" = "1" ] || [ "{{ enable_chat }}" = "true" ]; then
        ARGS="$ARGS --enable-chat"
    fi
    {{ python }} {{ manage_agentspace }} create-app $ARGS --env-file {{ env_file }}

# Create a new data store (use name, type, content, industry)
datastore-create name="" type="" content="" industry="":
    #!/usr/bin/env bash
    echo "Creating new data store..."
    echo "Options:"
    echo "  name='<name>' - Data store display name (default: datastore)"
    echo "  type=<type> - Solution type (default: SOLUTION_TYPE_SEARCH)"
    echo "  content=<config> - Content config (default: CONTENT_REQUIRED)"
    echo "  industry=<vertical> - Industry vertical (default: GENERIC)"
    ARGS=""
    if [ -n "{{ name }}" ]; then
        ARGS="$ARGS --name {{ quote(name) }}"
    fi
    if [ -n "{{ type }}" ]; then
        ARGS="$ARGS --type {{ quote(type) }}"
    fi
    if [ -n "{{ content }}" ]; then
        ARGS="$ARGS --content {{ quote(content) }}"
    fi
    if [ -n "{{ industry }}" ]; then
        ARGS="$ARGS --industry {{ quote(industry) }}"
    fi
    {{ python }} {{ manage_datastore }} create $ARGS --env-file {{ env_file }}

# List all data stores in the project
datastore-list:
    {{ python }} {{ manage_datastore }} list --env-file {{ env_file }}

# Get information about a specific data store (use datastore_id)
datastore-info datastore_id="":
    #!/usr/bin/env bash
    if [ -z "{{ datastore_id }}" ]; then
        echo "Error: datastore_id is required. Usage: just datastore-info <id>"
        exit 1
    fi
    {{ python }} {{ manage_datastore }} info "{{ datastore_id }}" --env-file {{ env_file }}

# Delete a data store (use datastore_id, force=true)
datastore-delete datastore_id="" force="false":
    #!/usr/bin/env bash
    if [ -z "{{ datastore_id }}" ]; then
        echo "Error: datastore_id is required. Usage: just datastore-delete <id>"
        exit 1
    fi
    if [ "{{ force }}" = "true" ] || [ "{{ force }}" = "1" ]; then
        {{ python }} {{ manage_datastore }} delete "{{ datastore_id }}" --force --env-file {{ env_file }}
    else
        {{ python }} {{ manage_datastore }} delete "{{ datastore_id }}" --env-file {{ env_file }}
    fi

# List all RAG corpora in the project
rag-list:
    {{ python }} {{ manage_rag }} list {{ verbose }} --env-file {{ env_file }}

# Get information about a specific RAG corpus (use rag_corpus_id)
rag-info rag_corpus_id="":
    #!/usr/bin/env bash
    if [ -z "{{ rag_corpus_id }}" ]; then
        echo "Error: rag_corpus_id is required. Usage: just rag-info <resource_name>"
        exit 1
    fi
    {{ python }} {{ manage_rag }} info "{{ rag_corpus_id }}" --env-file {{ env_file }}

# Create a new RAG corpus (use name, desc, embedding_model)
rag-create name desc="" embedding_model="":
    #!/usr/bin/env bash
    ARGS=""
    if [ -n "{{ desc }}" ]; then
        ARGS="$ARGS --description {{ quote(desc) }}"
    fi
    if [ -n "{{ embedding_model }}" ]; then
        ARGS="$ARGS --embedding-model {{ quote(embedding_model) }}"
    fi
    {{ python }} {{ manage_rag }} create "{{ name }}" $ARGS --env-file {{ env_file }}

# Delete a RAG corpus (use rag_corpus_id, force=true)
rag-delete rag_corpus_id="" force="false":
    #!/usr/bin/env bash
    if [ -z "{{ rag_corpus_id }}" ]; then
        echo "Error: rag_corpus_id is required. Usage: just rag-delete <resource_name>"
        exit 1
    fi
    if [ "{{ force }}" = "true" ] || [ "{{ force }}" = "1" ]; then
        {{ python }} {{ manage_rag }} delete "{{ rag_corpus_id }}" --force --env-file {{ env_file }}
    else
        {{ python }} {{ manage_rag }} delete "{{ rag_corpus_id }}" --env-file {{ env_file }}
    fi

# Import files from GCS to RAG corpus (use rag_corpus_id, gcs_uri, chunk_size, chunk_overlap, timeout)
rag-import rag_corpus_id="" gcs_uri="" chunk_size="" chunk_overlap="" timeout="":
    #!/usr/bin/env bash
    set -a; [ -f "{{env_file}}" ] && source "{{env_file}}"; set +a

    CORPUS="{{ rag_corpus_id }}"
    if [ -z "$CORPUS" ]; then
        CORPUS="$RAG_CORPUS_ID"
    fi

    if [ -z "$CORPUS" ]; then
        echo "Error: RAG_CORPUS_ID required. Set in .env or use: just rag-import <name>"
        exit 1
    fi

    ARGS=""
    if [ -n "{{ chunk_size }}" ]; then
        ARGS="$ARGS --chunk-size {{ quote(chunk_size) }}"
    fi
    if [ -n "{{ chunk_overlap }}" ]; then
        ARGS="$ARGS --chunk-overlap {{ quote(chunk_overlap) }}"
    fi
    if [ -n "{{ timeout }}" ]; then
        ARGS="$ARGS --timeout {{ quote(timeout) }}"
    fi

    if [ -n "{{ rag_corpus_id }}" ]; then
        if [ -z "{{ gcs_uri }}" ]; then
            echo "Error: gcs_uri is required when rag_corpus_id is provided. Usage: just rag-import <name> <gcs_uri>"
            exit 1
        fi
        echo "Importing file to RAG corpus..."
        echo "  Corpus: $CORPUS"
        echo "  File: {{ gcs_uri }}"
        {{ python }} {{ manage_rag }} import-files "$CORPUS" "{{ gcs_uri }}" $ARGS --env-file {{ env_file }}
    else
        echo "Importing all files from GCS_DEFAULT_BUCKET to RAG corpus from .env..."
        {{ python }} {{ manage_rag }} import-files $ARGS --env-file {{ env_file }}
    fi

# E2E Sync: Validate -> Rsync GCS -> Import RAG -> Prune Orphaned RAG Files
sync-runbooks rag_corpus_id="":
    #!/usr/bin/env bash
    ARGS=""
    if [ -n "{{ rag_corpus_id }}" ]; then
        ARGS="--corpus {{ quote(rag_corpus_id) }}"
    fi
    {{ python }} {{ manage_rag }} sync-runbooks $ARGS --env-file {{ env_file }}

# Validate local markdown runbooks (size, encoding, markdown blocks)
sync-runbooks-validate:
    {{ python }} {{ manage_rag }} validate-md --env-file {{ env_file }}

# Sync only valid local runbooks to GCS, deleting orphaned GCS files
sync-runbooks-gcs:
    {{ python }} {{ manage_rag }} sync-gcs --env-file {{ env_file }}

# Prune files from RAG Corpus that no longer exist in GCS
sync-runbooks-prune rag_corpus_id="":
    #!/usr/bin/env bash
    ARGS=""
    if [ -n "{{ rag_corpus_id }}" ]; then
        ARGS="{{ quote(rag_corpus_id) }}"
    fi
    {{ python }} {{ manage_rag }} prune-corpus $ARGS --env-file {{ env_file }}

# Upload local files to GCS (use: just bucket=bucket-name recursive=1 gcs-upload file1 file2)
gcs-upload *files:
    #!/usr/bin/env bash
    if [ -z "{{ files }}" ]; then
        echo "Error: files are required. Usage: just gcs-upload <file1> <file2>..."
        exit 1
    fi
    ARGS=""
    if [ -n "{{ bucket }}" ]; then
        ARGS="$ARGS --bucket {{ quote(bucket) }}"
    fi
    if [ -n "{{ path }}" ]; then
        ARGS="$ARGS --path {{ quote(path) }}"
    fi
    if [ "{{ recursive }}" = "1" ] || [ "{{ recursive }}" = "true" ]; then
        ARGS="$ARGS --recursive"
    fi
    if [ "{{ preserve_structure }}" = "1" ] || [ "{{ preserve_structure }}" = "true" ]; then
        ARGS="$ARGS --preserve-structure"
    fi
    if [ "{{ overwrite }}" = "1" ] || [ "{{ overwrite }}" = "true" ]; then
        ARGS="$ARGS --overwrite"
    fi
    {{ python }} {{ manage_gcs }} upload {{ files }} $ARGS --env-file {{ env_file }}

# List GCS buckets or files (use: just bucket=bucket-name prefix=path/ gcs-list)
gcs-list:
    #!/usr/bin/env bash
    ARGS=""
    if [ -n "{{ bucket }}" ]; then
        ARGS="$ARGS --bucket {{ quote(bucket) }}"
    fi
    if [ -n "{{ prefix }}" ]; then
        ARGS="$ARGS --prefix {{ quote(prefix) }}"
    fi
    {{ python }} {{ manage_gcs }} list $ARGS {{ verbose }} --env-file {{ env_file }}

# Delete files from GCS (use: just uri=gs://bucket/file gcs-delete OR just bucket=bucket prefix=path/ gcs-delete)
gcs-delete:
    #!/usr/bin/env bash
    ARGS=""
    if [ "{{ force }}" = "true" ] || [ "{{ force }}" = "1" ]; then
        ARGS="$ARGS --force"
    fi
    if [ "{{ dry_run }}" = "true" ] || [ "{{ dry_run }}" = "1" ]; then
        ARGS="$ARGS --dry-run"
    fi

    if [ -n "{{ uri }}" ]; then
        {{ python }} {{ manage_gcs }} delete "{{ uri }}" $ARGS --env-file {{ env_file }}
    elif [ -n "{{ bucket }}" ] && [ -n "{{ prefix }}" ]; then
        {{ python }} {{ manage_gcs }} delete --bucket "{{ bucket }}" --prefix "{{ prefix }}" $ARGS --env-file {{ env_file }}
    else
        echo "Error: Provide either uri=gs://... or both bucket=... and prefix=..."
        exit 1
    fi

# Validate files for RAG import
gcs-validate *files:
    #!/usr/bin/env bash
    if [ -z "{{ files }}" ]; then
        echo "Error: files are required. Usage: just gcs-validate <file1> <file2>..."
        exit 1
    fi
    {{ python }} {{ manage_gcs }} validate {{ files }} --env-file {{ env_file }}

# Generate GCS URIs for files (use: just bucket=bucket-name prefix=path/ gcs-uri)
gcs-uri output="":
    #!/usr/bin/env bash
    if [ -z "{{ bucket }}" ]; then
        echo "Error: bucket is required. Usage: just bucket=bucket-name gcs-uri"
        exit 1
    fi
    ARGS=""
    if [ -n "{{ prefix }}" ]; then
        ARGS="$ARGS --prefix {{ quote(prefix) }}"
    fi
    if [ -n "{{ output }}" ]; then
        ARGS="$ARGS --output {{ quote(output) }}"
    fi
    {{ python }} {{ manage_gcs }} uri --bucket "{{ bucket }}" $ARGS --env-file {{ env_file }}

# Create a new GCS bucket (use: just bucket=bucket-name location=us-central1 gcs-bucket-create)
gcs-bucket-create:
    #!/usr/bin/env bash
    if [ -z "{{ bucket }}" ]; then
        echo "Error: bucket is required. Usage: just bucket=bucket-name gcs-bucket-create"
        exit 1
    fi
    ARGS=""
    if [ -n "{{ location }}" ]; then
        ARGS="$ARGS --location {{ quote(location) }}"
    fi
    if [ -n "{{ storage_class }}" ]; then
        ARGS="$ARGS --storage-class {{ quote(storage_class) }}"
    fi
    {{ python }} {{ manage_gcs }} bucket-create "{{ bucket }}" $ARGS --env-file {{ env_file }}

# Get information about a GCS bucket (use: just bucket=bucket-name gcs-bucket-info)
gcs-bucket-info:
    #!/usr/bin/env bash
    if [ -z "{{ bucket }}" ]; then
        echo "Error: bucket is required. Usage: just bucket=bucket-name gcs-bucket-info"
        exit 1
    fi
    {{ python }} {{ manage_gcs }} bucket-info "{{ bucket }}" --env-file {{ env_file }}

# Verify complete Vertex AI setup (APIs, auth, permissions)
vertex-ai-verify:
    {{ python }} {{ manage_vertex_ai }} verify --env-file {{ env_file }}

# Enable all required Vertex AI APIs
vertex-ai-enable-apis:
    {{ python }} {{ manage_vertex_ai }} enable-apis --env-file {{ env_file }}

# Display quota information for Vertex AI services
vertex-ai-quota:
    {{ python }} {{ manage_vertex_ai }} check-quota --env-file {{ env_file }}

# List and discover available Gemini models from Google GenAI
models-list:
    {{ python }} {{ manage_models }} list --env-file {{ env_file }}

# Interactive OAuth client setup from client_secret.json (use: just client_secret=path/to/client_secret.json oauth-setup)
oauth-setup:
    #!/usr/bin/env bash
    if [ -z "{{ client_secret }}" ]; then
        echo "Error: client_secret is required. Usage: just client_secret=path/to/client_secret.json oauth-setup"
        exit 1
    fi
    {{ python }} {{ manage_oauth }} setup "{{ client_secret }}" --env-file {{ env_file }}

# Create OAuth authorization in Discovery Engine
oauth-create-auth:
    @{{ python }} {{ manage_oauth }} create-auth --env-file {{ env_file }}
    @echo "========================================"
    @echo "OAUTH SETUP COMPLETE - Save this value to .env:"
    @echo "========================================"
    @echo "Check the output above for:"
    @echo "  OAUTH_AUTH_ID=<auth_id>"
    @echo "========================================"

# Check OAuth authorization status
oauth-verify:
    {{ python }} {{ manage_oauth }} verify --env-file {{ env_file }}

# Remove OAuth authorization (use force=true to delete without confirmation)
oauth-delete force="false":
    #!/usr/bin/env bash
    if [ "{{ force }}" = "true" ] || [ "{{ force }}" = "1" ]; then
        {{ python }} {{ manage_oauth }} delete --force --env-file {{ env_file }}
    else
        {{ python }} {{ manage_oauth }} delete --env-file {{ env_file }}
    fi

# Upload Chronicle service account to Secret Manager (use creds=/path/to/sa.json for different account)
secret-upload:
    #!/usr/bin/env bash
    ARGS=""
    if [ -n "{{ creds }}" ]; then
        ARGS="--credentials {{ quote(creds) }}"
    fi
    {{ python }} {{ manage_secret }} upload --env-file {{ env_file }} $ARGS

# Upload Chronicle service account to Secret Manager (skip confirmation, use creds=/path/to/sa.json)
secret-upload-force:
    #!/usr/bin/env bash
    ARGS="--force"
    if [ -n "{{ creds }}" ]; then
        ARGS="$ARGS --credentials {{ quote(creds) }}"
    fi
    {{ python }} {{ manage_secret }} upload --env-file {{ env_file }} $ARGS

# Verify Secret Manager access to Chronicle service account (use creds=/path/to/sa.json)
secret-verify:
    #!/usr/bin/env bash
    ARGS=""
    if [ -n "{{ creds }}" ]; then
        ARGS="--credentials {{ quote(creds) }}"
    fi
    {{ python }} {{ manage_secret }} verify --env-file {{ env_file }} $ARGS

# Sync all agent secrets (SOAR, GTI, DBs) from .env to Secret Manager (use creds=/path/to/sa.json for different account)
secret-sync:
    #!/usr/bin/env bash
    ARGS=""
    if [ -n "{{ creds }}" ]; then
        ARGS="--credentials {{ quote(creds) }}"
    fi
    {{ python }} {{ manage_secret }} sync --env-file {{ env_file }} $ARGS

# Sync all agent secrets from .env to Secret Manager (skip confirmation, use creds=/path/to/sa.json)
secret-sync-force:
    #!/usr/bin/env bash
    ARGS="--force"
    if [ -n "{{ creds }}" ]; then
        ARGS="$ARGS --credentials {{ quote(creds) }}"
    fi
    {{ python }} {{ manage_secret }} sync --env-file {{ env_file }} $ARGS

# List all Agent Engine instances
agent-engine-list:
    {{ python }} {{ manage_agent_engine }} list {{ verbose }}

# Delete Agent Engine instance by index (use: just index=1 agent-engine-delete-by-index, add force=true to skip confirmation)
agent-engine-delete-by-index:
    #!/usr/bin/env bash
    if [ -z "{{ index }}" ]; then
        echo "Error: index is required. Usage: just index=1 agent-engine-delete-by-index"
        exit 1
    fi
    ARGS=""
    if [ "{{ force }}" = "true" ] || [ "{{ force }}" = "1" ]; then
        ARGS="--force"
    fi
    {{ python }} {{ manage_agent_engine }} delete --index "{{ index }}" $ARGS

# Delete Agent Engine instance by resource name (use: just resource=... agent-engine-delete-by-resource, add force=true to skip confirmation)
agent-engine-delete-by-resource:
    #!/usr/bin/env bash
    if [ -z "{{ resource }}" ]; then
        echo "Error: resource is required. Usage: just resource=projects/.../reasoningEngines/... agent-engine-delete-by-resource"
        exit 1
    fi
    ARGS=""
    if [ "{{ force }}" = "true" ] || [ "{{ force }}" = "1" ]; then
        ARGS="--force"
    fi
    {{ python }} {{ manage_agent_engine }} delete --resource "{{ resource }}" $ARGS

# Create a new Agent Engine instance (same as deploy)
agent-engine-create description="": check-prereqs
    {{ python }} {{ manage_agent_engine }} create --agent-module {{ agent_module }} {{ if description != "" { "--description " + quote(description) } else { "" } }}

# Create Agent Engine with debug logging enabled
agent-engine-create-debug description="": check-prereqs
    {{ python }} {{ manage_agent_engine }} create --agent-module {{ agent_module }} --debug {{ if description != "" { "--description " + quote(description) } else { "" } }}

# Create Agent Engine without running the test
agent-engine-create-no-test description="": check-prereqs
    {{ python }} {{ manage_agent_engine }} create --agent-module {{ agent_module }} --no-test {{ if description != "" { "--description " + quote(description) } else { "" } }}

# Get logs for a specific agent engine (requires: AGENT_ENGINE_RESOURCE_NAME in .env)
agent-engine-logs:
    #!/usr/bin/env bash
    set -a; [ -f "{{env_file}}" ] && source "{{env_file}}"; set +a
    if [ -z "$AGENT_ENGINE_RESOURCE_NAME" ]; then
        echo "Error: AGENT_ENGINE_RESOURCE_NAME is required. Set it in your {{env_file}} file or run agent-engine-deploy first."
        exit 1
    fi
    ENGINE_ID=$(echo "$AGENT_ENGINE_RESOURCE_NAME" | rev | cut -d'/' -f1 | rev)
    gcloud logging read "resource.labels.reasoning_engine_id=\"$ENGINE_ID\"" \
        --project="$GCP_PROJECT_ID" \
        --format="table(timestamp,severity,textPayload)" \
        --freshness=10m \
        --order=asc

# Redeploy the agent engine
agent-engine-redeploy description="": agent-engine-deploy
    @echo "Agent engine redeployment completed successfully!"

# Update Gemini Enterprise Agent Platform configuration
agentspace-redeploy: agentspace-update
    @echo "Gemini Enterprise Agent Platform configuration update completed successfully!"

# Redeploy agent engine and update Gemini Enterprise Agent Platform
redeploy-all: agent-engine-deploy agentspace-update
    @echo "Full redeployment completed successfully!"

# Complete OAuth setup (create auth and verify)
oauth-workflow: oauth-create-auth oauth-verify
    @echo "OAuth authorization setup completed successfully!"

# Deploy agent with OAuth and link to Gemini Enterprise Agent Platform
full-deploy-with-oauth: setup agent-engine-deploy oauth-workflow agentspace-link-agent
    @echo "Full deployment with OAuth completed successfully!"

# Check status of Gemini Enterprise Agent Platform registration
status: agentspace-verify
    @echo "Status check completed!"

# List agents and instruct how to clean up old instances
cleanup: agent-engine-list
    @echo "Use the agent index numbers shown above with 'just index=<number> agent-engine-delete-by-index' to clean up"

# Run all agent evaluations
eval:
    @echo "Running all evalsets..."
    {{ python }} -m google.adk.cli eval {{ agent_module }} evalsets/

# Run basic operations evalset
eval-basic:
    {{ python }} -m google.adk.cli eval {{ agent_module }} evalsets/soc_basic.evalset.json

# Run CTI research evalset
eval-cti:
    {{ python }} -m google.adk.cli eval {{ agent_module }} evalsets/cti_research.evalset.json

# Run custom CTI Researcher evaluation against the deployed cloud agent
test-eval-cti:
    {{ python }} {{ manage_eval }} run -f evalsets/cti_research.evalset.json

# Run custom Detection Engineer evaluation against the deployed cloud agent
test-eval-detection:
    {{ python }} {{ manage_eval }} run -f evalsets/detection_engineering.evalset.json

# Run custom Threat Hunter evaluation against the deployed cloud agent
test-eval-hunt:
    {{ python }} {{ manage_eval }} run -f evalsets/threat_hunting.evalset.json

# Run custom Tier 2 Responder evaluation against the deployed cloud agent
test-eval-response:
    {{ python }} {{ manage_eval }} run -f evalsets/incident_response.evalset.json

# Run custom evaluation for a specific evalset file against its deployed cloud agent (use file=path/to/file)
test-eval file:
    {{ python }} {{ manage_eval }} run -f {{ file }}

# Run Tier 1 triage evalset
eval-tier1:
    {{ python }} -m google.adk.cli eval {{ agent_module }} evalsets/tier1_triage.evalset.json

# Run multi-specialist evalset
eval-tier2:  # alias
    {{ python }} -m google.adk.cli eval {{ agent_module }} evalsets/multi_specialist.evalset.json

# Run all 7 evaluation sets concurrently (concurrency limit = 3)
test-eval-all:
    {{ python }} {{ manage_eval }} run-all --dir evalsets --concurrency 3

# Compare evaluation runs and view deltas (use evalset=id)
test-compare evalset:
    {{ python }} {{ manage_eval }} compare {{ evalset }}

# Profile agent latency (single run per query)
profile-latency:
    {{ python }} test_scripts/profile_latency.py

# Profile latency with multiple runs (use runs=N)
profile-latency-runs:
    #!/usr/bin/env bash
    RUNS_VAL="{{ runs }}"
    if [ -z "$RUNS_VAL" ]; then
        RUNS_VAL="3"
    fi
    {{ python }} test_scripts/profile_latency.py --runs "$RUNS_VAL"

# Profile RAG query latency only
profile-latency-rag:
    {{ python }} test_scripts/profile_latency.py --query-type rag

# Profile CTI query latency only
profile-latency-cti:
    {{ python }} test_scripts/profile_latency.py --query-type cti

# Profile Tier 1 query latency only
profile-latency-tier1:
    {{ python }} test_scripts/profile_latency.py --query-type tier1

# Check if required environment variables are set
check-env:
    #!/usr/bin/env bash
    if [ ! -f "{{env_file}}" ]; then
        echo "Error: {{env_file}} not found. Run 'just setup' first."
        exit 1
    fi
    echo "Environment file {{env_file}} exists"

# Run code linting (if available)
lint:
    #!/usr/bin/env bash
    if command -v ruff >/dev/null 2>&1; then
        echo "Running ruff linting..."
        ruff check .
    elif command -v flake8 >/dev/null 2>&1; then
        echo "Running flake8 linting..."
        flake8 .
    else
        echo "No linter available (install ruff or flake8)"
    fi

# Format code (if available)
format:
    #!/usr/bin/env bash
    if command -v ruff >/dev/null 2>&1; then
        echo "Running ruff formatting..."
        ruff format .
    elif command -v black >/dev/null 2>&1; then
        echo "Running black formatting..."
        black .
    else
        echo "No formatter available (install ruff or black)"
    fi

# Harvest and enrich investigations and detections from Chronicle SIEM
harvest: harvest-investigations harvest-detections

# Harvest and enrich investigations from Chronicle SIEM
harvest-investigations:
    {{ python }} {{ manage_harvest }} investigations

# Harvest and enrich alerting detections from Chronicle SIEM
harvest-detections:
    {{ python }} {{ manage_harvest }} detections

# Recreate the Elasticsearch index (deletes existing index first)
elastic-create:
    {{ python }} {{ manage_elastic }} create --env-file {{ env_file }}

# Sync local runbooks into Elasticsearch (use recreate="true" to recreate first)
elastic-sync recreate="false":
    {{ python }} {{ manage_elastic }} sync {{ if recreate == "true" { "--recreate" } else { "" } }} --env-file {{ env_file }}

# Search the Elasticsearch runbooks index (use: query="malware response" limit="3")
elastic-search query limit="3":
    {{ python }} {{ manage_elastic }} search {{ quote(query) }} --limit {{ limit }} --env-file {{ env_file }}

# Show details about the Elasticsearch index
elastic-info:
    {{ python }} {{ manage_elastic }} info --env-file {{ env_file }}

# Test the connection to the Neo4j database
neo4j-test:
    {{ python }} {{ manage_neo4j }} test-connection --env-file {{ env_file }}

# Ingest the flat knowledge graph JSON into Neo4j
neo4j-ingest:
    {{ python }} {{ manage_neo4j }} ingest --env-file {{ env_file }}

# Recalculate the threat graph from harvested investigations
neo4j-recalc:
    {{ python }} {{ manage_neo4j }} recalc

# Recalculate and ingest the threat graph into Neo4j
neo4j-sync: neo4j-recalc neo4j-ingest


# Clear all data in the Neo4j database (force=true to skip confirmation)
neo4j-clear force="false":
    {{ python }} {{ manage_neo4j }} clear {{ if force == "true" { "--force" } else { "" } }} --env-file {{ env_file }}

# Start a local Neo4j database container using Podman
neo4j-start:
    podman run -d --name neo4j_soc \
        -p 7474:7474 -p 7687:7687 \
        -e NEO4J_AUTH=neo4j/password \
        -v neo4j_data:/data:Z \
        -v neo4j_logs:/logs:Z \
        neo4j:5.20.0-community

# Stop and remove the local Neo4j database container
neo4j-stop:
    podman stop neo4j_soc && podman rm neo4j_soc

# Deploy Neo4j Database on a GCE VM with Firewall Rules configured
neo4j-gce-deploy:
    @echo "Creating GCP Firewall Rule: allow-neo4j-bolt..."
    -gcloud compute firewall-rules create allow-neo4j-bolt \
        --project=$GCP_PROJECT_ID \
        --direction=INGRESS \
        --priority=1000 \
        --network=default \
        --action=ALLOW \
        --rules=tcp:7687,tcp:7474 \
        --source-ranges=0.0.0.0/0 \
        --target-tags=neo4j-server
    @echo "Deploying GCE VM instance: neo4j-soc-db..."
    gcloud compute instances create neo4j-soc-db \
        --project=$GCP_PROJECT_ID \
        --zone=$NEO4J_VM_ZONE \
        --machine-type=e2-medium \
        --network-interface=network-tier=PREMIUM,subnet=default \
        --tags=neo4j-server \
        --metadata=neo4j-password=$NEO4J_PASSWORD \
        --metadata-from-file=startup-script=gce/startup_neo4j.sh

# Run a local-vs-cloud environment parity audit for a campaign
parity-audit uuid: check-prereqs
    {{ python }} installation_scripts/audit_environment_parity.py {{ uuid }}
