#!/usr/bin/env python3
"""
Agent Engine Manager for Google Vertex AI

This script manages Agent Engine (Reasoning Engine) operations including creating,
listing, testing, and deleting deployed agent engines.
"""

import asyncio
import json
import logging
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
import vertexai
from dotenv import load_dotenv, set_key
from google.api_core import client_options
from google.cloud import aiplatform
from google.cloud.aiplatform_v1beta1 import (
    DeleteReasoningEngineRequest,
    ListReasoningEnginesRequest,
    ReasoningEngineServiceClient,
)
from vertexai import agent_engines
from vertexai.preview.reasoning_engines import AdkApp

# Added AgentSpaceManager for synchronized UI purges
from installation_scripts.manage_agentspace import AgentSpaceManager


# Import Discovery Engine client for Agent Builder assistants
try:
    from google.cloud import discoveryengine_v1 as discoveryengine
except ImportError:
    discoveryengine = None
    logging.warning(
        "Discovery Engine client library not available. Install with: pip install google-cloud-discoveryengine"
    )


# Import SOC Agent package
sys.path.insert(0, str(Path(__file__).parent.parent))
# Additional imports for deployment
import importlib
import shutil

# Import validation utilities
from installation_scripts.env_validation import (
    format_validation_errors,
    validate_env_vars,
    validate_file_path_exists,
)


app = typer.Typer(
    add_completion=False,
    help="Manage Agent Engine instances in Vertex AI for the Google MCP Security Agent.",
)

# Debug mode configuration
DEBUG = os.environ.get("DEBUG", "False") == "True"

if DEBUG:
    os.environ["GRPC_VERBOSITY"] = "DEBUG"
    os.environ["GRPC_TRACE"] = "all"
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("google").setLevel(logging.DEBUG)
    logging.getLogger("google.auth").setLevel(logging.DEBUG)
    logging.getLogger("google.api_core").setLevel(logging.DEBUG)


class AgentEngineManager:
    """Manages Agent Engine operations in Vertex AI."""

    def __init__(self, env_file: Path):
        """
        Initialize the Agent Engine manager.

        Args:
            env_file: Path to the environment file.
        """
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project = None
        self.location = None
        self._initialize_vertex_ai()

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        env_vars = dict(os.environ)
        return env_vars

    def _initialize_vertex_ai(self) -> None:
        """Initialize Vertex AI with project and location from environment."""
        self.project = self.env_vars.get("GCP_PROJECT_ID")
        self.location = self.env_vars.get("GCP_LOCATION", "us-central1")

        if not self.project:
            typer.secho(
                " Missing required variable: GCP_PROJECT_ID", fg=typer.colors.RED
            )
            raise typer.Exit(code=1)

        try:
            vertexai.init(project=self.project, location=self.location)
            aiplatform.init(project=self.project, location=self.location)
            typer.secho(
                f"Initialized Vertex AI - Project: {self.project}, Location: {self.location}",
                fg=typer.colors.GREEN,
            )
        except Exception as e:
            typer.secho(f" Failed to initialize Vertex AI: {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    def _format_timestamp(self, timestamp) -> str:
        """Format timestamp to readable string."""
        if timestamp:
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        return "N/A"

    def list_agents(self, verbose: bool = False) -> list[dict]:
        """
        List all Agent Engine instances.

        Args:
            verbose: Show detailed information for each agent

        Returns:
            List of agent information dictionaries
        """
        typer.echo("\n" + "=" * 80)
        typer.secho("Listing Agent Engine Instances", fg=typer.colors.BLUE, bold=True)
        typer.echo("=" * 80 + "\n")

        try:
            endpoint = f"{self.location}-aiplatform.googleapis.com"
            client_opts = client_options.ClientOptions(api_endpoint=endpoint)
            client = ReasoningEngineServiceClient(client_options=client_opts)

            parent = f"projects/{self.project}/locations/{self.location}"

            # Use explicit pagination to avoid infinite loops
            # Set a reasonable page size to prevent excessive API calls
            request = ListReasoningEnginesRequest(
                parent=parent,
                page_size=100,  # Reasonable limit per page
                page_token="",  # Start from first page
            )

            agent_list = []
            page_count = 0
            max_pages = 50  # Safety limit to prevent infinite pagination

            # Manually iterate through pages with safety limits
            while True:
                page_count += 1
                if page_count > max_pages:
                    typer.secho(
                        f"\nWarning: Reached maximum page limit ({max_pages}). "
                        "There may be more agents not shown.",
                        fg=typer.colors.YELLOW,
                    )
                    break

                if DEBUG:
                    typer.echo(f"Fetching page {page_count}...")

                response = client.list_reasoning_engines(request=request)

                # Add agents from this page
                for agent in response.reasoning_engines:
                    agent_list.append(agent)

                # Check if there are more pages
                if not response.next_page_token:
                    break

                # Update request for next page
                request.page_token = response.next_page_token

            if DEBUG:
                typer.echo(f"Total pages fetched: {page_count}")

            if not agent_list:
                typer.secho("No Agent Engine instances found.", fg=typer.colors.YELLOW)
                return []

            typer.echo(
                f"Found {typer.style(str(len(agent_list)), fg=typer.colors.CYAN)} Agent Engine instance(s):\n"
            )

            # Build the return list with agent info dictionaries
            agents_info_list = []
            for i, agent in enumerate(agent_list, 1):
                agent_info = {
                    "resource_name": agent.name,
                    "display_name": agent.display_name,
                    "create_time": agent.create_time,
                    "update_time": agent.update_time,
                    "state": agent.state.name if hasattr(agent, "state") else "UNKNOWN",
                }
                agents_info_list.append(agent_info)

                typer.secho(f"{i}. {agent.display_name}", fg=typer.colors.CYAN)
                typer.echo(f"   Resource: {agent.name}")
                typer.echo(
                    f"   Created: {self._format_timestamp(agent.create_time.timestamp() if agent.create_time else None)}"
                )
                typer.echo(
                    f"   Updated: {self._format_timestamp(agent.update_time.timestamp() if agent.update_time else None)}"
                )

                if verbose:
                    typer.echo(f"   State: {agent_info['state']}")
                    try:
                        full_agent = agent_engines.get(agent.name)
                        typer.echo(f"   Type: {type(full_agent).__name__}")
                    except Exception as e:
                        typer.secho(
                            f"   Could not fetch additional details: {e}",
                            fg=typer.colors.YELLOW,
                        )

                typer.echo()

            return agents_info_list

        except Exception as e:
            typer.secho(f" Error listing agents: {e}", fg=typer.colors.RED)
            return []

    def list_assistants(
        self,
        engine_id: str = None,
        collection_id: str = "default_collection",
        verbose: bool = False,
    ) -> list[dict]:
        """
        List assistants from Discovery Engine/Agent Builder.

        Args:
            engine_id: The engine/app ID to list assistants for. If not provided, will list all engines first.
            collection_id: The collection ID (default: "default_collection")
            verbose: Show detailed information for each assistant

        Returns:
            List of assistant information dictionaries
        """
        if not discoveryengine:
            typer.secho(
                " Discovery Engine client library not installed.", fg=typer.colors.RED
            )
            typer.echo("Install with: pip install google-cloud-discoveryengine")
            return []

        typer.echo("\n" + "=" * 80)
        typer.secho("Listing Agent Builder Assistants", fg=typer.colors.BLUE, bold=True)
        typer.echo("=" * 80 + "\n")

        try:
            # If no engine_id provided, first list available engines
            if not engine_id:
                typer.secho(
                    "No engine ID specified. Listing available engines first...",
                    fg=typer.colors.YELLOW,
                )
                engines = self.list_engines(collection_id=collection_id)
                if not engines:
                    typer.secho(
                        "No engines found. Please create an engine first.",
                        fg=typer.colors.YELLOW,
                    )
                    return []

                # Let user select an engine
                typer.echo("\nAvailable engines:")
                for i, engine in enumerate(engines, 1):
                    typer.echo(
                        f"{i}. {engine['name'].split('/')[-1]} - {engine.get('display_name', 'No display name')}"
                    )

                # For now, we'll just return and ask user to specify engine_id
                typer.secho(
                    "\nPlease specify an engine ID to list its assistants.",
                    fg=typer.colors.YELLOW,
                )
                return []

            # Create Discovery Engine client
            client = discoveryengine.ConversationalSearchServiceClient()

            # Construct parent path
            parent = f"projects/{self.project}/locations/{self.location}/collections/{collection_id}/engines/{engine_id}"

            typer.echo(f"Listing assistants for engine: {parent}")

            # Create request to list assistants
            request = discoveryengine.ListConversationsRequest(
                parent=parent,
                page_size=100,  # Reasonable limit per page
            )

            assistant_list = []
            page_count = 0
            max_pages = 50  # Safety limit

            # Paginate through results
            while True:
                page_count += 1
                if page_count > max_pages:
                    typer.secho(
                        f"\nWarning: Reached maximum page limit ({max_pages}). "
                        "There may be more assistants not shown.",
                        fg=typer.colors.YELLOW,
                    )
                    break

                if DEBUG:
                    typer.echo(f"Fetching page {page_count}...")

                # Note: The actual method name might be list_conversations or similar
                # depending on the Discovery Engine API version
                try:
                    response = client.list_conversations(request=request)
                except AttributeError:
                    # Try alternative method names
                    typer.secho(
                        " API method not found. The Discovery Engine API may have changed.",
                        fg=typer.colors.RED,
                    )
                    return []

                # Add assistants from this page
                for conversation in response.conversations:
                    assistant_info = {
                        "name": conversation.name,
                        "display_name": getattr(conversation, "display_name", "N/A"),
                        "state": getattr(conversation, "state", "UNKNOWN"),
                        "start_time": getattr(conversation, "start_time", None),
                        "end_time": getattr(conversation, "end_time", None),
                    }
                    assistant_list.append(assistant_info)

                # Check if there are more pages
                if not response.next_page_token:
                    break

                # Update request for next page
                request.page_token = response.next_page_token

            if DEBUG:
                typer.echo(f"Total pages fetched: {page_count}")

            if not assistant_list:
                typer.secho(
                    f"No assistants found in engine: {engine_id}",
                    fg=typer.colors.YELLOW,
                )
                return []

            typer.echo(
                f"Found {typer.style(str(len(assistant_list)), fg=typer.colors.CYAN)} assistant(s):\n"
            )

            for i, assistant in enumerate(assistant_list, 1):
                typer.secho(f"{i}. {assistant['display_name']}", fg=typer.colors.CYAN)
                typer.echo(f"   Resource: {assistant['name']}")
                typer.echo(f"   State: {assistant['state']}")

                if verbose:
                    if assistant["start_time"]:
                        typer.echo(f"   Start Time: {assistant['start_time']}")
                    if assistant["end_time"]:
                        typer.echo(f"   End Time: {assistant['end_time']}")

                typer.echo()

            return assistant_list

        except Exception as e:
            typer.secho(f" Error listing assistants: {e}", fg=typer.colors.RED)
            if DEBUG:
                import traceback

                typer.echo(traceback.format_exc())
            return []

    def list_engines(self, collection_id: str = "default_collection") -> list[dict]:
        """
        List Discovery Engine engines/apps.

        Args:
            collection_id: The collection ID (default: "default_collection")

        Returns:
            List of engine information dictionaries
        """
        if not discoveryengine:
            typer.secho(
                " Discovery Engine client library not installed.", fg=typer.colors.RED
            )
            return []

        try:
            # Create Discovery Engine client for engines
            client = discoveryengine.EngineServiceClient()

            # Construct parent path for engines
            parent = f"projects/{self.project}/locations/{self.location}/collections/{collection_id}"

            # Create request to list engines
            request = discoveryengine.ListEnginesRequest(
                parent=parent,
                page_size=100,
            )

            engines_list = []

            # Get first page of results
            response = client.list_engines(request=request)

            for engine in response.engines:
                engine_info = {
                    "name": engine.name,
                    "display_name": getattr(engine, "display_name", "N/A"),
                    "solution_type": getattr(engine, "solution_type", "UNKNOWN"),
                    "create_time": getattr(engine, "create_time", None),
                }
                engines_list.append(engine_info)

            return engines_list

        except Exception as e:
            if DEBUG:
                typer.secho(f" Error listing engines: {e}", fg=typer.colors.RED)
            return []

    def get_agents_by_display_name(self, display_name: str) -> list[dict]:
        """
        Find all Agent Engine instances with a specific display name.
        """
        agents = self.list_agents(verbose=False)
        return [a for a in agents if a.get("display_name") == display_name]

    def delete_agent(self, resource_name: str, force: bool = False) -> bool:
        """
        Delete a specific Agent Engine instance.

        Args:
            resource_name: Full resource name of the agent to delete
            force: Skip confirmation prompt

        Returns:
            True if successful, False otherwise
        """
        typer.echo("\n" + "=" * 80)
        typer.secho("Deleting Agent Engine Instance", fg=typer.colors.RED, bold=True)
        typer.echo("=" * 80 + "\n")

        try:
            endpoint = f"{self.location}-aiplatform.googleapis.com"
            client_opts = client_options.ClientOptions(api_endpoint=endpoint)
            client = ReasoningEngineServiceClient(client_options=client_opts)

            typer.echo(f"Fetching agent: {resource_name}")
            agent = client.get_reasoning_engine(name=resource_name)

            typer.secho("\nAgent Details:", fg=typer.colors.YELLOW)
            typer.echo(f"  Name: {agent.display_name}")
            typer.echo(f"  Resource: {agent.name}")
            typer.echo(
                f"  Created: {self._format_timestamp(agent.create_time.timestamp() if agent.create_time else None)}"
            )

            if not force:
                if not typer.confirm(
                    "\nAre you sure you want to delete this agent?",
                    default=False,
                ):
                    typer.secho("Deletion cancelled.", fg=typer.colors.YELLOW)
                    return False

            typer.secho("\nDeleting agent...", fg=typer.colors.YELLOW)
            request = DeleteReasoningEngineRequest(
                name=resource_name, force=True  # Delete child resources too
            )
            client.delete_reasoning_engine(request=request)
            typer.secho("Agent deleted successfully!", fg=typer.colors.GREEN)
            return True

        except Exception as e:
            typer.secho(f" Error deleting agent: {e}", fg=typer.colors.RED)
            return False

    def delete_agent_by_index(self, index: int, force: bool = False) -> bool:
        """
        Delete an agent by its index in the list.

        Args:
            index: Index of the agent in the list (1-based)
            force: Skip confirmation prompt

        Returns:
            True if successful, False otherwise
        """
        agents = self.list_agents(verbose=False)

        if not agents:
            return False

        if index < 1 or index > len(agents):
            typer.secho(
                f" Invalid index. Please choose between 1 and {len(agents)}",
                fg=typer.colors.RED,
            )
            return False

        agent = agents[index - 1]
        return self.delete_agent(agent["resource_name"], force)

    def create_agent(
        self,
        agent_module: str = "agent_soc_manager",
        debug: bool = False,
        no_test: bool = False,
        description: str | None = None,
    ) -> str | None:
        return self._deploy_agent_internal(
            agent_module=agent_module,
            debug=debug,
            no_test=no_test,
            is_update=False,
            description=description,
        )

    def update_agent(
        self,
        resource_name: str,
        agent_module: str = "agent_soc_manager",
        debug: bool = False,
        no_test: bool = False,
        description: str | None = None,
    ) -> str | None:
        return self._deploy_agent_internal(
            agent_module=agent_module,
            debug=debug,
            no_test=no_test,
            is_update=True,
            update_resource_name=resource_name,
            description=description,
        )

    def _deploy_agent_internal(
        self,
        agent_module: str = "agent_soc_manager",
        debug: bool = False,
        no_test: bool = False,
        is_update: bool = False,
        update_resource_name: str | None = None,
        description: str | None = None,
    ) -> str | None:
        """
        Create and deploy a new Agent Engine instance.

        Args:
            agent_module: Name of the agent module to import (default: "agent_soc_manager")
            debug: Enable debug mode with verbose logging
            no_test: Skip the automatic test after creation

        Returns:
            Resource name of the created agent if successful, None otherwise
        """
        typer.echo("\n" + "=" * 80)
        action_text = "Updating" if is_update else "Creating"
        typer.secho(
            f"{action_text} Agent Engine Instance", fg=typer.colors.BLUE, bold=True
        )
        typer.echo("=" * 80 + "\n")

        typer.echo(f"Agent module: {agent_module}")

        # Set debug mode
        if debug:
            os.environ["DEBUG"] = "True"
            os.environ["GRPC_VERBOSITY"] = "DEBUG"
            os.environ["GRPC_TRACE"] = "all"
            logging.basicConfig(level=logging.DEBUG)
            logging.getLogger("google").setLevel(logging.DEBUG)
            logging.getLogger("google.auth").setLevel(logging.DEBUG)
            logging.getLogger("google.api_core").setLevel(logging.DEBUG)

        try:
            # Load environment variables
            typer.echo("Loading environment configuration...")
            load_dotenv(self.env_file, override=True)

            # Validate required environment variables
            # Note: CHRONICLE_SERVICE_ACCOUNT_PATH is optional if CHRONICLE_SERVICE_ACCOUNT_SECRET is set
            required_vars = [
                "GCP_PROJECT_ID",
                "GCP_LOCATION",
                "GCP_STAGING_BUCKET",
                "CHRONICLE_PROJECT_ID",
                "CHRONICLE_CUSTOMER_ID",
                "SOAR_URL",
                "SOAR_APP_KEY",
                "GTI_API_KEY",
                "RAG_CORPUS_ID",
            ]

            # Check for missing or placeholder values
            is_valid, errors = validate_env_vars(required_vars)
            if not is_valid:
                typer.secho(" Configuration Error", fg=typer.colors.RED, bold=True)
                typer.echo()
                typer.echo(format_validation_errors(errors))
                return None

            # Validate service account configuration (either secret or file path required)
            has_secret = bool(os.environ.get("CHRONICLE_SERVICE_ACCOUNT_SECRET"))
            has_path = bool(os.environ.get("CHRONICLE_SERVICE_ACCOUNT_PATH"))

            if not has_secret and not has_path:
                typer.secho(" Configuration Error", fg=typer.colors.RED, bold=True)
                typer.echo()
                typer.echo(
                    "Either CHRONICLE_SERVICE_ACCOUNT_SECRET or CHRONICLE_SERVICE_ACCOUNT_PATH must be set"
                )
                typer.echo()
                typer.echo("Option 1 (Recommended): Use Secret Manager")
                typer.echo(
                    "  1. Upload SA file: python installation_scripts/upload_secret.py upload"
                )
                typer.echo(
                    "  2. Add to .env: CHRONICLE_SERVICE_ACCOUNT_SECRET=projects/PROJECT/secrets/SECRET/versions/latest"
                )
                typer.echo()
                typer.echo("Option 2 (Legacy): Use local file")
                typer.echo(
                    "  Add to .env: CHRONICLE_SERVICE_ACCOUNT_PATH=/path/to/service-account.json"
                )
                return None

            # Validate RAG_CORPUS_ID format
            # Pattern validates GCP resource name structure for RAG corpora.
            # Supports both numeric and alphanumeric corpus IDs with common separators.
            # This is intentionally permissive to allow for GCP naming flexibility
            # while catching obvious format errors (missing slashes, wrong order).
            rag_corpus_id = os.environ.get("RAG_CORPUS_ID", "")
            rag_pattern = r"^projects/[^/]+/locations/[^/]+/ragCorpora/[a-zA-Z0-9_-]+$"
            if not re.match(rag_pattern, rag_corpus_id):
                typer.secho(
                    f" Invalid RAG_CORPUS_ID format: {rag_corpus_id}",
                    fg=typer.colors.RED,
                )
                typer.secho(
                    "  Expected format: projects/PROJECT_ID/locations/LOCATION/ragCorpora/CORPUS_ID",
                    fg=typer.colors.YELLOW,
                )
                return None

            # Initialize Vertex AI
            typer.echo("Initializing Vertex AI...")
            GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")
            GCP_LOCATION = os.environ.get("GCP_LOCATION", "us-central1")
            GCP_STAGING_BUCKET = os.environ.get("GCP_STAGING_BUCKET")

            vertexai.init(
                project=GCP_PROJECT_ID,
                location=GCP_LOCATION,
                staging_bucket=GCP_STAGING_BUCKET,
            )

            # Handle Chronicle service account authentication
            # Priority: Secret Manager > Local File
            CHRONICLE_SERVICE_ACCOUNT_SECRET = os.environ.get(
                "CHRONICLE_SERVICE_ACCOUNT_SECRET"
            )
            CHRONICLE_SERVICE_ACCOUNT_PATH = os.environ.get(
                "CHRONICLE_SERVICE_ACCOUNT_PATH"
            )

            if CHRONICLE_SERVICE_ACCOUNT_SECRET:
                typer.secho(
                    "Using Secret Manager for service account authentication",
                    fg=typer.colors.GREEN,
                )
                typer.echo(f"  Secret: {CHRONICLE_SERVICE_ACCOUNT_SECRET}")
                # No file copying needed - MCP server will read from Secret Manager
                use_secret_manager = True
            elif CHRONICLE_SERVICE_ACCOUNT_PATH:
                # Validate the service account file path exists and is not a placeholder
                file_error = validate_file_path_exists(
                    "CHRONICLE_SERVICE_ACCOUNT_PATH", CHRONICLE_SERVICE_ACCOUNT_PATH
                )
                if file_error:
                    typer.secho(" Configuration Error", fg=typer.colors.RED, bold=True)
                    typer.echo()
                    typer.echo(format_validation_errors([file_error]))
                    return None

                typer.secho(
                    "Using local file for service account authentication (legacy mode)",
                    fg=typer.colors.YELLOW,
                )
                typer.echo(f"  Path: {CHRONICLE_SERVICE_ACCOUNT_PATH}")
                # Copy to the root of the deployment directory instead of inside the module
                dest_dir = Path(".")
                dest_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy(CHRONICLE_SERVICE_ACCOUNT_PATH, dest_dir)
                sa_filename = Path(CHRONICLE_SERVICE_ACCOUNT_PATH).name
                typer.echo(
                    f"Copied service account file ({sa_filename}) to project root for deployment"
                )
                use_secret_manager = False
            else:
                raise ValueError(
                    "Either CHRONICLE_SERVICE_ACCOUNT_SECRET or CHRONICLE_SERVICE_ACCOUNT_PATH must be set"
                )

            # Dynamically import and create the agent from the specified module
            typer.echo(f"Importing agent from {agent_module}...")
            os.environ["REASONING_ENGINE_DEPLOYMENT"] = "True"
            if "GOOGLE_CLOUD_PROJECT" not in os.environ and GCP_PROJECT_ID:
                os.environ["GOOGLE_CLOUD_PROJECT"] = GCP_PROJECT_ID
            # Allow Vertex AI init - agents need it to use Vertex AI models instead of genai client
            try:
                agent_pkg = importlib.import_module(agent_module)
                create_agent_func = agent_pkg.create_agent
            except ImportError as e:
                typer.secho(
                    f" Failed to import agent module '{agent_module}': {e}",
                    fg=typer.colors.RED,
                )
                return None
            except AttributeError:
                typer.secho(
                    f" Module '{agent_module}' does not have a 'create_agent' function",
                    fg=typer.colors.RED,
                )
                return None

            typer.echo("Creating agent...")
            agent = create_agent_func()

            # Extract memory bank configuration if present
            memory_bank_config = getattr(agent_pkg, "memory_bank_config", None)
            if memory_bank_config:
                typer.secho(
                    f"Found Memory Bank configuration with {len(memory_bank_config.get('customization_configs', [{}])[0].get('memory_topics', []))} topics",
                    fg=typer.colors.CYAN,
                )
            else:
                typer.secho(
                    "No Memory Bank configuration found in agent module.",
                    fg=typer.colors.YELLOW,
                )

            # Create the ADK app
            from google.adk.artifacts.gcs_artifact_service import GcsArtifactService

            def build_artifact_service():
                bucket_name = os.environ.get("GCP_ARTIFACT_BUCKET")
                if not bucket_name:
                    raise ValueError(
                        "GCP_ARTIFACT_BUCKET is required for GcsArtifactService (set in .env)"
                    )
                if bucket_name.startswith("gs://"):
                    bucket_name = bucket_name[5:]
                return GcsArtifactService(bucket_name=bucket_name)

            typer.echo("Creating ADK app...")
            app = AdkApp(
                agent=agent,
                enable_tracing=True,
                artifact_service_builder=build_artifact_service,
            )
            # Get environment variables for deployment
            # HYBRID APPROACH:
            # - RAG sub-agent uses Vertex AI (initialized in agent code)
            # - Other agents use Gemini API key (no location restrictions!)
            env_vars = {
                "CHRONICLE_PROJECT_ID": os.environ.get("CHRONICLE_PROJECT_ID"),
                "CHRONICLE_CUSTOMER_ID": os.environ.get("CHRONICLE_CUSTOMER_ID"),
                "CHRONICLE_REGION": os.environ.get("CHRONICLE_REGION", "us"),
                "GCP_VERTEXAI_ENABLED": os.environ.get("GCP_VERTEXAI_ENABLED", "TRUE"),
                "PROJECT_ID": os.environ.get("GCP_PROJECT_ID"),
                "GCP_PROJECT_ID": os.environ.get("GCP_PROJECT_ID"),
                "GCP_LOCATION": os.environ.get("GCP_LOCATION", "us-central1"),
                "GCP_STAGING_BUCKET": os.environ.get("GCP_STAGING_BUCKET"),
                "GCP_ARTIFACT_BUCKET": os.environ.get("GCP_ARTIFACT_BUCKET"),
                "RAG_CORPUS_ID": os.environ.get("RAG_CORPUS_ID"),
                "SOAR_URL": os.environ.get("SOAR_URL"),
                "SOAR_APP_KEY": os.environ.get("SOAR_APP_KEY"),
                "VT_APIKEY": os.environ.get("GTI_API_KEY"),
                # API keys excluded - deployed agent uses Vertex AI ambient credentials
                # Gemini 3.x workaround: Route model calls to global endpoint
                # See: https://github.com/google/adk-python/issues/3628
                "GOOGLE_CLOUD_LOCATION": "global",
                "GOOGLE_GENAI_USE_VERTEXAI": "TRUE",
                # OpenTelemetry Tracing and Logging
                "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY": "TRUE",
                "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "TRUE",
                "OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT": "32768",  # Truncate large tool payloads to prevent 64KB GCP Trace limit crash
                "OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT": "32768",
                "OTEL_SERVICE_NAME": "adk-soc-agent",
                "OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED": "TRUE",
                # GTI Response Caching (Latency Optimization)
                "GTI_CACHE_ENABLED": os.environ.get("GTI_CACHE_ENABLED", "True"),
                "GTI_CACHE_FILE_TTL": os.environ.get(
                    "GTI_CACHE_FILE_TTL", "86400"
                ),  # 24h
                "GTI_CACHE_IP_TTL": os.environ.get("GTI_CACHE_IP_TTL", "43200"),  # 12h
                "GTI_CACHE_DOMAIN_TTL": os.environ.get(
                    "GTI_CACHE_DOMAIN_TTL", "1800"
                ),  # 30m
                "GTI_CACHE_URL_TTL": os.environ.get("GTI_CACHE_URL_TTL", "1800"),  # 30m
                "GTI_CACHE_THREAT_ACTOR_TTL": os.environ.get(
                    "GTI_CACHE_THREAT_ACTOR_TTL", "86400"
                ),  # 24h
                "GTI_CACHE_MALWARE_FAMILY_TTL": os.environ.get(
                    "GTI_CACHE_MALWARE_FAMILY_TTL", "86400"
                ),  # 24h
                "GTI_CACHE_CAMPAIGN_TTL": os.environ.get(
                    "GTI_CACHE_CAMPAIGN_TTL", "43200"
                ),  # 12h
                "GTI_CACHE_REPORT_TTL": os.environ.get(
                    "GTI_CACHE_REPORT_TTL", "43200"
                ),  # 12h
                "GTI_CACHE_COLLECTION_TTL": os.environ.get(
                    "GTI_CACHE_COLLECTION_TTL", "43200"
                ),  # 12h
                "GTI_CACHE_THREAT_PROFILE_TTL": os.environ.get(
                    "GTI_CACHE_THREAT_PROFILE_TTL", "86400"
                ),  # 24h
                "GTI_CACHE_HUNTING_RULESET_TTL": os.environ.get(
                    "GTI_CACHE_HUNTING_RULESET_TTL", "86400"
                ),  # 24h
                "GTI_CACHE_MAX_SIZE": os.environ.get("GTI_CACHE_MAX_SIZE", "250"),
                # ChatOps Webhook URL (passed to Reasoning Engine)
                "WEBHOOK_URL": os.environ.get("WEBHOOK_URL"),
                "CHATOPS_BASE_URL": os.environ.get("CHATOPS_BASE_URL"),
                "CHRONICLE_CHATOPS_SECRET": os.environ.get("CHRONICLE_CHATOPS_SECRET"),
                # Remote Specialist A2A Coordinates
                "TIER2_AGENT_RESOURCE_NAME": os.environ.get("TIER2_AGENT_RESOURCE_NAME"),
                "TIER1_AGENT_RESOURCE_NAME": os.environ.get("TIER1_AGENT_RESOURCE_NAME"),
            }

            # Add service account configuration based on authentication method
            if use_secret_manager:
                # Use Secret Manager - pass secret resource name
                env_vars["CHRONICLE_SERVICE_ACCOUNT_SECRET"] = (
                    CHRONICLE_SERVICE_ACCOUNT_SECRET
                )
            else:
                # Use local file - pass filename only (file already copied to package)
                sa_filename = Path(CHRONICLE_SERVICE_ACCOUNT_PATH).name
                env_vars["SECOPS_SA_PATH"] = sa_filename

            # Filter out None values to prevent Vertex AI SDK validation errors
            env_vars = {k: v for k, v in env_vars.items() if v is not None}

            # Determine display name based on agent module
            if agent_module == "agent_a2a_tier2":
                display_name = "SecOps Security Agent - Tier 2"
            elif agent_module == "agent_soc_manager":
                display_name = "SecOps Security Agent - Orchestrator"
            else:
                # For any future agent modules, use the module name as-is
                display_name = f"SecOps Security Agent - {agent_module}"

            # Ensure we do not break Gemini Enterprise Proxy UI Schemas natively generating '500 Server Errors'
            typer.echo("Configuring Workspace Endpoint Schema Compatibility Profile...")
            for key in dict(app.__dict__).keys():
                if key.startswith("async_"):
                    # Hide the property from the Pydantic type reflector natively using primitive bindings
                    app.__dict__[key] = "Schema Compatibility Shadow Wrapper"

            # Deploy or Update the agent engine
            action_verb = "Updating" if is_update else "Deploying"
            typer.echo(
                f"{action_verb} agent engine to Vertex AI as '{display_name}'..."
            )

            extra_packages = [
                "installation_scripts/install.sh",  # installs MCP server packages
                "agent_soc_manager",
                "agent_a2a_tier2",
                "external/mcp-security/server/secops",
                "external/mcp-security/server/secops-soar",
                "external/mcp-security/server/gti",
                "external/mcp-security/server/scc",
            ]
            if not use_secret_manager:
                extra_packages.append(sa_filename)

            deploy_kwargs = {
                "display_name": display_name,
                "description": description,
                "requirements": [
                    "cloudpickle",
                    "google-adk~=2.0.0",
                    "google-cloud-aiplatform[agent-engines,evaluation]~=1.153.0",
                    "pydantic",
                    "python-dotenv",
                    "httpx>=0.28.1",
                    "mcp[cli]>=1.4.1",
                    "secops>=0.18.0",
                    "google-auth>=2.38.0",
                    "google-auth-httplib2>=0.2.0",
                    "google-api-python-client>=2.164.0",
                    "aiohttp>=3.11.15",
                    "vt-py",
                    "typing-extensions>=4.8.0",
                    "google-cloud-securitycenter>=1.38.0",
                    "google-cloud-asset>=3.15.0",
                    "google-cloud-secret-manager>=2.16.0",  # For Secret Manager access
                    "google-cloud-logging>=3.11.0",
                    "opentelemetry-sdk>=1.26.0",
                    "opentelemetry-exporter-gcp-logging>=0.47b0",
                    "opentelemetry-instrumentation-google-genai>=0.0.1",
                ],
                "build_options": {
                    "installation_scripts": ["installation_scripts/install.sh"]
                },
                "extra_packages": extra_packages,
                "env_vars": env_vars,
            }

            # Add Memory Bank configuration logging
            if memory_bank_config:
                typer.secho(
                    "Memory Bank custom topics found in agent module.",
                    fg=typer.colors.CYAN,
                )
            else:
                logging.info("DEPLOYMENT: No memory_bank_config found.")

            if is_update:
                if not update_resource_name:
                    raise ValueError(
                        "update_resource_name must be provided for updates"
                    )
                remote_app = agent_engines.update(
                    resource_name=update_resource_name,
                    agent_engine=app,
                    **deploy_kwargs,
                )
            else:
                remote_app = agent_engines.create(app, **deploy_kwargs)

            # If memory bank config is present, we must apply it via a separate update
            # because the high-level create/update APIs don't currently support context_spec
            if memory_bank_config:
                try:
                    typer.echo("Applying Memory Bank custom topics configuration...")
                    client = vertexai.Client(
                        project=self.project, location=self.location
                    )

                    # Debug: Check if already present
                    existing_agent = client.agent_engines.get(
                        name=remote_app.resource_name
                    )
                    if existing_agent.api_resource.context_spec:
                        typer.echo("Existing context_spec found. Updating...")
                    else:
                        typer.echo("No existing context_spec found. Creating...")

                    client.agent_engines.update(
                        name=remote_app.resource_name,
                        config={
                            "context_spec": {"memory_bank_config": memory_bank_config}
                        },
                    )

                    # Verify after update
                    updated_agent = client.agent_engines.get(
                        name=remote_app.resource_name
                    )
                    if updated_agent.api_resource.context_spec:
                        typer.secho(
                            "Memory Bank configuration verified on backend!",
                            fg=typer.colors.GREEN,
                        )
                    else:
                        typer.secho(
                            "Warning: Memory Bank configuration NOT found on backend after update.",
                            fg=typer.colors.YELLOW,
                        )

                    typer.secho(
                        "Memory Bank configuration applied successfully!",
                        fg=typer.colors.GREEN,
                    )
                except Exception as e:
                    typer.secho(
                        f"Warning: Failed to apply Memory Bank configuration: {e}",
                        fg=typer.colors.YELLOW,
                    )
                    logging.error(
                        f"DEPLOYMENT_ERROR: Failed to update context_spec: {e}",
                        exc_info=True,
                    )

            success_text = "updated" if is_update else "deployed"
            typer.secho(f"\n Agent {success_text} successfully!", fg=typer.colors.GREEN)
            typer.echo(f"Resource name: {remote_app.resource_name}")

            # Optionally run test
            if not no_test:
                typer.echo("\nRunning test...")
                self.test_agent_with_resource(remote_app.resource_name, agent_module=agent_module)

            return remote_app.resource_name

        except Exception as e:
            typer.secho(f" Error creating agent: {e}", fg=typer.colors.RED)
            import traceback

            typer.echo(traceback.format_exc())
            return None

    def test_agent_with_resource(self, resource_name: str, agent_module: str = "soc_agent") -> bool:
        """
        Test a deployed agent engine with a sample query.

        Args:
            resource_name: Resource name of the agent to test

        Returns:
            True if test successful, False otherwise
        """
        try:
            typer.echo("\n" + "=" * 80)
            typer.secho("Testing Agent Engine", fg=typer.colors.CYAN, bold=True)
            typer.echo("=" * 80 + "\n")

            # Get the agent
            remote_app = agent_engines.get(resource_name)

            # Run async test
            asyncio.run(self._async_test_agent(remote_app, agent_module=agent_module))
            return True

        except Exception as e:
            typer.secho(f" Error testing agent: {e}", fg=typer.colors.RED)
            return False

    async def _async_test_agent(self, remote_app, agent_module: str = "soc_agent"):
        """Async test function for agent engine."""
        fd, log_path = tempfile.mkstemp(suffix=".log", prefix="agent_test_")
        typer.secho(
            f"\nRedirecting detailed test events to: {log_path}", fg=typer.colors.CYAN
        )

        with os.fdopen(fd, "w") as log_file:
            user_id = "test_user"
            session = await remote_app.async_create_session(user_id=user_id)
            session_id = session.get("id")
            typer.echo(f"Created session: {session_id}")
            log_file.write(f"Created session: {session_id}\n")

            if agent_module == "agent_soc_manager":
                test_messages = (
                    "We have confirmed active ransomware encryption and beaconing from host MALWARETEST-WIN. Please isolate this endpoint from the network immediately to contain the threat.",
                )
            elif agent_module == "agent_a2a_tier2":
                test_messages = (
                    "Isolate compromised host MALWARETEST-WIN from the network.",
                )
            else:
                test_messages = (
                    "Use the get_ioc_matches tool for domain superstarts.top",
                # "Get the 2 documents on Malware and then fetch_full_document for both",
                # "List rules with ursnif in the name.",  # Chronicle SIEM MCP
                # "List the first page of soar cases.",  # SOAR MCP
                # memory save test
                # "For our future investigations, please note that we have a critical asset: MALWARETEST-WIN at IP 50.90.32.142. Please acknowledge this so we have it for future reference.",
                # soar case search test
                # "Can you check our SOAR case management system to see if we have any currently open security cases that might relate to APT29?",
            )

            for test_message in test_messages:
                typer.echo(f"\nSending test query: {test_message}")
                log_file.write(f"\n--- QUERY: {test_message} ---\n")

                events = []
                async for event in remote_app.async_stream_query(
                    user_id=user_id, session_id=session_id, message=test_message
                ):
                    log_file.write(f"Event: {event}\n")
                    print(f"Event: {event}\n")
                    events.append(event)
                    # Optional: Print a dot to show progress instead of full event
                    print(".", end="", flush=True)

                print()  # New line after dots

                if not events:
                    typer.secho(
                        " No events received from agent!", fg=typer.colors.YELLOW
                    )
                    log_file.write("No events received from agent!\n")
                else:
                    typer.secho(
                        f" Test completed successfully - received {len(events)} events",
                        fg=typer.colors.GREEN,
                    )
                    log_file.write(
                        f"Test completed successfully - received {len(events)} events\n"
                    )

        typer.secho(f"\nDetailed logs available at: {log_path}\n", fg=typer.colors.CYAN)

    def warmup_mcp_servers(self, resource_name: str) -> bool:
        """
        Pre-warm MCP server connections to reduce cold start latency.

        This function sends simple queries that initialize connections to each MCP server:
        - SOAR MCP (list_cases)
        - GTI MCP (IP reputation check)
        - Chronicle SIEM MCP (basic search)

        Recommended to run after deployment or when agent has been idle.

        Args:
            resource_name: Resource name of the agent to warm up

        Returns:
            True if warmup successful, False otherwise
        """
        try:
            typer.echo("\n" + "=" * 80)
            typer.secho("MCP Connection Pre-Warming", fg=typer.colors.CYAN, bold=True)
            typer.echo("=" * 80 + "\n")
            typer.echo(
                "Initializing MCP server connections to reduce cold start latency..."
            )

            # Get the agent
            remote_app = agent_engines.get(resource_name)

            # Run async warmup
            asyncio.run(self._async_warmup_mcp(remote_app))
            return True

        except Exception as e:
            typer.secho(f" Error warming up MCP servers: {e}", fg=typer.colors.RED)
            return False

    async def _async_warmup_mcp(self, remote_app):
        """Async warmup function that exercises each MCP server."""
        user_id = "warmup_user"
        session = await remote_app.async_create_session(user_id=user_id)

        # Warmup queries - each targets a different MCP server
        # Using lightweight queries to ensure fast warmup
        warmup_queries = [
            (
                "List the first 3 SOAR cases",
                "SOAR MCP",
            ),  # Lightweight - first page of cases
            (
                "Check IP reputation 8.8.8.8",
                "GTI MCP",
            ),  # Single IP lookup (cached after first call)
            (
                "What tools are available in Chronicle SIEM?",
                "Chronicle SIEM MCP",
            ),  # Tool discovery, no data query
        ]

        for query, target_mcp in warmup_queries:
            typer.echo(f"\nWarming up {target_mcp}...")
            typer.echo(f"  Query: {query}")

            try:
                event_count = 0
                async for event in remote_app.async_stream_query(
                    user_id=user_id, session_id=session.get("id"), message=query
                ):
                    event_count += 1
                    # Silently consume events - we just want to trigger MCP connections

                typer.secho(
                    f"  ✓ {target_mcp} warmed up ({event_count} events)",
                    fg=typer.colors.GREEN,
                )
            except Exception as e:
                typer.secho(
                    f"  Warning: {target_mcp} warmup failed: {e}",
                    fg=typer.colors.YELLOW,
                )
                # Continue with other warmup queries even if one fails

        typer.echo("\n" + "=" * 80)
        typer.secho("MCP Pre-Warming Complete", fg=typer.colors.GREEN, bold=True)
        typer.echo("=" * 80)
        typer.echo("Next requests should have reduced cold start latency.")

    def inspect_agent(self, resource_name: str, verbose: bool = False) -> bool:
        """
        Inspect a deployed Agent Engine to see its configuration and service account details.

        Args:
            resource_name: Resource name of the agent to inspect
            verbose: Show additional details including full REST API response

        Returns:
            True if successful, False otherwise
        """
        try:
            typer.echo("\n" + "=" * 80)
            typer.secho("Inspecting Agent Engine", fg=typer.colors.CYAN, bold=True)
            typer.echo("=" * 80 + "\n")

            # Get the agent using agent_engines API
            typer.echo(f"Fetching agent: {resource_name}")
            remote_app = agent_engines.get(resource_name)

            # Display basic information
            typer.secho("\nBasic Information:", fg=typer.colors.YELLOW, bold=True)
            typer.echo(f"Resource Name: {resource_name}")
            if hasattr(remote_app, "display_name"):
                typer.echo(f"Display Name: {remote_app.display_name}")

            # Try to access various attributes
            typer.secho("\nAgent Attributes:", fg=typer.colors.YELLOW, bold=True)
            interesting_attrs = [
                "resource_name",
                "display_name",
                "create_time",
                "update_time",
                "state",
                "spec",
                "deployment_spec",
                "service_account",
            ]

            for attr in interesting_attrs:
                if hasattr(remote_app, attr):
                    try:
                        value = getattr(remote_app, attr)
                        if value is not None and not callable(value):
                            if attr in ["create_time", "update_time"]:
                                typer.echo(f"{attr}: {value}")
                            else:
                                typer.echo(f"{attr}: {value}")
                    except Exception as e:
                        typer.secho(
                            f"{attr}: Error accessing - {e}", fg=typer.colors.RED
                        )

            # Get full REST API response for detailed inspection
            if verbose:
                typer.secho(
                    "\nFetching detailed configuration via REST API...",
                    fg=typer.colors.YELLOW,
                    bold=True,
                )
                try:
                    # Get access token from credentials
                    from google.auth import default
                    from google.auth.transport import requests as auth_requests

                    credentials, _ = default()

                    # Ensure credentials are refreshed
                    if not credentials.valid:
                        request = auth_requests.Request()
                        credentials.refresh(request)

                    access_token = credentials.token

                    # Make REST API call
                    import requests

                    api_url = f"https://{self.location}-aiplatform.googleapis.com/v1/{resource_name}"
                    headers = {
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                    }

                    response = requests.get(api_url, headers=headers)
                    if response.status_code == 200:
                        data = response.json()

                        typer.secho("\nREST API Response:", fg=typer.colors.CYAN)
                        typer.echo(json.dumps(data, indent=2))

                        # Try to extract service account if present
                        if "spec" in data and "serviceAccount" in data.get("spec", {}):
                            typer.secho(
                                f"\nService Account: {data['spec']['serviceAccount']}",
                                fg=typer.colors.GREEN,
                                bold=True,
                            )

                        # Show environment variables if present
                        if "spec" in data:
                            spec = data["spec"]
                            if "deploymentSpec" in spec:
                                deploy_spec = spec["deploymentSpec"]
                                if "env" in deploy_spec:
                                    typer.secho(
                                        "\nEnvironment Variables:",
                                        fg=typer.colors.YELLOW,
                                        bold=True,
                                    )
                                    for env_var in deploy_spec["env"]:
                                        name = env_var.get("name", "")
                                        value = env_var.get("value", "")
                                        # Mask sensitive values
                                        if any(
                                            x in name.upper()
                                            for x in [
                                                "KEY",
                                                "SECRET",
                                                "PASSWORD",
                                                "TOKEN",
                                            ]
                                        ):
                                            value = "*" * 8
                                        typer.echo(f"  {name}: {value}")
                    else:
                        typer.secho(
                            f"\nREST API Error: {response.status_code}",
                            fg=typer.colors.RED,
                        )
                        typer.echo(response.text)

                except Exception as e:
                    typer.secho(
                        f"\nError fetching REST API details: {e}", fg=typer.colors.RED
                    )
                    logging.error(f"REST API error: {e}", exc_info=True)

            # Show recommendations
            typer.secho("\nRecommendations:", fg=typer.colors.YELLOW, bold=True)
            typer.echo(
                "1. Reasoning Engines typically use the Vertex AI service agent:"
            )
            typer.echo(
                f"   service-{self.project.split('/')[-1] if '/' not in self.project else 'PROJECT_NUMBER'}@gcp-sa-aiplatform.iam.gserviceaccount.com"
            )
            typer.echo("2. Or the Compute Engine default service account:")
            typer.echo("   PROJECT_NUMBER-compute@developer.gserviceaccount.com")
            typer.echo(
                "3. Grant necessary permissions to the appropriate service account"
            )

            return True

        except Exception as e:
            typer.secho(f" Error inspecting agent: {e}", fg=typer.colors.RED)
            logging.error(f"Inspection error: {e}", exc_info=True)
            return False

    def inspect_agent_by_index(self, index: int, verbose: bool = False) -> bool:
        """
        Inspect an agent by its index in the list.

        Args:
            index: Index of the agent in the list (1-based)
            verbose: Show additional details

        Returns:
            True if successful, False otherwise
        """
        agents = self.list_agents(verbose=False)

        if not agents:
            return False

        if index < 1 or index > len(agents):
            typer.secho(
                f" Invalid index. Please choose between 1 and {len(agents)}",
                fg=typer.colors.RED,
            )
            return False

        agent = agents[index - 1]
        return self.inspect_agent(agent["resource_name"], verbose)


@app.command()
def list(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed information.")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """List all Agent Engine instances in the project."""
    manager = AgentEngineManager(env_file)
    manager.list_agents(verbose)


@app.command()
def delete(
    resource: Annotated[
        str | None,
        typer.Option(
            "--resource", "-r", help="Full resource name of the agent to delete"
        ),
    ] = None,
    index: Annotated[
        int | None,
        typer.Option(
            "--index", "-i", help="Index of the agent from the list to delete"
        ),
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation prompt")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Delete an Agent Engine instance by resource name or index."""
    if not resource and not index:
        typer.secho(
            " Error: Either --resource or --index must be provided",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    if resource and index:
        typer.secho(
            " Error: Cannot specify both --resource and --index",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    manager = AgentEngineManager(env_file)

    if resource:
        success = manager.delete_agent(resource, force)
    else:  # index
        success = manager.delete_agent_by_index(index, force)

    if not success:
        raise typer.Exit(code=1)


@app.command()
def create(
    agent_module: Annotated[
        str,
        typer.Option(
            "--agent-module",
            "-a",
            help="Agent module to deploy (e.g., 'agent_soc_manager', 'agent_a2a_tier2')",
        ),
    ] = "agent_soc_manager",
    debug: Annotated[
        bool, typer.Option("--debug", help="Enable debug mode with verbose logging")
    ] = False,
    no_test: Annotated[
        bool, typer.Option("--no-test", help="Skip automatic test after creation")
    ] = False,
    description: Annotated[
        str | None,
        typer.Option(
            "--description", "-d", help="Description for the deployed agent engine"
        ),
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Create and deploy a new Agent Engine instance."""
    manager = AgentEngineManager(env_file)
    resource_name = manager.create_agent(agent_module, debug, no_test, description)

    if resource_name:
        typer.echo("\n" + "=" * 80)
        typer.secho("DEPLOYMENT COMPLETE", fg=typer.colors.GREEN, bold=True)
        typer.echo("=" * 80)
        typer.echo("\nSave these values to your .env file:")
        # Determine env var names based on agent module
        if agent_module == "agent_a2a_tier2":
            resource_var = "TIER2_AGENT_RESOURCE_NAME"
            id_var = "TIER2_AGENT_ID"
        else:
            resource_var = "AGENT_ENGINE_RESOURCE_NAME"
            id_var = "AGENT_ENGINE_ID"

        typer.echo(f"{resource_var}={resource_name}")
        # Extract the numeric ID from the resource name
        engine_id = (
            resource_name.split("/")[-1] if "/" in resource_name else resource_name
        )
        typer.echo(f"{id_var}={engine_id}")

        # Write back to .env automatically
        try:
            target_env = manager.env_file
            if target_env.exists():
                set_key(str(target_env), resource_var, resource_name)
                set_key(str(target_env), id_var, engine_id)
                typer.secho(
                    "\n Automatically updated .env with new agent coordinates!",
                    fg=typer.colors.GREEN,
                )
        except Exception as e:
            typer.secho(f"\n Failed to auto-update .env: {e}", fg=typer.colors.YELLOW)

    else:
        raise typer.Exit(code=1)


@app.command()
def update(
    resource_name: Annotated[
        str | None,
        typer.Option(
            "--resource",
            "-r",
            help="Resource name of the agent to update. If not provided, AGENT_ENGINE_RESOURCE_NAME from .env is used.",
        ),
    ] = None,
    agent_module: Annotated[
        str,
        typer.Option(
            "--agent-module",
            "-a",
            help="Agent module to deploy (e.g., 'agent_soc_manager', 'agent_a2a_tier2')",
        ),
    ] = "agent_soc_manager",
    debug: Annotated[
        bool, typer.Option("--debug", help="Enable debug mode with verbose logging")
    ] = False,
    no_test: Annotated[
        bool, typer.Option("--no-test", help="Skip automatic test after update")
    ] = False,
    description: Annotated[
        str | None,
        typer.Option(
            "--description", "-d", help="Description for the deployed agent engine"
        ),
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Update an existing Agent Engine instance in-place."""
    manager = AgentEngineManager(env_file)

    if not resource_name:
        # Determine env var name based on agent module
        if agent_module == "agent_a2a_tier2":
            env_var = "TIER2_AGENT_RESOURCE_NAME"
        else:
            env_var = "AGENT_ENGINE_RESOURCE_NAME"

        resource_name = os.environ.get(env_var)
        if not resource_name:
            typer.secho(
                f"Error: No resource name provided and {env_var} not found in environment.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

    updated_resource = manager.update_agent(
        resource_name, agent_module, debug, no_test, description
    )

    if updated_resource:
        typer.echo("\n" + "=" * 80)
        typer.secho("UPDATE COMPLETE", fg=typer.colors.GREEN, bold=True)
        typer.echo("=" * 80)
    else:
        raise typer.Exit(code=1)


@app.command()
def deploy(
    agent_module: Annotated[
        str,
        typer.Option(
            "--agent-module",
            "-a",
            help="Agent module to deploy (e.g., 'agent_soc_manager', 'agent_a2a_tier2')",
        ),
    ] = "agent_soc_manager",
    debug: Annotated[
        bool, typer.Option("--debug", help="Enable debug mode with verbose logging")
    ] = False,
    no_test: Annotated[
        bool, typer.Option("--no-test", help="Skip automatic test after creation")
    ] = False,
    description: Annotated[
        str | None,
        typer.Option(
            "--description", "-d", help="Description for the deployed agent engine"
        ),
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Intelligently deploy a new Agent Engine instance and cleanup older versions."""
    typer.echo("\n" + "=" * 80)
    typer.secho(
        "Intelligent Deployment (Build & Replace)", fg=typer.colors.MAGENTA, bold=True
    )
    typer.echo("=" * 80 + "\n")

    manager = AgentEngineManager(env_file)

    # Determine what the display name will be so we can find orphans later
    if agent_module == "agent_a2a_tier2":
        display_name = "SecOps Security Agent - Tier 2"
    elif agent_module == "agent_soc_manager":
        display_name = "SecOps Security Agent - Orchestrator"
    else:
        display_name = f"SecOps Security Agent - {agent_module}"

    typer.echo(f"Targeting logic for: {display_name}")

    # Find existing agents
    orphans = manager.get_agents_by_display_name(display_name)
    if orphans:
        typer.secho(
            f"Found {len(orphans)} existing '{display_name}' instances.",
            fg=typer.colors.YELLOW,
        )
    else:
        typer.secho(
            "No existing instances found. Proceeding with fresh build.",
            fg=typer.colors.GREEN,
        )

    # Create the new agent
    typer.echo("\n--- Phase 1: Building New Engine ---")
    resource_name = manager.create_agent(
        agent_module, debug, no_test, description=description
    )

    if resource_name:
        typer.echo("\n--- Phase 2: Updating Environment ---")
        engine_id = (
            resource_name.split("/")[-1] if "/" in resource_name else resource_name
        )

        try:
            # Determine env var names based on agent module
            if agent_module == "agent_a2a_tier2":
                resource_var = "TIER2_AGENT_RESOURCE_NAME"
                id_var = "TIER2_AGENT_ID"
            else:
                resource_var = "AGENT_ENGINE_RESOURCE_NAME"
                id_var = "AGENT_ENGINE_ID"

            target_env = manager.env_file
            if target_env.exists():
                set_key(str(target_env), resource_var, resource_name)
                set_key(str(target_env), id_var, engine_id)
                typer.secho(
                    f"Successfully bound .env to -> {engine_id}", fg=typer.colors.GREEN
                )
        except Exception as e:
            typer.secho(
                f"Warning: Failed to auto-update .env: {e}", fg=typer.colors.YELLOW
            )

        # Cleanup old agents (Vertex + AgentSpace UI)
        if orphans:
            typer.echo("\n--- Phase 3: Garbage Collection ---")
            # 1. Purge Vertex AI containers
            for orphan in orphans:
                if orphan["resource_name"] != resource_name:
                    typer.secho(
                        f"Deleting stale engine: {orphan['resource_name']}",
                        fg=typer.colors.YELLOW,
                    )
                    manager.delete_agent(orphan["resource_name"], force=True)

            # 2. Unlink AgentSpace UI proxies implicitly
            try:
                typer.echo("\n--- Phase 4: Validating Workspace UI Proxies ---")
                ui_manager = AgentSpaceManager(env_file)
                proxy_agents = ui_manager.list_agents(show_raw=False)

                # AgentSpace uses a different display name than Vertex AI natively
                proxy_display_name = ui_manager.env_vars.get(
                    "AGENT_DISPLAY_NAME", "SecOps Security Agent"
                )

                if proxy_agents:
                    for proxy in proxy_agents:
                        # Unlink proxies matching our exact displayName that do NOT match the one we are actively writing
                        if proxy.get("displayName") == proxy_display_name:
                            proxy_id = proxy.get("name", "").split("/")[-1]

                            # Never nuke the active .env proxy!
                            if proxy_id != ui_manager.env_vars.get(
                                "AGENTSPACE_AGENT_ID"
                            ):
                                typer.secho(
                                    f"Unlinking stale Workspace Proxy: {proxy_id}",
                                    fg=typer.colors.YELLOW,
                                )
                                ui_manager.unlink_agent_from_agentspace(
                                    agent_id=proxy_id, force=True
                                )
            except Exception as e:
                typer.secho(
                    f"Warning: Failed to clean AgentSpace workspace proxies implicitly: {e}",
                    fg=typer.colors.YELLOW,
                )

            typer.secho("\n Garbage collection complete!", fg=typer.colors.GREEN)

        typer.echo("\n" + "=" * 80)
        typer.secho("INTELLIGENT DEPLOYMENT COMPLETE", fg=typer.colors.GREEN, bold=True)
        typer.echo("=" * 80)
    else:
        typer.secho(
            "\nDeployment failed during Phase 1. Aborting garbage collection.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)


@app.command()
def test(
    resource: Annotated[
        str | None,
        typer.Option(
            "--resource", "-r", help="Full resource name of the agent to test"
        ),
    ] = None,
    index: Annotated[
        int | None,
        typer.Option("--index", "-i", help="Index of the agent from the list to test"),
    ] = None,
    agent_module: Annotated[
        str,
        typer.Option(
            "--agent-module",
            "-m",
            help="Agent module to test (options: agent_soc_manager, agent_a2a_tier2)",
        ),
    ] = "agent_soc_manager",
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Test an Agent Engine instance with a sample query."""
    if not resource and not index:
        # Try to get from environment based on agent module
        if agent_module == "agent_a2a_tier2":
            env_var = "TIER2_AGENT_RESOURCE_NAME"
        else:
            env_var = "AGENT_ENGINE_RESOURCE_NAME"

        manager = AgentEngineManager(env_file)
        resource = manager.env_vars.get(env_var)
        if not resource:
            typer.secho(
                f" Error: Either --resource, --index, or {env_var} in .env must be provided",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

    if resource and index:
        typer.secho(
            " Error: Cannot specify both --resource and --index",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    manager = AgentEngineManager(env_file)

    if index:
        # Get agent by index
        agents = manager.list_agents(verbose=False)
        if not agents:
            raise typer.Exit(code=1)
        if index < 1 or index > len(agents):
            typer.secho(
                f" Invalid index. Please choose between 1 and {len(agents)}",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)
        resource = agents[index - 1]["resource_name"]

    success = manager.test_agent_with_resource(resource, agent_module=agent_module)
    if not success:
        raise typer.Exit(code=1)


@app.command()
def warmup(
    resource: Annotated[
        str | None,
        typer.Option(
            "--resource", "-r", help="Full resource name of the agent to warm up"
        ),
    ] = None,
    index: Annotated[
        int | None,
        typer.Option(
            "--index", "-i", help="Index of the agent from the list to warm up"
        ),
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Pre-warm MCP server connections to reduce cold start latency."""
    if not resource and not index:
        # Try to get from environment
        manager = AgentEngineManager(env_file)
        resource = manager.env_vars.get("AGENT_ENGINE_RESOURCE_NAME")
        if not resource:
            typer.secho(
                " Error: Either --resource, --index, or AGENT_ENGINE_RESOURCE_NAME in .env must be provided",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

    if resource and index:
        typer.secho(
            " Error: Cannot specify both --resource and --index",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    manager = AgentEngineManager(env_file)

    if index:
        # Get agent by index
        agents = manager.list_agents(verbose=False)
        if not agents:
            raise typer.Exit(code=1)
        if index < 1 or index > len(agents):
            typer.secho(
                f" Invalid index. Please choose between 1 and {len(agents)}",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)
        resource = agents[index - 1]["resource_name"]

    success = manager.warmup_mcp_servers(resource)
    if not success:
        raise typer.Exit(code=1)


@app.command()
def inspect(
    resource: Annotated[
        str | None,
        typer.Option(
            "--resource", "-r", help="Full resource name of the agent to inspect"
        ),
    ] = None,
    index: Annotated[
        int | None,
        typer.Option(
            "--index", "-i", help="Index of the agent from the list to inspect"
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed information including REST API response",
        ),
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Inspect an Agent Engine instance to see its configuration and service account details."""
    if not resource and not index:
        # Try to get from environment
        manager = AgentEngineManager(env_file)
        resource = manager.env_vars.get("AGENT_ENGINE_RESOURCE_NAME")
        if not resource:
            typer.secho(
                " Error: Either --resource, --index, or AGENT_ENGINE_RESOURCE_NAME in .env must be provided",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

    if resource and index:
        typer.secho(
            " Error: Cannot specify both --resource and --index",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    manager = AgentEngineManager(env_file)

    if index:
        success = manager.inspect_agent_by_index(index, verbose)
    else:
        success = manager.inspect_agent(resource, verbose)

    if not success:
        raise typer.Exit(code=1)


@app.command("list-assistants")
def list_assistants(
    engine_id: Annotated[
        str | None,
        typer.Option(
            "--engine",
            "-e",
            help="Engine/App ID to list assistants for. If not provided, lists available engines.",
        ),
    ] = None,
    collection: Annotated[
        str,
        typer.Option(
            "--collection",
            "-c",
            help="Collection ID (default: default_collection)",
        ),
    ] = "default_collection",
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed information.")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """
    List assistants from Discovery Engine/Agent Builder.

    This uses the Google Cloud Generative AI App Builder API to list assistants
    within a specified engine (app). If no engine ID is provided, it will first
    list available engines to help you choose one.

    Example:
        python manage_agent_engine.py list-assistants --engine my-engine-id
    """
    manager = AgentEngineManager(env_file)
    assistants = manager.list_assistants(
        engine_id=engine_id, collection_id=collection, verbose=verbose
    )

    if not assistants and engine_id:
        typer.secho(
            f"\nNo assistants found for engine '{engine_id}'.", fg=typer.colors.YELLOW
        )
        typer.echo("You may need to create assistants first or verify the engine ID.")


@app.command("list-engines")
def list_engines(
    collection: Annotated[
        str,
        typer.Option(
            "--collection",
            "-c",
            help="Collection ID (default: default_collection)",
        ),
    ] = "default_collection",
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """
    List Discovery Engine engines/apps.

    This uses the Google Cloud Discovery Engine API to list all engines (apps)
    within a collection. These engines can contain assistants that can be listed
    using the 'list-assistants' command.

    Example:
        python manage_agent_engine.py list-engines
    """
    manager = AgentEngineManager(env_file)

    if not discoveryengine:
        typer.secho(
            " Discovery Engine client library not installed.", fg=typer.colors.RED
        )
        typer.echo("\nTo install, run:")
        typer.echo("  pip install google-cloud-discoveryengine")
        raise typer.Exit(code=1)

    typer.echo("\n" + "=" * 80)
    typer.secho(
        "Listing Discovery Engine Engines/Apps", fg=typer.colors.BLUE, bold=True
    )
    typer.echo("=" * 80 + "\n")

    engines = manager.list_engines(collection_id=collection)

    if not engines:
        typer.secho(
            "No engines found in the specified collection.", fg=typer.colors.YELLOW
        )
        typer.echo(f"Collection: {collection}")
        typer.echo("\nYou may need to:")
        typer.echo("  1. Create an engine in the Google Cloud Console")
        typer.echo("  2. Verify the collection ID")
        typer.echo("  3. Ensure you have the necessary permissions")
    else:
        typer.echo(
            f"Found {typer.style(str(len(engines)), fg=typer.colors.CYAN)} engine(s):\n"
        )

        for i, engine in enumerate(engines, 1):
            engine_id = engine["name"].split("/")[-1]
            typer.secho(f"{i}. {engine_id}", fg=typer.colors.CYAN)
            typer.echo(f"   Display Name: {engine['display_name']}")
            typer.echo(f"   Solution Type: {engine['solution_type']}")
            typer.echo(f"   Full Name: {engine['name']}")
            if engine["create_time"]:
                typer.echo(f"   Created: {engine['create_time']}")
            typer.echo()

        typer.secho("\nTo list assistants for an engine:", fg=typer.colors.GREEN)
        typer.echo(
            "  python manage_agent_engine.py list-assistants --engine <ENGINE_ID>"
        )


if __name__ == "__main__":
    app()
