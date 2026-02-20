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
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
import vertexai
from dotenv import load_dotenv
from google.api_core import client_options
from google.cloud import aiplatform
from google.cloud.aiplatform_v1beta1 import (
    DeleteReasoningEngineRequest,
    ListReasoningEnginesRequest,
    ReasoningEngineServiceClient,
)
from vertexai import agent_engines
from vertexai.preview.reasoning_engines import AdkApp
from google.adk.memory.vertex_ai_memory_bank_service import VertexAiMemoryBankService


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
        agent_module: str = "soc_agent",
        debug: bool = False,
        no_test: bool = False,
    ) -> str | None:
        """
        Create and deploy a new Agent Engine instance.

        Args:
            agent_module: Name of the agent module to import (default: "soc_agent")
            debug: Enable debug mode with verbose logging
            no_test: Skip the automatic test after creation

        Returns:
            Resource name of the created agent if successful, None otherwise
        """
        typer.echo("\n" + "=" * 80)
        typer.secho("Creating Agent Engine Instance", fg=typer.colors.BLUE, bold=True)
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
            required_vars = [
                "GCP_PROJECT_ID",
                "GCP_LOCATION",
                "GCP_STAGING_BUCKET",
                "CHRONICLE_PROJECT_ID",
                "CHRONICLE_CUSTOMER_ID",
                "CHRONICLE_SERVICE_ACCOUNT_PATH",
                "SOAR_URL",
                "SOAR_API_KEY",
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

            # Copy service account file to where MCP server expects it
            CHRONICLE_SERVICE_ACCOUNT_PATH = os.environ.get(
                "CHRONICLE_SERVICE_ACCOUNT_PATH"
            )
            if CHRONICLE_SERVICE_ACCOUNT_PATH:
                # Validate the service account file path exists and is not a placeholder
                file_error = validate_file_path_exists(
                    "CHRONICLE_SERVICE_ACCOUNT_PATH", CHRONICLE_SERVICE_ACCOUNT_PATH
                )
                if file_error:
                    typer.secho(" Configuration Error", fg=typer.colors.RED, bold=True)
                    typer.echo()
                    typer.echo(format_validation_errors([file_error]))
                    return None

                dest_dir = Path("./mcp-security/server/secops/secops_mcp/")
                dest_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy(CHRONICLE_SERVICE_ACCOUNT_PATH, dest_dir)
                typer.echo("Copied service account file for Chronicle MCP server")
            else:
                raise ValueError("CHRONICLE_SERVICE_ACCOUNT_PATH is not set")

            # Dynamically import and create the agent from the specified module
            typer.echo(f"Importing agent from {agent_module}...")
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

            # Configure memory service builder for NotebookLM-like memory bank
            # This creates a new memory scope for each investigation (session)
            def memory_service_builder():
                # Try to get AGENT_ENGINE_ID from environment (set after deployment)
                agent_engine_id = os.environ.get("AGENT_ENGINE_ID")

                # If not set, check if we can parse it from resource name
                if not agent_engine_id and os.environ.get("AGENT_ENGINE_RESOURCE_NAME"):
                    resource_name = os.environ.get("AGENT_ENGINE_RESOURCE_NAME")
                    agent_engine_id = (
                        resource_name.split("/")[-1]
                        if "/" in resource_name
                        else resource_name
                    )

                return VertexAiMemoryBankService(
                    project=GCP_PROJECT_ID,
                    location=GCP_LOCATION,
                    agent_engine_id=agent_engine_id,
                )

            # Create the ADK app
            typer.echo("Creating ADK app...")
            app = AdkApp(
                agent=agent,
                enable_tracing=True,
                memory_service_builder=memory_service_builder,
            )

            # Resolve AGENT_ENGINE_ID for deployment environment
            agent_engine_id = os.environ.get("AGENT_ENGINE_ID")
            if not agent_engine_id and os.environ.get("AGENT_ENGINE_RESOURCE_NAME"):
                resource_name = os.environ.get("AGENT_ENGINE_RESOURCE_NAME")
                agent_engine_id = (
                    resource_name.split("/")[-1]
                    if "/" in resource_name
                    else resource_name
                )

            # Get environment variables for deployment
            env_vars = {
                "AGENT_ENGINE_ID": agent_engine_id,
                "CHRONICLE_PROJECT_ID": os.environ.get("CHRONICLE_PROJECT_ID"),
                "CHRONICLE_CUSTOMER_ID": os.environ.get("CHRONICLE_CUSTOMER_ID"),
                "CHRONICLE_REGION": os.environ.get("CHRONICLE_REGION", "us"),
                "GOOGLE_GENAI_USE_VERTEXAI": os.environ.get(
                    "GCP_VERTEXAI_ENABLED", "True"
                ),
                "LOCATION": os.environ.get("GCP_LOCATION"),
                "GCP_LOCATION": os.environ.get("GCP_LOCATION"),  # testing
                "PROJECT_ID": os.environ.get("GCP_PROJECT_ID"),
                "GCP_PROJECT_ID": os.environ.get("GCP_PROJECT_ID"),
                "RAG_CORPUS": os.environ.get("RAG_CORPUS_ID"),
                "RAG_CORPUS_ID": os.environ.get("RAG_CORPUS_ID"),  # testing
                "SOAR_URL": os.environ.get("SOAR_URL"),
                "SOAR_APP_KEY": os.environ.get("SOAR_API_KEY"),
                "VT_APIKEY": os.environ.get("GTI_API_KEY"),
            }

            # Check if AGENT_ENGINE_ID is set for memory features
            if not agent_engine_id:
                typer.secho(
                    "\nWarning: AGENT_ENGINE_ID/RESOURCE_NAME not set. Memory features (NotebookLM notebook) will not work until redeployment.",
                    fg=typer.colors.YELLOW,
                )

            # Determine display name based on agent module
            if agent_module == "soc_agent_flash":
                display_name = "SOC Agent - Flash"
            elif agent_module == "soc_agent":
                display_name = "SOC Agent - Pro"
            elif agent_module == "soc_agent_tier1":
                display_name = "SOC Agent - Tier 1 Analyst"
            elif agent_module == "soc_agent_cti":
                display_name = "SOC Agent - CTI Researcher"
            else:
                # For any future agent modules, use the module name as-is
                display_name = f"SOC Agent - {agent_module}"

            # Deploy the agent engine
            typer.echo(f"Deploying agent engine to Vertex AI as '{display_name}'...")
            remote_app = agent_engines.create(
                app,
                display_name=display_name,
                requirements=[
                    "cloudpickle",
                    "google-adk~=1.18.0",
                    "google-cloud-aiplatform[agent-engines]~=1.127.0",
                    "pydantic",
                    "python-dotenv",
                ],
                build_options={
                    "installation_scripts": ["installation_scripts/install.sh"]
                },
                extra_packages=[
                    "mcp-security/server",
                    "installation_scripts/install.sh",  # installs uvx
                ],
                env_vars=env_vars,
            )

            typer.secho("\n Agent deployed successfully!", fg=typer.colors.GREEN)
            typer.echo(f"Resource name: {remote_app.resource_name}")

            # Optionally run test
            if not no_test:
                typer.echo("\nRunning test...")
                self.test_agent_with_resource(remote_app.resource_name)

            return remote_app.resource_name

        except Exception as e:
            typer.secho(f" Error creating agent: {e}", fg=typer.colors.RED)
            import traceback

            typer.echo(traceback.format_exc())
            return None

    def test_agent_with_resource(self, resource_name: str) -> bool:
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
            asyncio.run(self._async_test_agent(remote_app))
            return True

        except Exception as e:
            typer.secho(f" Error testing agent: {e}", fg=typer.colors.RED)
            return False

    async def _async_test_agent(self, remote_app):
        """Async test function for agent engine."""
        user_id = "test_user"
        session = await remote_app.async_create_session(user_id=user_id)
        typer.echo(f"Created session: {session.get('id')}")

        events = []
        test_message = (
            "Search RAG Corpus for Malware IRP runbook and get the objective."
        )
        # test_message = "List rules with ursnif in the name."
        # test_message = "List the first page of soar cases."

        typer.echo(f"Sending test query: {test_message}")
        async for event in remote_app.async_stream_query(
            user_id=user_id, session_id=session.get("id"), message=test_message
        ):
            typer.echo(f"Event: {event}")
            events.append(event)

        if not events:
            typer.secho(" No events received from agent!", fg=typer.colors.YELLOW)
        else:
            typer.secho(
                f" Test completed successfully - received {len(events)} events",
                fg=typer.colors.GREEN,
            )

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
            help="Agent module to deploy (e.g., 'soc_agent', 'soc_agent_flash')",
        ),
    ] = "soc_agent",
    debug: Annotated[
        bool, typer.Option("--debug", help="Enable debug mode with verbose logging")
    ] = False,
    no_test: Annotated[
        bool, typer.Option("--no-test", help="Skip automatic test after creation")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Create and deploy a new Agent Engine instance."""
    manager = AgentEngineManager(env_file)
    resource_name = manager.create_agent(agent_module, debug, no_test)

    if resource_name:
        typer.echo("\n" + "=" * 80)
        typer.secho("DEPLOYMENT COMPLETE", fg=typer.colors.GREEN, bold=True)
        typer.echo("=" * 80)
        typer.echo("\nSave these values to your .env file:")
        typer.echo(f"AGENT_ENGINE_RESOURCE_NAME={resource_name}")
        # Extract the numeric ID from the resource name
        engine_id = (
            resource_name.split("/")[-1] if "/" in resource_name else resource_name
        )
        typer.echo(f"AGENT_ENGINE_ID={engine_id}")
    else:
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
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Test an Agent Engine instance with a sample query."""
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

    success = manager.test_agent_with_resource(resource)
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
