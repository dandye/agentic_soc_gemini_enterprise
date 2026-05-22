#!/usr/bin/env python3
"""
Memory Bank Manager for Google Vertex AI Agent Engine

This script manages Agent Engine memories including listing, retrieving,
and getting specific memories in Vertex AI.

References

 1. https://docs.cloud.google.com/agent-builder/agent-engine/memory-bank/overview
 2. https://docs.cloud.google.com/agent-builder/agent-engine/memory-bank/quickstart-api
 3. https://docs.cloud.google.com/agent-builder/agent-engine/memory-bank/quickstart-adk
 4. https://docs.cloud.google.com/agent-builder/agent-engine/memory-bank/fetch-memories
 5. https://docs.cloud.google.com/agent-builder/agent-engine/memory-bank/generate-memories#memory-topics

"""

import os
from pathlib import Path
from typing import Annotated

import typer
import vertexai
from dotenv import load_dotenv

from management_scripts.manage_agent_engine import AgentEngineManager


app = typer.Typer(
    add_completion=False,
    help="Manage Memory Bank for Agent Engine instances in Vertex AI.",
)

# Debug mode configuration
DEBUG = os.environ.get("DEBUG", "False") == "True"


class MemoryManager:
    """Manages Memory Bank operations in Vertex AI."""

    def __init__(self, env_file: Path):
        """
        Initialize the Memory manager.

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
        return dict(os.environ)

    def _initialize_vertex_ai(self) -> None:
        """Initialize the Vertex AI SDK."""
        self.project = self.env_vars.get("GCP_PROJECT_ID")
        self.location = self.env_vars.get("GCP_LOCATION", "us-central1")
        self.staging_bucket = self.env_vars.get("GCP_STAGING_BUCKET")

        if not self.project:
            typer.secho("Error: GCP_PROJECT_ID not set in .env", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        try:
            # For memories API, we MUST use application-default credentials, not API keys
            # If an API key is in the environment, temporarily remove it to force ADC
            api_key = os.environ.pop("GEMINI_API_KEY", None)

            vertexai.init(
                project=self.project,
                location=self.location,
                staging_bucket=self.staging_bucket,
            )

            if api_key:
                os.environ["GEMINI_API_KEY"] = api_key

        except Exception as e:
            typer.secho(f"Failed to initialize Vertex AI: {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    def _get_agent_engine_id(self, resource_name_or_index: str) -> str:
        """Resolve either a resource name or an index to a full resource name."""
        if not resource_name_or_index:
            # Fall back to env variable
            resource_name_or_index = self.env_vars.get("AGENT_ENGINE_RESOURCE_NAME")
            if not resource_name_or_index:
                typer.secho(
                    "Error: No resource name or index provided, and AGENT_ENGINE_RESOURCE_NAME is not set in .env.",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)

        if resource_name_or_index.isdigit():
            # Treat as index
            manager = AgentEngineManager(self.env_file)
            agents = manager.list_agents(verbose=False)
            index = int(resource_name_or_index)
            if index < 1 or index > len(agents):
                typer.secho(
                    f"Invalid index. Please choose between 1 and {len(agents)}",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)
            return agents[index - 1]["resource_name"]

        # If it doesn't look like a full resource name, construct it
        if not resource_name_or_index.startswith("projects/"):
            return f"projects/{self.project}/locations/{self.location}/reasoningEngines/{resource_name_or_index}"

        return resource_name_or_index

    def retrieve(
        self,
        engine: str,
        user_id: str,
        app_name: str,
        query: str | None = None,
        top_k: int = 3,
        filter_str: str | None = None,
    ) -> None:
        """Retrieve memories within a specific scope."""
        engine_name = self._get_agent_engine_id(engine)

        # Extract location from the resource name to initialize client properly
        parts = engine_name.split("/")
        location = "us-central1"
        if len(parts) >= 4 and parts[2] == "locations":
            location = parts[3]

        # Temporarily strip API key to force OAuth credentials
        api_key = os.environ.pop("GEMINI_API_KEY", None)

        # We must explicitly set the API endpoint to match the location
        # or it will default to us-central1 and fail for multi-region engines
        api_endpoint = f"{location}-aiplatform.googleapis.com"

        vertexai.init(
            project=self.project,
            location=location,
            staging_bucket=self.staging_bucket,
            api_endpoint=api_endpoint,
        )
        client = vertexai.Client(project=self.project, location=location)
        if api_key:
            os.environ["GEMINI_API_KEY"] = api_key

        scope = {
            "user_id": user_id,
            "app_name": app_name,
        }

        try:
            kwargs = {
                "name": engine_name,
                "scope": scope,
            }

            if query:
                kwargs["similarity_search_params"] = {
                    "search_query": query,
                    "top_k": top_k,
                }

            if filter_str:
                kwargs["config"] = {"filter": filter_str}

            typer.secho(
                f"Retrieving memories for scope {scope}...", fg=typer.colors.BLUE
            )
            results = client.agent_engines.memories.retrieve(**kwargs)

            memories = list(results)
            if not memories:
                typer.secho("No memories found.", fg=typer.colors.YELLOW)
                return

            for idx, retrieved_memory in enumerate(memories, 1):
                memory = retrieved_memory.memory
                typer.echo("-" * 40)
                typer.secho(f"Result {idx}", fg=typer.colors.GREEN, bold=True)
                typer.echo(f"ID: {memory.name}")
                typer.echo(f"Fact: {memory.fact}")
                if memory.topics:
                    topics = []
                    for t in memory.topics:
                        if getattr(t, "custom_memory_topic_label", None):
                            topics.append(t.custom_memory_topic_label)
                        elif getattr(t, "custom_memory_topic", None) and getattr(
                            t.custom_memory_topic, "label", None
                        ):
                            topics.append(t.custom_memory_topic.label)
                        elif getattr(t, "managed_memory_topic", None) and getattr(
                            t.managed_memory_topic, "managed_topic_enum", None
                        ):
                            topics.append(
                                t.managed_memory_topic.managed_topic_enum.name
                            )
                        elif getattr(t, "managed_topic_enum", None):
                            enum_val = str(t.managed_topic_enum)
                            # Handle <ManagedTopicEnum.EXPLICIT_INSTRUCTIONS: 'EXPLICIT_INSTRUCTIONS'>
                            if "ManagedTopicEnum." in enum_val:
                                topics.append(
                                    enum_val.split("'")[1]
                                    if "'" in enum_val
                                    else enum_val.split(".")[-1].split(":")[0]
                                )
                            else:
                                topics.append(enum_val)
                        elif str(t).startswith("custom_memory_topic_label="):
                            # Handle direct string representation of the object
                            topic_str = str(t)
                            if "managed_memory_topic=<ManagedTopicEnum." in topic_str:
                                try:
                                    enum_part = topic_str.split("<ManagedTopicEnum.")[
                                        1
                                    ].split(":")[0]
                                    topics.append(enum_part)
                                except IndexError:
                                    topics.append(topic_str)
                            else:
                                topics.append(topic_str)
                        elif isinstance(t, dict):
                            if t.get("custom_memory_topic_label"):
                                topics.append(t["custom_memory_topic_label"])
                            elif t.get("managed_memory_topic"):
                                topics.append(str(t["managed_memory_topic"]))
                            elif t.get("custom_memory_topic"):
                                topics.append(str(t["custom_memory_topic"]))
                            else:
                                topics.append(str(t))
                        elif hasattr(t, "id") and t.id:
                            topics.append(str(t.id))
                        else:
                            topics.append(str(t))
                    typer.echo(f"Topics: {', '.join(topics)}")
                if retrieved_memory.similarity_score:
                    typer.echo(f"Similarity Score: {retrieved_memory.similarity_score}")

        except Exception as e:
            typer.secho(f"Error retrieving memories: {e}", fg=typer.colors.RED)
            if DEBUG:
                import traceback

                typer.echo(traceback.format_exc())

    def list_all(
        self,
        engine: str,
        filter_str: str | None = None,
    ) -> None:
        """List all memories for an Agent Engine."""
        engine_name = self._get_agent_engine_id(engine)

        # Extract location from the resource name to initialize client properly
        parts = engine_name.split("/")
        location = "us-central1"
        if len(parts) >= 4 and parts[2] == "locations":
            location = parts[3]

        # Temporarily strip API key to force OAuth credentials
        api_key = os.environ.pop("GEMINI_API_KEY", None)

        # We must explicitly set the API endpoint to match the location
        # or it will default to us-central1 and fail for multi-region engines
        api_endpoint = f"{location}-aiplatform.googleapis.com"

        vertexai.init(
            project=self.project,
            location=location,
            staging_bucket=self.staging_bucket,
            api_endpoint=api_endpoint,
        )
        client = vertexai.Client(project=self.project, location=location)
        if api_key:
            os.environ["GEMINI_API_KEY"] = api_key

        try:
            kwargs = {"name": engine_name}
            if filter_str:
                kwargs["config"] = {"filter": filter_str}

            typer.secho(
                f"Listing memories for engine {engine_name}...", fg=typer.colors.BLUE
            )
            results = client.agent_engines.memories.list(**kwargs)

            count = 0
            for memory in results:
                count += 1
                typer.echo("-" * 40)
                typer.echo(f"ID: {memory.name}")
                typer.echo(f"Fact: {memory.fact}")
                typer.echo(f"Scope: {memory.scope}")
                if memory.topics:
                    topics = []
                    for t in memory.topics:
                        if getattr(t, "custom_memory_topic_label", None):
                            topics.append(t.custom_memory_topic_label)
                        elif getattr(t, "custom_memory_topic", None) and getattr(
                            t.custom_memory_topic, "label", None
                        ):
                            topics.append(t.custom_memory_topic.label)
                        elif getattr(t, "managed_memory_topic", None) and getattr(
                            t.managed_memory_topic, "managed_topic_enum", None
                        ):
                            topics.append(
                                t.managed_memory_topic.managed_topic_enum.name
                            )
                        elif getattr(t, "managed_topic_enum", None):
                            enum_val = str(t.managed_topic_enum)
                            # Handle <ManagedTopicEnum.EXPLICIT_INSTRUCTIONS: 'EXPLICIT_INSTRUCTIONS'>
                            if "ManagedTopicEnum." in enum_val:
                                topics.append(
                                    enum_val.split("'")[1]
                                    if "'" in enum_val
                                    else enum_val.split(".")[-1].split(":")[0]
                                )
                            else:
                                topics.append(enum_val)
                        elif str(t).startswith("custom_memory_topic_label="):
                            # Handle direct string representation of the object
                            topic_str = str(t)
                            if "managed_memory_topic=<ManagedTopicEnum." in topic_str:
                                try:
                                    enum_part = topic_str.split("<ManagedTopicEnum.")[
                                        1
                                    ].split(":")[0]
                                    topics.append(enum_part)
                                except IndexError:
                                    topics.append(topic_str)
                            else:
                                topics.append(topic_str)
                        elif isinstance(t, dict):
                            if t.get("custom_memory_topic_label"):
                                topics.append(t["custom_memory_topic_label"])
                            elif t.get("managed_memory_topic"):
                                topics.append(str(t["managed_memory_topic"]))
                            elif t.get("custom_memory_topic"):
                                topics.append(str(t["custom_memory_topic"]))
                            else:
                                topics.append(str(t))
                        elif hasattr(t, "id") and t.id:
                            topics.append(str(t.id))
                        else:
                            topics.append(str(t))
                    typer.echo(f"Topics: {', '.join(topics)}")

            if count == 0:
                typer.secho("No memories found.", fg=typer.colors.YELLOW)
            else:
                typer.secho(f"\nTotal memories: {count}", fg=typer.colors.GREEN)

        except Exception as e:
            typer.secho(f"Error listing memories: {e}", fg=typer.colors.RED)
            if DEBUG:
                import traceback

                typer.echo(traceback.format_exc())

    def get(self, memory_id: str) -> None:
        """Get a specific memory by its full resource name."""

        if not memory_id.startswith("projects/"):
            typer.secho(
                "Error: memory_id must be the full resource name (e.g., projects/.../memories/...).",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

        # Extract location from the resource name to initialize client properly
        parts = memory_id.split("/")
        location = "us-central1"
        if len(parts) >= 4 and parts[2] == "locations":
            location = parts[3]

        # Temporarily strip API key to force OAuth credentials
        api_key = os.environ.pop("GEMINI_API_KEY", None)

        # We must explicitly set the API endpoint to match the location
        # or it will default to us-central1 and fail for multi-region engines
        api_endpoint = f"{location}-aiplatform.googleapis.com"

        vertexai.init(
            project=self.project,
            location=location,
            staging_bucket=self.staging_bucket,
            api_endpoint=api_endpoint,
        )
        client = vertexai.Client(project=self.project, location=location)
        if api_key:
            os.environ["GEMINI_API_KEY"] = api_key

        try:
            typer.secho(f"Fetching memory {memory_id}...", fg=typer.colors.BLUE)
            memory = client.agent_engines.memories.get(name=memory_id)

            typer.echo("-" * 40)
            typer.echo(f"ID: {memory.name}")
            typer.echo(f"Fact: {memory.fact}")
            typer.echo(f"Scope: {memory.scope}")
            if memory.topics:
                topics = []
                for t in memory.topics:
                    if getattr(t, "custom_memory_topic_label", None):
                        topics.append(t.custom_memory_topic_label)
                    elif getattr(t, "custom_memory_topic", None) and getattr(
                        t.custom_memory_topic, "label", None
                    ):
                        topics.append(t.custom_memory_topic.label)
                    elif getattr(t, "managed_memory_topic", None) and getattr(
                        t.managed_memory_topic, "managed_topic_enum", None
                    ):
                        topics.append(t.managed_memory_topic.managed_topic_enum.name)
                    elif getattr(t, "managed_topic_enum", None):
                        enum_val = str(t.managed_topic_enum)
                        if "ManagedTopicEnum." in enum_val:
                            topics.append(
                                enum_val.split("'")[1]
                                if "'" in enum_val
                                else enum_val.split(".")[-1].split(":")[0]
                            )
                        else:
                            topics.append(enum_val)
                    elif str(t).startswith("custom_memory_topic_label="):
                        topic_str = str(t)
                        if "managed_memory_topic=<ManagedTopicEnum." in topic_str:
                            try:
                                enum_part = topic_str.split("<ManagedTopicEnum.")[
                                    1
                                ].split(":")[0]
                                topics.append(enum_part)
                            except IndexError:
                                topics.append(topic_str)
                        else:
                            topics.append(topic_str)
                    elif isinstance(t, dict):
                        if t.get("custom_memory_topic_label"):
                            topics.append(t["custom_memory_topic_label"])
                        elif t.get("managed_memory_topic"):
                            topics.append(str(t["managed_memory_topic"]))
                        elif t.get("custom_memory_topic"):
                            topics.append(str(t["custom_memory_topic"]))
                        else:
                            topics.append(str(t))
                    elif hasattr(t, "id") and t.id:
                        topics.append(str(t.id))
                    else:
                        topics.append(str(t))
                typer.echo(f"Topics: {', '.join(topics)}")
            typer.echo(f"Create Time: {memory.create_time}")
            typer.echo(f"Update Time: {memory.update_time}")

            if hasattr(memory, "metadata") and memory.metadata:
                typer.echo("Metadata:")
                for k, v in memory.metadata.items():
                    val_str = str(v)
                    # Simple extraction for common MemoryMetadataValue types
                    if "string_value=" in val_str:
                        try:
                            clean_val = (
                                val_str.split("string_value=")[1]
                                .strip()
                                .strip("'")
                                .strip('"')
                            )
                            typer.echo(f"  {k}: {clean_val}")
                        except Exception:
                            typer.echo(f"  {k}: {val_str}")
                    elif "int_value=" in val_str:
                        try:
                            clean_val = val_str.split("int_value=")[1].strip()
                            typer.echo(f"  {k}: {clean_val}")
                        except Exception:
                            typer.echo(f"  {k}: {val_str}")
                    else:
                        typer.echo(f"  {k}: {val_str}")

        except Exception as e:
            typer.secho(f"Error fetching memory: {e}", fg=typer.colors.RED)
            if DEBUG:
                import traceback

                typer.echo(traceback.format_exc())

    def create(
        self,
        engine: str,
        fact: str,
        user_id: str,
        app_name: str,
        topic: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        """Create a new memory manually."""
        engine_name = self._get_agent_engine_id(engine)

        # Extract location from the resource name to initialize client properly
        parts = engine_name.split("/")
        location = "us-central1"
        if len(parts) >= 4 and parts[2] == "locations":
            location = parts[3]

        # Temporarily strip API key to force OAuth credentials
        api_key = os.environ.pop("GEMINI_API_KEY", None)

        # We must explicitly set the API endpoint to match the location
        # or it will default to us-central1 and fail for multi-region engines
        api_endpoint = f"{location}-aiplatform.googleapis.com"

        vertexai.init(
            project=self.project,
            location=location,
            staging_bucket=self.staging_bucket,
            api_endpoint=api_endpoint,
        )
        client = vertexai.Client(project=self.project, location=location)
        if api_key:
            os.environ["GEMINI_API_KEY"] = api_key

        scope = {
            "user_id": user_id,
            "app_name": app_name,
        }

        # Build config with topics and metadata
        config = {}
        if topic:
            # Check if it's a known managed topic or treat as custom label
            managed_topics = [
                "USER_PERSONAL_INFO",
                "USER_PREFERENCES",
                "KEY_CONVERSATION_DETAILS",
                "EXPLICIT_INSTRUCTIONS",
            ]
            if topic.upper() in managed_topics:
                config["topics"] = [{"managed_topic_enum": topic.upper()}]
            else:
                config["topics"] = [{"custom_memory_topic_label": topic}]

        if metadata:
            config["metadata"] = metadata

        try:
            typer.secho(
                f"Creating memory for scope {scope} in engine {engine_name}...",
                fg=typer.colors.BLUE,
            )
            operation = client.agent_engines.memories.create(
                name=engine_name, fact=fact, scope=scope, config=config
            )

            # Wait for completion
            if hasattr(operation, "result"):
                memory = operation.result()
            else:
                memory = operation

            typer.secho("Memory created successfully!", fg=typer.colors.GREEN)

            # The returned object might be an operation or a memory depending on SDK version
            # Let's handle both gracefully for printing
            if hasattr(memory, "name"):
                typer.echo(f"ID: {memory.name}")
            if hasattr(memory, "fact"):
                typer.echo(f"Fact: {memory.fact}")

        except Exception as e:
            typer.secho(f"Error creating memory: {e}", fg=typer.colors.RED)
            if DEBUG:
                import traceback

                typer.echo(traceback.format_exc())


@app.command()
def retrieve(
    engine: Annotated[
        str | None,
        typer.Option(
            "--engine",
            "-e",
            help="Agent Engine ID or resource name. Defaults to AGENT_ENGINE_RESOURCE_NAME in .env",
        ),
    ] = None,
    user_id: Annotated[
        str,
        typer.Option(
            "--user",
            "-u",
            help="User ID scope to retrieve for (e.g., 'global_soc_team')",
        ),
    ] = "global_soc_team",
    app_name: Annotated[
        str | None,
        typer.Option(
            "--app",
            "-a",
            help="App name scope. Defaults to AGENTSPACE_APP_ID in .env or 'secops_agent'",
        ),
    ] = None,
    query: Annotated[
        str | None,
        typer.Option("--query", "-q", help="Search query for similarity search."),
    ] = None,
    top_k: Annotated[
        int,
        typer.Option(
            "--top-k", "-k", help="Number of results to return for similarity search."
        ),
    ] = 3,
    filter_str: Annotated[
        str | None,
        typer.Option(
            "--filter", "-f", help="EBNF filter string (e.g., 'fact=~\".*error.*\"')."
        ),
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Retrieve memories matching a specific scope and optional similarity search query."""
    manager = MemoryManager(env_file)

    if not app_name:
        app_name = manager.env_vars.get("AGENTSPACE_APP_ID", "secops_agent")

    manager.retrieve(
        engine=engine,
        user_id=user_id,
        app_name=app_name,
        query=query,
        top_k=top_k,
        filter_str=filter_str,
    )


@app.command()
def list_all(
    engine: Annotated[
        str | None,
        typer.Option(
            "--engine",
            "-e",
            help="Agent Engine ID or resource name. Defaults to AGENT_ENGINE_RESOURCE_NAME in .env",
        ),
    ] = None,
    filter_str: Annotated[
        str | None, typer.Option("--filter", "-f", help="EBNF filter string.")
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """List all memories for an Agent Engine."""
    manager = MemoryManager(env_file)
    manager.list_all(engine=engine, filter_str=filter_str)


@app.command()
def get(
    memory_id: Annotated[
        str,
        typer.Argument(help="The full resource name of the memory to fetch."),
    ],
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Get a specific memory by its ID (full resource name)."""
    manager = MemoryManager(env_file)
    manager.get(memory_id)


@app.command()
def create(
    fact: Annotated[str, typer.Option("--content", "-c", help="The fact to remember.")],
    topic: Annotated[
        str | None,
        typer.Option("--topic", "-t", help="The topic label for this memory."),
    ] = None,
    engine: Annotated[
        str | None,
        typer.Option(
            "--engine",
            "-e",
            help="Agent Engine ID or resource name. Defaults to AGENT_ENGINE_RESOURCE_NAME in .env",
        ),
    ] = None,
    user_id: Annotated[
        str,
        typer.Option(
            "--user", "-u", help="User ID scope to create for (e.g., 'global_soc_team')"
        ),
    ] = "global_soc_team",
    app_name: Annotated[
        str | None,
        typer.Option(
            "--app",
            "-a",
            help="App name scope. Defaults to AGENTSPACE_APP_ID in .env or 'secops_agent'",
        ),
    ] = None,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Create a new memory manually with a specific topic."""
    manager = MemoryManager(env_file)

    if not app_name:
        app_name = manager.env_vars.get("AGENTSPACE_APP_ID", "secops_agent")

    manager.create(
        engine=engine,
        fact=fact,
        user_id=user_id,
        app_name=app_name,
        topic=topic,
    )


if __name__ == "__main__":
    app()
