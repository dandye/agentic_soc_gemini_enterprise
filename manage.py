#!/usr/bin/env python3
"""
Unified CLI for Agentic SOC Gemini Enterprise Agent Platform Management

This script provides a unified interface to manage all components of the
Agentic SOC Gemini Enterprise Agent Platform system including agent engines, Gemini Enterprise Agent Platform apps,
OAuth authorizations, data stores, and RAG corpora.
"""

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console


# Import management apps from installation_scripts
sys.path.insert(0, str(Path(__file__).parent / "installation_scripts"))

from installation_scripts.harvest_investigations import app as harvest_app
from installation_scripts.manage_agent_engine import app as agent_engine_app
from installation_scripts.manage_agentspace import app as agentspace_app
from installation_scripts.manage_alloydb import app as alloydb_app
from installation_scripts.manage_chat_ops import app as chatops_app
from installation_scripts.manage_datastore import app as datastore_app
from installation_scripts.manage_elasticsearch import app as elastic_app
from installation_scripts.manage_eval import app as eval_app
from installation_scripts.manage_iam import app as iam_app
from installation_scripts.manage_licenses import app as licenses_app
from installation_scripts.manage_memories import app as memories_app
from installation_scripts.manage_models import app as models_app
from installation_scripts.manage_neo4j import app as neo4j_app
from installation_scripts.manage_oauth import app as oauth_app
from installation_scripts.manage_rag import app as rag_app
from installation_scripts.manage_secret import app as secret_app
from installation_scripts.manage_vertex_ai import app as vertex_app


console = Console()

# Create main app
app = typer.Typer(
    name="manage",
    help="Unified management interface for Agentic SOC Gemini Enterprise Agent Platform",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

# Mount existing management apps as subcommands
app.add_typer(
    agent_engine_app, name="agent-engine", help="Manage Agent Engine instances"
)
app.add_typer(
    agentspace_app,
    name="agentspace",
    help="Manage Gemini Enterprise Agent Platform apps and agents",
)
app.add_typer(oauth_app, name="oauth", help="Manage OAuth authorizations")
app.add_typer(secret_app, name="secret", help="Manage Secret Manager keys")
app.add_typer(datastore_app, name="datastore", help="Manage data stores")
app.add_typer(rag_app, name="rag", help="Manage RAG corpora")
app.add_typer(memories_app, name="memories", help="Manage Agent Engine memories")
app.add_typer(iam_app, name="iam", help="Manage IAM permissions for service accounts")
app.add_typer(
    vertex_app,
    name="vertex",
    help="Verify and manage Gemini Enterprise Agent Platform setup",
)
app.add_typer(
    chatops_app, name="chatops", help="Manage and test ChatOps cards and functions"
)
app.add_typer(
    models_app, name="models", help="List and discover available Gemini models"
)
app.add_typer(elastic_app, name="elastic", help="Manage Elasticsearch runbook index")
app.add_typer(eval_app, name="eval", help="Run agent evaluations")
app.add_typer(
    harvest_app,
    name="harvest",
    help="Harvest and enrich investigations and detections from Chronicle SIEM",
)
app.add_typer(neo4j_app, name="neo4j", help="Manage Neo4j Graph Database")
app.add_typer(
    alloydb_app, name="alloydb", help="Manage AlloyDB detection reports database"
)
app.add_typer(
    licenses_app, name="licenses", help="Manage Gemini Enterprise user licenses"
)


# Workflow subcommand group
workflow_app = typer.Typer(
    help="Composite workflows and multi-step operations",
    no_args_is_help=True,
)
app.add_typer(workflow_app, name="workflow")


@workflow_app.command("full-deploy")
def full_deploy(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """
    Complete deployment workflow with OAuth.

    This workflow:
    1. Deploys the agent engine (requires main.py)
    2. Creates OAuth authorization
    3. Links agent to Gemini Enterprise Agent Platform
    """
    console.print("\n[bold blue]Starting full deployment workflow...[/bold blue]\n")

    # Step 1: Deploy agent engine
    console.print("[yellow]Step 1: Deploy Agent Engine[/yellow]")
    console.print("Please run: [cyan]python main.py[/cyan]")
    console.print("Then save the AGENT_ENGINE_RESOURCE_NAME to your .env file\n")

    if not typer.confirm("Have you deployed the agent engine?"):
        console.print(
            "[red]Deployment cancelled. Please deploy the agent engine first.[/red]"
        )
        raise typer.Exit(code=1)

    # Step 2: Create OAuth authorization
    console.print("\n[yellow]Step 2: Create OAuth Authorization[/yellow]")
    from installation_scripts.manage_oauth import OAuthManager

    oauth_manager = OAuthManager(env_file)

    # Check if OAuth is already configured
    if not oauth_manager.env_vars.get("OAUTH_CLIENT_ID"):
        console.print(
            "[red]OAuth not configured. Please run:[/red] [cyan]python manage.py oauth setup <client_secret.json>[/cyan]"
        )
        raise typer.Exit(code=1)

    # Create OAuth authorization
    import uuid

    auth_id = oauth_manager.env_vars.get("OAUTH_AUTH_ID")
    if not auth_id:
        auth_id = f"auth-{uuid.uuid4().hex[:8]}"

    client_id = oauth_manager.env_vars.get("OAUTH_CLIENT_ID")
    client_secret = oauth_manager.env_vars.get("OAUTH_CLIENT_SECRET")
    auth_uri = oauth_manager.env_vars.get("OAUTH_AUTH_URI")
    token_uri = oauth_manager.env_vars.get(
        "OAUTH_TOKEN_URI", "https://oauth2.googleapis.com/token"
    )

    if oauth_manager.create_authorization(
        auth_id, client_id, client_secret, auth_uri, token_uri
    ):
        console.print(f"[green]OAuth authorization created: {auth_id}[/green]")
    else:
        console.print("[red]Failed to create OAuth authorization[/red]")
        raise typer.Exit(code=1)

    # Step 3: Link agent to Gemini Enterprise Agent Platform
    console.print(
        "\n[yellow]Step 3: Link Agent to Gemini Enterprise Agent Platform[/yellow]"
    )
    from installation_scripts.manage_agentspace import AgentSpaceManager

    as_manager = AgentSpaceManager(env_file)
    if as_manager.link_agent_to_agentspace():
        console.print(
            "[green]Agent linked to Gemini Enterprise Agent Platform successfully![/green]"
        )
    else:
        console.print(
            "[red]Failed to link agent to Gemini Enterprise Agent Platform[/red]"
        )
        raise typer.Exit(code=1)

    console.print(
        "\n[bold green]Full deployment workflow completed successfully![/bold green]"
    )


@workflow_app.command("redeploy-all")
def redeploy_all(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """
    Redeploy agent engine and update Gemini Enterprise Agent Platform configuration.

    This workflow:
    1. Redeploys the agent engine (requires main.py)
    2. Updates Gemini Enterprise Agent Platform agent configuration
    """
    console.print("\n[bold blue]Starting full redeployment...[/bold blue]\n")

    # Step 1: Redeploy agent engine
    console.print("[yellow]Step 1: Redeploy Agent Engine[/yellow]")
    console.print("Please run: [cyan]python main.py[/cyan]")
    console.print("Then update the AGENT_ENGINE_RESOURCE_NAME in your .env file\n")

    if not typer.confirm("Have you redeployed the agent engine?"):
        console.print("[red]Redeployment cancelled.[/red]")
        raise typer.Exit(code=1)

    # Step 2: Update Gemini Enterprise Agent Platform
    console.print(
        "\n[yellow]Step 2: Update Gemini Enterprise Agent Platform Configuration[/yellow]"
    )
    from installation_scripts.manage_agentspace import AgentSpaceManager

    manager = AgentSpaceManager(env_file)
    if manager.update_agent():
        console.print(
            "[green]Gemini Enterprise Agent Platform updated successfully![/green]"
        )
    else:
        console.print("[red]Failed to update Gemini Enterprise Agent Platform[/red]")
        raise typer.Exit(code=1)

    console.print(
        "\n[bold green]Full redeployment completed successfully![/bold green]"
    )


@workflow_app.command("status")
def status(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """
    Check the status of the entire system.

    Displays information about:
    - Agent Engine deployment
    - Gemini Enterprise Agent Platform registration
    - OAuth configuration
    - Data stores
    - RAG corpora
    """
    console.print("\n[bold blue]System Status Check[/bold blue]\n")

    from installation_scripts.manage_agentspace import AgentSpaceManager

    manager = AgentSpaceManager(env_file)

    # Check environment variables
    console.print("[yellow]Environment Configuration:[/yellow]")
    env_vars_to_check = [
        "GCP_PROJECT_ID",
        "GCP_PROJECT_NUMBER",
        "GCP_LOCATION",
        "AGENT_ENGINE_RESOURCE_NAME",
        "AGENTSPACE_APP_ID",
        "AGENTSPACE_AGENT_ID",
        "OAUTH_AUTH_ID",
        "RAG_CORPUS_ID",
    ]

    for var in env_vars_to_check:
        value = manager.env_vars.get(var)
        if value:
            # Truncate long values
            display_value = value if len(value) < 60 else f"{value[:60]}..."
            console.print(f"  {var}: [green]{display_value}[/green]")
        else:
            console.print(f"  {var}: [red]Not set[/red]")

    # Verify Gemini Enterprise Agent Platform
    console.print("\n[yellow]Gemini Enterprise Agent Platform Status:[/yellow]")
    if manager.verify_agent():
        console.print(
            "  [green]Gemini Enterprise Agent Platform agent is verified and active[/green]"
        )
    else:
        console.print(
            "  [red]Gemini Enterprise Agent Platform agent verification failed[/red]"
        )

    console.print()


@app.command()
def setup(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """
    Set up the environment and install dependencies.

    Creates .env file from template if it doesn't exist and checks dependencies.
    """
    console.print("\n[bold blue]Setting up environment...[/bold blue]\n")

    # Check if .env exists
    if not env_file.exists():
        env_example = Path(".env.example")
        if env_example.exists():
            import shutil

            shutil.copy(env_example, env_file)
            console.print(f"[green]Created {env_file} from template[/green]")
            console.print(
                f"[yellow]Please edit {env_file} with your configuration[/yellow]"
            )
        else:
            console.print(
                f"[yellow]No .env.example found. Please create {env_file} manually[/yellow]"
            )
    else:
        console.print(f"[green]{env_file} already exists[/green]")

    # Check Python dependencies
    console.print("\n[yellow]Checking Python dependencies...[/yellow]")
    try:
        import google.adk  # noqa: F401
        import google.auth  # noqa: F401
        import vertexai  # noqa: F401
        from dotenv import load_dotenv  # noqa: F401

        console.print("[green]All required packages are installed[/green]")
    except ImportError as e:
        console.print(f"[red]Missing package: {e}[/red]")
        console.print(
            "[yellow]Please run:[/yellow] [cyan]pip install -r requirements.txt[/cyan]"
        )
        raise typer.Exit(code=1)

    console.print("\n[bold green]Setup complete![/bold green]")
    console.print("\n[yellow]Next steps:[/yellow]")
    console.print(f"  1. Edit {env_file} with your configuration")
    console.print(
        "  2. Run: [cyan]python manage.py agent-engine deploy[/cyan] (or python main.py)"
    )
    console.print("  3. Run: [cyan]python manage.py workflow full-deploy[/cyan]")


@app.command()
def version() -> None:
    """Display version information."""
    console.print(
        "\n[bold blue]Agentic SOC Gemini Enterprise Agent Platform Management CLI[/bold blue]"
    )
    console.print("Version: [cyan]1.0.0[/cyan]")
    console.print("Python Typer-based unified management interface\n")


def main():
    """Main entry point."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {e}[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    main()
