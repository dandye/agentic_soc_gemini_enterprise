#!/usr/bin/env python3
"""
Model Version Manager for Gemini

This script lists the available Gemini model versions via Google GenAI SDK
to help developers select and configure current active model versions.
"""

import os
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from google import genai
from rich.console import Console
from rich.table import Table


app = typer.Typer(
    add_completion=False,
    help="List and discover available Gemini model versions.",
)

console = Console()


def get_genai_client() -> genai.Client:
    """
    Initialize and return a google-genai Client based on environment settings.
    """
    use_vertex = (
        os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "False") == "TRUE"
        or os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "False") == "True"
        or os.environ.get("GCP_VERTEXAI_ENABLED", "True") == "True"
    )

    project = os.environ.get("GCP_PROJECT_ID")
    location = os.environ.get("GCP_LOCATION", "us-central1")

    if use_vertex and project:
        console.print(
            f"[yellow]Using Vertex AI Backend (Project: {project}, Location: {location})[/yellow]"
        )
        return genai.Client(vertexai=True, project=project, location=location)
    else:
        console.print("[yellow]Using Gemini Developer API Backend (AI Studio)[/yellow]")
        return genai.Client()


@app.command("list")
def list_models(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """
    List available Gemini models via the Google GenAI SDK.
    """
    if env_file.exists():
        load_dotenv(env_file, override=True)

    console.print("\n[bold blue]Fetching Available Gemini Models...[/bold blue]\n")

    try:
        # Initialize genai Client based on environment settings
        client = get_genai_client()

        models = list(client.models.list())

        if not models:
            console.print("[yellow]No models returned by the API.[/yellow]")
            return

        table = Table(title="Available Gemini Models")
        table.add_column("Model Name", style="cyan")
        table.add_column("Version/Display Name", style="green")
        table.add_column("Description", style="white")

        for model in models:
            table.add_row(
                model.name or "", model.display_name or "", model.description or ""
            )

        console.print(table)
        console.print(f"\nTotal models discovered: [green]{len(models)}[/green]")

    except Exception as e:
        console.print(f"[red]Failed to retrieve models: {e}[/red]")
        console.print("\n[yellow]Troubleshooting tips:[/yellow]")
        console.print(
            "  1. Ensure you have set [cyan]GEMINI_API_KEY[/cyan] or standard GCP application credentials."
        )
        console.print("  2. Verify your network connection")
        raise typer.Exit(code=1)


@app.command("info")
def model_info(
    model_name: Annotated[
        str,
        typer.Argument(
            help="The name of the model to fetch details for (e.g., gemini-2.5-flash)."
        ),
    ],
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """
    Get detailed metadata for a specific Gemini model.
    """
    if env_file.exists():
        load_dotenv(env_file, override=True)

    console.print(
        f"\n[bold blue]Fetching Metadata for Model: {model_name}...[/bold blue]\n"
    )

    try:
        client = get_genai_client()
        model = client.models.get(model=model_name)

        table = Table(title=f"Model Details: {model.name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Display Name", model.display_name or "N/A")
        table.add_row("Description", model.description or "N/A")
        table.add_row("Input Token Limit", str(model.input_token_limit or "N/A"))
        table.add_row("Output Token Limit", str(model.output_token_limit or "N/A"))
        table.add_row(
            "Supported Generation Methods",
            ", ".join(model.supported_generation_methods or []),
        )

        console.print(table)

    except Exception as e:
        console.print(
            f"[red]Failed to retrieve model details for '{model_name}': {e}[/red]"
        )
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
