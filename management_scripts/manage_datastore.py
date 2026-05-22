#!/usr/bin/env python3
"""
DataStore Manager for Google Discovery Engine

This script manages data store operations including creating, listing,
getting information about, and deleting data stores.
"""

import os
from pathlib import Path
from typing import Annotated, Any

import google.auth
import requests
import typer
from dotenv import load_dotenv
from google.auth.transport import requests as google_requests


app = typer.Typer(
    add_completion=False,
    help="Manage data stores in Discovery Engine for the Google MCP Security Agent.",
)

DISCOVERY_ENGINE_API_BASE = "https://discoveryengine.googleapis.com/v1alpha"


class DataStoreManager:
    """Manages data store operations in Discovery Engine."""

    def __init__(self, env_file: Path):
        """
        Initialize the data store manager.

        Args:
            env_file: Path to the environment file.
        """
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.creds, self.project = google.auth.default()

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        env_vars = dict(os.environ)
        return env_vars

    def _get_access_token(self) -> str | None:
        """Get Google Cloud access token."""
        if not self.creds.valid:
            self.creds.refresh(google_requests.Request())
        return self.creds.token

    def _make_request(
        self, method: str, url: str, **kwargs: Any
    ) -> requests.Response | None:
        """Make an authenticated request to the Discovery Engine API."""
        access_token = self._get_access_token()
        if not access_token:
            return None

        project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
        if not project_number:
            typer.secho(" Missing GCP_PROJECT_NUMBER", fg=typer.colors.RED)
            return None

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "X-Goog-User-Project": project_number,
        }
        headers.update(kwargs.pop("headers", {}))

        try:
            response = requests.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            typer.secho(f" API request failed: {e}", fg=typer.colors.RED)
            if e.response is not None:
                typer.echo(f"  Response: {e.response.text}")
            return None

    def create_data_store(
        self,
        display_name: str,
        data_store_id: str | None = None,
        solution_type: str = "SOLUTION_TYPE_SEARCH",
        content_config: str = "CONTENT_REQUIRED",
        industry_vertical: str = "GENERIC",
    ) -> bool:
        """
        Create a new data store.

        Args:
            display_name: Display name for the data store
            data_store_id: Optional ID for the data store (generated if not provided)
            solution_type: Solution type (SOLUTION_TYPE_SEARCH, SOLUTION_TYPE_CHAT, etc.)
            content_config: Content configuration (CONTENT_REQUIRED, NO_CONTENT, etc.)
            industry_vertical: Industry vertical (GENERIC, MEDIA, HEALTHCARE, etc.)

        Returns:
            True if successful, False otherwise
        """
        project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
        if not project_number:
            typer.secho(" Missing GCP_PROJECT_NUMBER", fg=typer.colors.RED)
            return False

        collection = self.env_vars.get("AGENTSPACE_COLLECTION", "default_collection")

        # Generate data store ID if not provided
        if not data_store_id:
            import time

            data_store_id = (
                f"{display_name.lower().replace(' ', '-')}_{int(time.time())}"
            )

        url = (
            f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
            f"locations/global/collections/{collection}/dataStores"
        )

        data_store_config = {
            "displayName": display_name,
            "industryVertical": industry_vertical,
            "solutionTypes": [solution_type],
            "contentConfig": content_config,
        }

        typer.echo(f"Creating data store: {display_name}")
        typer.echo(f"  ID: {data_store_id}")
        typer.echo(f"  Solution type: {solution_type}")

        response = self._make_request(
            "POST", url, json=data_store_config, params={"dataStoreId": data_store_id}
        )

        if response and response.status_code in [200, 201]:
            result = response.json()
            typer.secho(" Data store created successfully!", fg=typer.colors.GREEN)
            typer.echo(f"  Resource name: {result.get('name', 'N/A')}")
            typer.echo(f"  Data store ID: {data_store_id}")
            return True
        else:
            typer.secho(" Failed to create data store", fg=typer.colors.RED)
            return False

    def list_data_stores(self) -> bool:
        """
        List all data stores in the project.

        Returns:
            True if successful, False otherwise
        """
        project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
        if not project_number:
            typer.secho(" Missing GCP_PROJECT_NUMBER", fg=typer.colors.RED)
            return False

        collection = self.env_vars.get("AGENTSPACE_COLLECTION", "default_collection")

        url = (
            f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
            f"locations/global/collections/{collection}/dataStores"
        )

        response = self._make_request("GET", url)

        if response and response.status_code == 200:
            result = response.json()
            data_stores = result.get("dataStores", [])

            if not data_stores:
                typer.echo("No data stores found.")
                return True

            typer.echo(f"\nFound {len(data_stores)} data store(s):\n")
            for i, ds in enumerate(data_stores, 1):
                name = ds.get("name", "")
                ds_id = name.split("/")[-1] if "/" in name else name
                display_name = ds.get("displayName", "N/A")
                content_config = ds.get("contentConfig", "N/A")
                solution_types = ds.get("solutionTypes", [])

                typer.echo(f"{i}. {display_name}")
                typer.echo(f"   ID: {ds_id}")
                typer.echo(f"   Resource: {name}")
                typer.echo(f"   Content Config: {content_config}")
                typer.echo(f"   Solution Types: {', '.join(solution_types)}")
                typer.echo()

            return True
        else:
            typer.secho(" Failed to list data stores", fg=typer.colors.RED)
            return False

    def get_data_store_info(self, data_store_id: str) -> bool:
        """
        Get information about a specific data store.

        Args:
            data_store_id: ID of the data store

        Returns:
            True if successful, False otherwise
        """
        project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
        if not project_number:
            typer.secho(" Missing GCP_PROJECT_NUMBER", fg=typer.colors.RED)
            return False

        collection = self.env_vars.get("AGENTSPACE_COLLECTION", "default_collection")

        url = (
            f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
            f"locations/global/collections/{collection}/dataStores/{data_store_id}"
        )

        response = self._make_request("GET", url)

        if response and response.status_code == 200:
            ds = response.json()
            typer.echo("\nData Store Information:")
            typer.echo("=" * 80)
            typer.echo(f"Display Name: {ds.get('displayName', 'N/A')}")
            typer.echo(f"Resource Name: {ds.get('name', 'N/A')}")
            typer.echo(f"Content Config: {ds.get('contentConfig', 'N/A')}")
            typer.echo(f"Industry Vertical: {ds.get('industryVertical', 'N/A')}")
            typer.echo(f"Solution Types: {', '.join(ds.get('solutionTypes', []))}")
            typer.echo(f"Create Time: {ds.get('createTime', 'N/A')}")
            typer.echo("=" * 80)
            return True
        else:
            typer.secho(f" Data store not found: {data_store_id}", fg=typer.colors.RED)
            return False

    def delete_data_store(self, data_store_id: str, force: bool = False) -> bool:
        """
        Delete a data store.

        Args:
            data_store_id: ID of the data store to delete
            force: Skip confirmation prompt

        Returns:
            True if successful, False otherwise
        """
        project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
        if not project_number:
            typer.secho(" Missing GCP_PROJECT_NUMBER", fg=typer.colors.RED)
            return False

        collection = self.env_vars.get("AGENTSPACE_COLLECTION", "default_collection")

        url = (
            f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/"
            f"locations/global/collections/{collection}/dataStores/{data_store_id}"
        )

        # Get data store info first
        info_response = self._make_request("GET", url)
        if not info_response:
            typer.secho(f" Data store not found: {data_store_id}", fg=typer.colors.RED)
            return False

        ds = info_response.json()
        display_name = ds.get("displayName", data_store_id)

        if not force:
            typer.echo(f"\nData store to delete: {display_name}")
            typer.echo(f"  ID: {data_store_id}")
            if not typer.confirm("\nAre you sure you want to delete this data store?"):
                typer.echo("Cancelled.")
                return False

        typer.echo(f"Deleting data store: {display_name}")
        response = self._make_request("DELETE", url)

        if response and response.status_code in [200, 204]:
            typer.secho(" Data store deleted successfully!", fg=typer.colors.GREEN)
            return True
        else:
            typer.secho(" Failed to delete data store", fg=typer.colors.RED)
            return False


@app.command()
def create(
    name: Annotated[
        str, typer.Option("--name", "-n", help="Display name for the data store")
    ] = "datastore",
    data_store_id: Annotated[
        str | None, typer.Option("--id", "-i", help="ID for the data store")
    ] = None,
    solution_type: Annotated[
        str, typer.Option("--type", "-t", help="Solution type")
    ] = "SOLUTION_TYPE_SEARCH",
    content_config: Annotated[
        str, typer.Option("--content", "-c", help="Content configuration")
    ] = "CONTENT_REQUIRED",
    industry: Annotated[
        str, typer.Option("--industry", help="Industry vertical")
    ] = "GENERIC",
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Create a new data store."""
    manager = DataStoreManager(env_file)
    if not manager.create_data_store(
        name, data_store_id, solution_type, content_config, industry
    ):
        raise typer.Exit(code=1)


@app.command()
def list(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """List all data stores in the project."""
    manager = DataStoreManager(env_file)
    if not manager.list_data_stores():
        raise typer.Exit(code=1)


@app.command()
def info(
    data_store_id: Annotated[str, typer.Argument(help="ID of the data store")],
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Get information about a specific data store."""
    manager = DataStoreManager(env_file)
    if not manager.get_data_store_info(data_store_id):
        raise typer.Exit(code=1)


@app.command()
def delete(
    data_store_id: Annotated[
        str, typer.Argument(help="ID of the data store to delete")
    ],
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation prompt")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Delete a data store."""
    manager = DataStoreManager(env_file)
    if not manager.delete_data_store(data_store_id, force):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
