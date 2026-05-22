#!/usr/bin/env python3
"""
OAuth Manager for Google MCP Security Agent

This script manages OAuth authorization for AgentSpace integration including
creating, updating, and deleting OAuth authorizations.
"""

import json
import os
from pathlib import Path
from typing import Annotated, Any

import google.auth
import google_auth_oauthlib.flow
import requests
import typer
from dotenv import load_dotenv
from google.auth.transport import requests as google_requests


app = typer.Typer(
    add_completion=False,
    help="Manage OAuth authorizations for AgentSpace integration.",
)

DISCOVERY_ENGINE_API_BASE = "https://discoveryengine.googleapis.com/v1alpha"


class OAuthManager:
    """Manages OAuth configuration and operations."""

    def __init__(self, env_file: Path):
        """
        Initialize the OAuth manager.

        Args:
            env_file: Path to the environment file.
        """
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.creds, self.project = google.auth.default()

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file using python-dotenv."""
        # Load .env file into environment
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)

        # Get all environment variables (includes both .env and system env vars)
        # dotenv handles quotes, comments, and spaces properly
        env_vars = dict(os.environ)
        return env_vars

    def _update_env_var(self, key: str, value: str) -> None:
        """Update an environment variable in the .env file."""
        if not self.env_file.exists():
            self.env_file.touch()

        lines = []
        if self.env_file.exists():
            with open(self.env_file) as f:
                lines = f.readlines()

        # Find existing key or add new one
        key_found = False
        for i, line in enumerate(lines):
            if line.strip() and not line.strip().startswith("#") and "=" in line:
                existing_key = line.split("=", 1)[0].strip()
                if existing_key == key:
                    lines[i] = f"{key}={value}\n"
                    key_found = True
                    break

        if not key_found:
            lines.append(f"{key}={value}\n")

        with open(self.env_file, "w") as f:
            f.writelines(lines)

        # Update in-memory env_vars
        self.env_vars[key] = value

    def _get_access_token(self) -> str | None:
        """Get Google Cloud access token."""
        if not self.creds.valid:
            self.creds.refresh(google_requests.Request())
        return self.creds.token

    def generate_oauth_uri(
        self,
        client_secret_file: Path,
        scopes: list[str],
        redirect_uri: str = "https://vertexaisearch.cloud.google.com/oauth-redirect",
    ) -> tuple[str, str, str]:
        """
        Generate OAuth authorization URI from client secret file.

        Args:
            client_secret_file: Path to the OAuth client secret JSON file
            scopes: List of OAuth scopes to request
            redirect_uri: OAuth redirect URI

        Returns:
            Tuple of (authorization_url, client_id, client_secret)
        """
        if not client_secret_file.exists():
            typer.echo(
                f"Error: Client secret file not found: {client_secret_file}", err=True
            )
            raise typer.Exit(1)

        # Read client secret to extract client_id and client_secret
        with open(client_secret_file) as f:
            client_config = json.load(f)

        if "web" in client_config:
            client_id = client_config["web"]["client_id"]
            client_secret = client_config["web"]["client_secret"]
        elif "installed" in client_config:
            client_id = client_config["installed"]["client_id"]
            client_secret = client_config["installed"]["client_secret"]
        else:
            typer.echo("Error: Invalid client secret file format", err=True)
            raise typer.Exit(1)

        # Create OAuth flow
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            str(client_secret_file), scopes=scopes
        )

        flow.redirect_uri = redirect_uri

        # Generate authorization URL
        authorization_url, state = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent"
        )

        return authorization_url, client_id, client_secret

    def create_authorization(
        self,
        auth_id: str,
        client_id: str,
        client_secret: str,
        auth_uri: str,
        token_uri: str = "https://oauth2.googleapis.com/token",
    ) -> bool:
        """
        Create OAuth authorization in Discovery Engine.

        Args:
            auth_id: Unique identifier for the authorization
            client_id: OAuth client ID
            client_secret: OAuth client secret
            auth_uri: OAuth authorization URI
            token_uri: OAuth token exchange URI

        Returns:
            True if successful, False otherwise
        """
        project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
        if not project_number:
            typer.echo("Error: GCP_PROJECT_NUMBER not found in environment", err=True)
            return False

        access_token = self._get_access_token()
        if not access_token:
            typer.echo("Error: Failed to get access token", err=True)
            return False

        url = f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/locations/global/authorizations"

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "X-Goog-User-Project": project_number,
        }

        data = {
            "name": f"projects/{project_number}/locations/global/authorizations/{auth_id}",
            "serverSideOauth2": {
                "clientId": client_id,
                "clientSecret": client_secret,
                "authorizationUri": auth_uri,
                "tokenUri": token_uri,
            },
        }

        params = {"authorizationId": auth_id}

        try:
            response = requests.post(url, headers=headers, json=data, params=params)
            response.raise_for_status()

            typer.echo(f"Successfully created OAuth authorization: {auth_id}")

            # Save auth ID to env file
            self._update_env_var("OAUTH_AUTH_ID", auth_id)
            self._update_env_var("OAUTH_CLIENT_ID", client_id)
            self._update_env_var("OAUTH_CLIENT_SECRET", client_secret)
            self._update_env_var("OAUTH_AUTH_URI", auth_uri)
            self._update_env_var("OAUTH_TOKEN_URI", token_uri)

            return True

        except requests.exceptions.RequestException as e:
            typer.echo(f"Error creating OAuth authorization: {e}", err=True)
            if hasattr(e.response, "text"):
                typer.echo(f"Response: {e.response.text}", err=True)
            return False

    def delete_authorization(self, auth_id: str) -> bool:
        """
        Delete OAuth authorization from Discovery Engine.

        Args:
            auth_id: Authorization ID to delete

        Returns:
            True if successful, False otherwise
        """
        project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
        if not project_number:
            typer.echo("Error: GCP_PROJECT_NUMBER not found in environment", err=True)
            return False

        access_token = self._get_access_token()
        if not access_token:
            typer.echo("Error: Failed to get access token", err=True)
            return False

        url = f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/locations/global/authorizations/{auth_id}"

        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-Goog-User-Project": project_number,
        }

        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()

            typer.echo(f"Successfully deleted OAuth authorization: {auth_id}")
            return True

        except requests.exceptions.RequestException as e:
            typer.echo(f"Error deleting OAuth authorization: {e}", err=True)
            if hasattr(e.response, "text"):
                typer.echo(f"Response: {e.response.text}", err=True)
            return False

    def get_authorization(self, auth_id: str) -> dict[str, Any] | None:
        """
        Get OAuth authorization details from Discovery Engine.

        Args:
            auth_id: Authorization ID to retrieve

        Returns:
            Authorization details if found, None otherwise
        """
        project_number = self.env_vars.get("GCP_PROJECT_NUMBER")
        if not project_number:
            typer.echo("Error: GCP_PROJECT_NUMBER not found in environment", err=True)
            return None

        access_token = self._get_access_token()
        if not access_token:
            typer.echo("Error: Failed to get access token", err=True)
            return None

        url = f"{DISCOVERY_ENGINE_API_BASE}/projects/{project_number}/locations/global/authorizations/{auth_id}"

        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-Goog-User-Project": project_number,
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            typer.echo(f"Error retrieving OAuth authorization: {e}", err=True)
            if hasattr(e.response, "text"):
                typer.echo(f"Response: {e.response.text}", err=True)
            return None


@app.command()
def setup(
    client_secret_file: Annotated[
        Path, typer.Argument(help="Path to OAuth client secret JSON file")
    ],
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to environment file")
    ] = Path(".env"),
    scopes: Annotated[
        str | None,
        typer.Option("--scopes", "-s", help="Comma-separated OAuth scopes"),
    ] = None,
):
    """
    Setup OAuth authorization from client secret file.

    This command will:
    1. Generate OAuth authorization URI
    2. Save OAuth credentials to environment file
    3. Display the authorization URI for user to complete OAuth flow
    """
    manager = OAuthManager(env_file)

    # Default scopes if not provided
    if not scopes:
        scopes_list = [
            "https://www.googleapis.com/auth/drive.metadata.readonly",
            "https://www.googleapis.com/auth/calendar.readonly",
        ]
    else:
        scopes_list = [s.strip() for s in scopes.split(",")]

    typer.echo("Generating OAuth authorization URI...")

    try:
        auth_uri, client_id, client_secret = manager.generate_oauth_uri(
            client_secret_file, scopes_list
        )

        # Save to environment
        manager._update_env_var("OAUTH_CLIENT_ID", client_id)
        manager._update_env_var("OAUTH_CLIENT_SECRET", client_secret)
        manager._update_env_var("OAUTH_AUTH_URI", auth_uri)
        manager._update_env_var(
            "OAUTH_TOKEN_URI", "https://oauth2.googleapis.com/token"
        )

        typer.echo("\nOAuth configuration saved to environment file.")
        typer.echo("\nOAuth Authorization URI:")
        typer.echo(f"\n{auth_uri}\n")
        typer.echo(
            "Please visit the above URL to complete the OAuth authorization flow."
        )
        typer.echo(
            "\nAfter authorization, run 'make oauth-create-auth' to register the authorization."
        )

    except Exception as e:
        typer.echo(f"Error setting up OAuth: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def create_auth(
    auth_id: Annotated[
        str | None, typer.Option("--auth-id", "-i", help="Authorization ID")
    ] = None,
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to environment file")
    ] = Path(".env"),
):
    """
    Create OAuth authorization in Discovery Engine.

    Uses OAuth credentials from environment file to create the authorization.
    """
    manager = OAuthManager(env_file)

    # Use provided auth_id or get from environment
    if not auth_id:
        auth_id = manager.env_vars.get("OAUTH_AUTH_ID")
        if not auth_id:
            # Generate a default auth ID
            import uuid

            auth_id = f"auth-{uuid.uuid4().hex[:8]}"
            typer.echo(f"Generated authorization ID: {auth_id}")

    # Get OAuth credentials from environment
    client_id = manager.env_vars.get("OAUTH_CLIENT_ID")
    client_secret = manager.env_vars.get("OAUTH_CLIENT_SECRET")
    auth_uri = manager.env_vars.get("OAUTH_AUTH_URI")
    token_uri = manager.env_vars.get(
        "OAUTH_TOKEN_URI", "https://oauth2.googleapis.com/token"
    )

    if not all([client_id, client_secret, auth_uri]):
        typer.echo(
            "Error: OAuth credentials not found in environment. Run 'setup' command first.",
            err=True,
        )
        raise typer.Exit(1)

    if manager.create_authorization(
        auth_id, client_id, client_secret, auth_uri, token_uri
    ):
        typer.echo(
            f"\nAuthorization ID '{auth_id}' has been saved to environment file."
        )
        typer.echo(
            "You can now link your agent to AgentSpace using this authorization."
        )
    else:
        raise typer.Exit(1)


@app.command()
def verify(
    auth_id: Annotated[
        str | None, typer.Option("--auth-id", "-i", help="Authorization ID")
    ] = None,
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to environment file")
    ] = Path(".env"),
):
    """
    Verify OAuth authorization status.

    Checks if the authorization exists and displays its details.
    """
    manager = OAuthManager(env_file)

    # Use provided auth_id or get from environment
    if not auth_id:
        auth_id = manager.env_vars.get("OAUTH_AUTH_ID")
        if not auth_id:
            typer.echo(
                "Error: No authorization ID provided or found in environment", err=True
            )
            raise typer.Exit(1)

    auth_details = manager.get_authorization(auth_id)

    if auth_details:
        typer.echo(f"\nOAuth Authorization '{auth_id}' exists:")
        typer.echo(json.dumps(auth_details, indent=2))
    else:
        typer.echo(f"OAuth Authorization '{auth_id}' not found", err=True)
        raise typer.Exit(1)


@app.command()
def delete(
    auth_id: Annotated[
        str | None, typer.Option("--auth-id", "-i", help="Authorization ID")
    ] = None,
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to environment file")
    ] = Path(".env"),
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation prompt")
    ] = False,
):
    """
    Delete OAuth authorization from Discovery Engine.
    """
    manager = OAuthManager(env_file)

    # Use provided auth_id or get from environment
    if not auth_id:
        auth_id = manager.env_vars.get("OAUTH_AUTH_ID")
        if not auth_id:
            typer.echo(
                "Error: No authorization ID provided or found in environment", err=True
            )
            raise typer.Exit(1)

    if not force:
        confirm = typer.confirm(
            f"Are you sure you want to delete authorization '{auth_id}'?"
        )
        if not confirm:
            typer.echo("Deletion cancelled.")
            raise typer.Exit(0)

    if manager.delete_authorization(auth_id):
        typer.echo("Authorization deleted successfully.")
    else:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
