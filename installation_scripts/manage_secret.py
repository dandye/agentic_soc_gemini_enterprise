#!/usr/bin/env python3
"""
Secret Manager CLI for Google Cloud Secret Manager

This script handles registering, uploading, verifying, and syncing sensitive
credentials and service accounts from the local .env to Google Secret Manager.
"""

import json
import os
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from google.api_core import exceptions
from google.cloud import secretmanager


app = typer.Typer(
    add_completion=False,
    help="Manage Google Cloud Secret Manager keys for the Google MCP Security Agent.",
)


class SecretManager:
    """Manages creation, retrieval, and updates of secrets in Google Cloud Secret Manager."""

    def __init__(self, env_file: Path):
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project_id = self.env_vars.get("GCP_PROJECT_ID")
        self.sa_path = self.env_vars.get("CHRONICLE_SERVICE_ACCOUNT_PATH")

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        return dict(os.environ)

    def _get_client(
        self, credentials_path: Path = None
    ) -> secretmanager.SecretManagerServiceClient:
        """Initialize and return the Secret Manager client."""
        if credentials_path:
            from google.oauth2 import service_account

            credentials = service_account.Credentials.from_service_account_file(
                str(credentials_path)
            )
            typer.echo(f"Using credentials from: {credentials_path}")
            return secretmanager.SecretManagerServiceClient(credentials=credentials)
        else:
            typer.echo("Using Application Default Credentials (ADC)")
            return secretmanager.SecretManagerServiceClient()

    def create_or_update_secret(
        self,
        secret_id: str,
        secret_data: str,
        force: bool = False,
        credentials_path: Path = None,
    ) -> str:
        """
        Create or update a secret in Secret Manager.

        Args:
            secret_id: Name of the secret
            secret_data: The secret payload data
            force: If True, bypass confirmation prompt
            credentials_path: Optional path to service account key file

        Returns:
            Full secret version name
        """
        if not self.project_id:
            typer.secho("✗ GCP_PROJECT_ID not set", fg=typer.colors.RED)
            raise typer.Exit(1)

        client = self._get_client(credentials_path)
        parent = f"projects/{self.project_id}"
        secret_name = f"{parent}/secrets/{secret_id}"

        try:
            # Check if secret already exists
            client.get_secret(name=secret_name)
            secret_exists = True
        except exceptions.NotFound:
            secret_exists = False

        if secret_exists:
            if not force:
                typer.secho(
                    f"⚠️  Secret '{secret_id}' already exists in project '{self.project_id}'",
                    fg=typer.colors.YELLOW,
                )
                if not typer.confirm("Do you want to add a new version?", default=True):
                    typer.secho("Cancelled.", fg=typer.colors.YELLOW)
                    raise typer.Exit(0)

            typer.echo(f"Adding new version to existing secret '{secret_id}'...")
        else:
            typer.echo(f"Creating new secret '{secret_id}'...")
            secret = client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {
                        "replication": {
                            "automatic": {},
                        },
                    },
                }
            )
            typer.secho(f"✓ Created secret: {secret.name}", fg=typer.colors.GREEN)

        # Add secret version
        version = client.add_secret_version(
            request={
                "parent": secret_name,
                "payload": {"data": secret_data.encode("UTF-8")},
            }
        )

        typer.secho(f"✓ Added secret version: {version.name}", fg=typer.colors.GREEN)
        return version.name

    def upload_service_account(
        self,
        secret_id: str,
        force: bool = False,
        credentials_path: Path = None,
    ) -> None:
        """Upload the Chronicle service account JSON to Secret Manager."""
        if not self.sa_path:
            typer.secho(
                "✗ CHRONICLE_SERVICE_ACCOUNT_PATH not set in environment",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)

        sa_file = Path(self.sa_path)
        if not sa_file.exists():
            typer.secho(
                f"✗ Service account file not found: {self.sa_path}", fg=typer.colors.RED
            )
            raise typer.Exit(1)

        typer.echo(f"Reading service account file: {sa_file}")
        try:
            with open(sa_file) as f:
                sa_data = json.load(f)

            if "type" not in sa_data or sa_data["type"] != "service_account":
                typer.secho(
                    "✗ File does not appear to be a service account JSON",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(1)

            sa_json_str = json.dumps(sa_data)
            typer.secho("✓ Valid service account JSON", fg=typer.colors.GREEN)
            typer.echo(f"  Project: {sa_data.get('project_id', 'N/A')}")
            typer.echo(f"  Client Email: {sa_data.get('client_email', 'N/A')}")

        except json.JSONDecodeError as e:
            typer.secho(f"✗ Invalid JSON file: {e}", fg=typer.colors.RED)
            raise typer.Exit(1)

        typer.echo("\nUploading to Secret Manager...")
        typer.echo(f"  Project: {self.project_id}")
        typer.echo(f"  Secret ID: {secret_id}")

        self.create_or_update_secret(
            secret_id=secret_id,
            secret_data=sa_json_str,
            force=force,
            credentials_path=credentials_path,
        )

        typer.echo("\n" + "=" * 80)
        typer.secho("✓ Upload Complete!", fg=typer.colors.GREEN, bold=True)
        typer.echo("=" * 80 + "\n")

        secret_resource = (
            f"projects/{self.project_id}/secrets/{secret_id}/versions/latest"
        )
        typer.secho("Next Steps:", fg=typer.colors.YELLOW, bold=True)
        typer.echo("Add this to your .env file:")
        typer.echo()
        typer.secho(
            f'CHRONICLE_SERVICE_ACCOUNT_SECRET="{secret_resource}"',
            fg=typer.colors.CYAN,
        )
        typer.echo()
        typer.echo("The deployment script will automatically use Secret Manager")
        typer.echo("when CHRONICLE_SERVICE_ACCOUNT_SECRET is set.\n")

    def verify_service_account(
        self,
        secret_id: str,
        credentials_path: Path = None,
    ) -> None:
        """Verify that the Chronicle service account secret exists and is accessible."""
        if not self.project_id:
            typer.secho("✗ GCP_PROJECT_ID not set", fg=typer.colors.RED)
            raise typer.Exit(1)

        client = self._get_client(credentials_path)
        secret_name = f"projects/{self.project_id}/secrets/{secret_id}/versions/latest"

        try:
            typer.echo(f"Accessing secret: {secret_name}")
            response = client.access_secret_version(request={"name": secret_name})

            secret_data = response.payload.data.decode("UTF-8")
            sa_json = json.loads(secret_data)

            typer.secho("✓ Secret accessible!", fg=typer.colors.GREEN)
            typer.echo(f"  Project: {sa_json.get('project_id', 'N/A')}")
            typer.echo(f"  Client Email: {sa_json.get('client_email', 'N/A')}")
            typer.echo(f"  Size: {len(secret_data)} bytes")

        except exceptions.NotFound:
            typer.secho(f"✗ Secret not found: {secret_name}", fg=typer.colors.RED)
            raise typer.Exit(1)
        except exceptions.PermissionDenied:
            typer.secho("✗ Permission denied accessing secret", fg=typer.colors.RED)
            typer.echo(
                "  Ensure your credentials have 'secretmanager.versions.access' permission"
            )
            raise typer.Exit(1)
        except Exception as e:
            typer.secho(f"✗ Error accessing secret: {e}", fg=typer.colors.RED)
            raise typer.Exit(1)

    def sync_env_secrets(
        self,
        force: bool = False,
        credentials_path: Path = None,
    ) -> None:
        """Sync all sensitive environment variables from .env to Secret Manager."""
        secrets_to_sync = {
            "SOAR_APP_KEY": self.env_vars.get("SOAR_APP_KEY"),
            "GTI_API_KEY": self.env_vars.get("GTI_API_KEY"),
            "ELASTICSEARCH_PASSWORD": self.env_vars.get("ELASTICSEARCH_PASSWORD"),
            "NEO4J_PASSWORD": self.env_vars.get("NEO4J_PASSWORD"),
            "CTI_RESEARCHER_AGENT_RESOURCE_NAME": self.env_vars.get(
                "CTI_RESEARCHER_AGENT_RESOURCE_NAME"
            ),
            "DETECTION_ENGINEER_AGENT_RESOURCE_NAME": self.env_vars.get(
                "DETECTION_ENGINEER_AGENT_RESOURCE_NAME"
            ),
            "THREAT_HUNTER_AGENT_RESOURCE_NAME": self.env_vars.get(
                "THREAT_HUNTER_AGENT_RESOURCE_NAME"
            ),
            "TIER2_AGENT_RESOURCE_NAME": self.env_vars.get("TIER2_AGENT_RESOURCE_NAME"),
        }

        synced_count = 0
        for secret_id, secret_val in secrets_to_sync.items():
            if not secret_val:
                typer.echo(f"  Skipping '{secret_id}' (not set in .env)")
                continue

            typer.echo(f"\nProcessing '{secret_id}'...")
            try:
                self.create_or_update_secret(
                    secret_id=secret_id,
                    secret_data=secret_val,
                    force=force,
                    credentials_path=credentials_path,
                )
                synced_count += 1
            except Exception as e:
                typer.secho(f"✗ Failed to sync '{secret_id}': {e}", fg=typer.colors.RED)

        typer.echo("\n" + "=" * 80)
        typer.secho(
            f"✓ Sync Complete! Successfully synced {synced_count} secrets.",
            fg=typer.colors.GREEN,
            bold=True,
        )
        typer.echo("=" * 80 + "\n")


@app.command("upload")
def upload(
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to .env file")
    ] = Path(".env"),
    secret_id: Annotated[
        str, typer.Option("--secret-id", "-s", help="Secret ID in Secret Manager")
    ] = "chronicle-service-account",
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation prompts")
    ] = False,
    credentials: Annotated[
        Path,
        typer.Option(
            "--credentials", "-c", help="Path to service account key file for auth"
        ),
    ] = None,
) -> None:
    """Upload Chronicle service account JSON to Secret Manager."""
    typer.echo("\n" + "=" * 80)
    typer.secho(
        "Upload Service Account to Secret Manager", fg=typer.colors.BLUE, bold=True
    )
    typer.echo("=" * 80 + "\n")

    manager = SecretManager(env_file)
    manager.upload_service_account(secret_id, force, credentials)


@app.command("verify")
def verify(
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to .env file")
    ] = Path(".env"),
    secret_id: Annotated[
        str, typer.Option("--secret-id", "-s", help="Secret ID in Secret Manager")
    ] = "chronicle-service-account",
    credentials: Annotated[
        Path,
        typer.Option(
            "--credentials", "-c", help="Path to service account key file for auth"
        ),
    ] = None,
) -> None:
    """Verify that the service account secret exists and is accessible."""
    typer.echo("\n" + "=" * 80)
    typer.secho("Verify Secret Access", fg=typer.colors.BLUE, bold=True)
    typer.echo("=" * 80 + "\n")

    manager = SecretManager(env_file)
    manager.verify_service_account(secret_id, credentials)


@app.command("sync")
def sync(
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to .env file")
    ] = Path(".env"),
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Skip confirmation prompts")
    ] = False,
    credentials: Annotated[
        Path,
        typer.Option(
            "--credentials", "-c", help="Path to service account key file for auth"
        ),
    ] = None,
) -> None:
    """Sync all agent secrets (SOAR, GTI, DBs) from .env to Secret Manager."""
    typer.echo("\n" + "=" * 80)
    typer.secho(
        "Syncing Agent Secrets to Secret Manager", fg=typer.colors.BLUE, bold=True
    )
    typer.echo("=" * 80 + "\n")

    manager = SecretManager(env_file)
    manager.sync_env_secrets(force, credentials)


if __name__ == "__main__":
    app()
