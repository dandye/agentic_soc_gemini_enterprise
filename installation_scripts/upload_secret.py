#!/usr/bin/env python3
"""
Upload Service Account to Google Secret Manager

This script uploads the Chronicle service account JSON file to Secret Manager
for secure access by the deployed agent.
"""

import json
import os
from pathlib import Path

import typer
from dotenv import load_dotenv
from google.api_core import exceptions
from google.cloud import secretmanager


app = typer.Typer(add_completion=False)


def create_or_update_secret(
    project_id: str,
    secret_id: str,
    secret_data: str,
    force: bool = False,
    credentials_path: Path = None,
) -> str:
    """
    Create or update a secret in Secret Manager.

    Args:
        project_id: GCP project ID
        secret_id: Name of the secret
        secret_data: The secret data (JSON string)
        force: If True, update existing secret without confirmation
        credentials_path: Optional path to service account key file

    Returns:
        Full secret version name
    """
    # Initialize client with credentials if provided
    if credentials_path:
        from google.oauth2 import service_account

        credentials = service_account.Credentials.from_service_account_file(
            str(credentials_path)
        )
        client = secretmanager.SecretManagerServiceClient(credentials=credentials)
        typer.echo(f"Using credentials from: {credentials_path}")
    else:
        client = secretmanager.SecretManagerServiceClient()
        typer.echo("Using Application Default Credentials (ADC)")
    parent = f"projects/{project_id}"
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
                f"⚠️  Secret '{secret_id}' already exists in project '{project_id}'",
                fg=typer.colors.YELLOW,
            )
            if not typer.confirm("Do you want to add a new version?", default=True):
                typer.secho("Cancelled.", fg=typer.colors.YELLOW)
                raise typer.Exit(0)

        typer.echo(f"Adding new version to existing secret '{secret_id}'...")
    else:
        typer.echo(f"Creating new secret '{secret_id}'...")
        # Create the secret
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


@app.command()
def upload(
    env_file: Path = typer.Option(  # noqa: B008
        Path(".env"), "--env-file", "-e", help="Path to .env file"
    ),
    secret_id: str = typer.Option(  # noqa: B008
        "chronicle-service-account",
        "--secret-id",
        "-s",
        help="Secret ID in Secret Manager",
    ),
    force: bool = typer.Option(  # noqa: B008
        False, "--force", "-f", help="Skip confirmation prompts"
    ),
    credentials: Path = typer.Option(  # noqa: B008
        None,
        "--credentials",
        "-c",
        help="Path to service account key file for authentication (if different from ADC)",
    ),
):
    """
    Upload Chronicle service account JSON to Secret Manager.

    This reads the CHRONICLE_SERVICE_ACCOUNT_PATH from .env and uploads
    the JSON file to Google Secret Manager for secure access.
    """
    typer.echo("\n" + "=" * 80)
    typer.secho(
        "Upload Service Account to Secret Manager", fg=typer.colors.BLUE, bold=True
    )
    typer.echo("=" * 80 + "\n")

    # Load environment variables
    if not env_file.exists():
        typer.secho(f"✗ Environment file not found: {env_file}", fg=typer.colors.RED)
        raise typer.Exit(1)

    load_dotenv(env_file, override=True)

    # Get required variables
    project_id = os.environ.get("GCP_PROJECT_ID")
    sa_path = os.environ.get("CHRONICLE_SERVICE_ACCOUNT_PATH")

    if not project_id:
        typer.secho("✗ GCP_PROJECT_ID not set in .env", fg=typer.colors.RED)
        raise typer.Exit(1)

    if not sa_path:
        typer.secho(
            "✗ CHRONICLE_SERVICE_ACCOUNT_PATH not set in .env", fg=typer.colors.RED
        )
        raise typer.Exit(1)

    sa_file = Path(sa_path)
    if not sa_file.exists():
        typer.secho(f"✗ Service account file not found: {sa_path}", fg=typer.colors.RED)
        raise typer.Exit(1)

    # Read and validate service account JSON
    typer.echo(f"Reading service account file: {sa_file}")
    try:
        with open(sa_file) as f:
            sa_data = json.load(f)

        # Validate it's a service account JSON
        if "type" not in sa_data or sa_data["type"] != "service_account":
            typer.secho(
                "✗ File does not appear to be a service account JSON",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)

        # Convert back to string for storage
        sa_json_str = json.dumps(sa_data)

        typer.secho("✓ Valid service account JSON", fg=typer.colors.GREEN)
        typer.echo(f"  Project: {sa_data.get('project_id', 'N/A')}")
        typer.echo(f"  Client Email: {sa_data.get('client_email', 'N/A')}")

    except json.JSONDecodeError as e:
        typer.secho(f"✗ Invalid JSON file: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    # Validate credentials file if provided
    if credentials and not credentials.exists():
        typer.secho(f"✗ Credentials file not found: {credentials}", fg=typer.colors.RED)
        raise typer.Exit(1)

    # Upload to Secret Manager
    typer.echo("\nUploading to Secret Manager...")
    typer.echo(f"  Project: {project_id}")
    typer.echo(f"  Secret ID: {secret_id}")
    if credentials:
        typer.echo(f"  Using credentials: {credentials}")

    try:
        create_or_update_secret(
            project_id=project_id,
            secret_id=secret_id,
            secret_data=sa_json_str,
            force=force,
            credentials_path=credentials,
        )

        typer.echo("\n" + "=" * 80)
        typer.secho("✓ Upload Complete!", fg=typer.colors.GREEN, bold=True)
        typer.echo("=" * 80 + "\n")

        # Provide instructions for updating .env
        secret_resource = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
        typer.secho("Next Steps:", fg=typer.colors.YELLOW, bold=True)
        typer.echo("Add this to your .env file:")
        typer.echo()
        typer.secho(
            f'CHRONICLE_SERVICE_ACCOUNT_SECRET="{secret_resource}"',
            fg=typer.colors.CYAN,
        )
        typer.echo()
        typer.echo("The deployment script will automatically use Secret Manager")
        typer.echo("when CHRONICLE_SERVICE_ACCOUNT_SECRET is set.")
        typer.echo()

    except Exception as e:
        typer.secho(f"✗ Error uploading secret: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)


@app.command()
def verify(
    env_file: Path = typer.Option(  # noqa: B008
        Path(".env"), "--env-file", "-e", help="Path to .env file"
    ),
    secret_id: str = typer.Option(  # noqa: B008
        "chronicle-service-account",
        "--secret-id",
        "-s",
        help="Secret ID in Secret Manager",
    ),
    credentials: Path = typer.Option(  # noqa: B008
        None,
        "--credentials",
        "-c",
        help="Path to service account key file for authentication (if different from ADC)",
    ),
):
    """
    Verify that the secret exists and is accessible.
    """
    typer.echo("\n" + "=" * 80)
    typer.secho("Verify Secret Access", fg=typer.colors.BLUE, bold=True)
    typer.echo("=" * 80 + "\n")

    load_dotenv(env_file, override=True)
    project_id = os.environ.get("GCP_PROJECT_ID")

    if not project_id:
        typer.secho("✗ GCP_PROJECT_ID not set in .env", fg=typer.colors.RED)
        raise typer.Exit(1)

    # Validate credentials file if provided
    if credentials and not credentials.exists():
        typer.secho(f"✗ Credentials file not found: {credentials}", fg=typer.colors.RED)
        raise typer.Exit(1)

    # Initialize client with credentials if provided
    if credentials:
        from google.oauth2 import service_account

        creds = service_account.Credentials.from_service_account_file(str(credentials))
        client = secretmanager.SecretManagerServiceClient(credentials=creds)
        typer.echo(f"Using credentials from: {credentials}")
    else:
        client = secretmanager.SecretManagerServiceClient()
        typer.echo("Using Application Default Credentials (ADC)")

    secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"

    try:
        typer.echo(f"Accessing secret: {secret_name}")
        response = client.access_secret_version(request={"name": secret_name})

        # Try to parse as JSON
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


if __name__ == "__main__":
    app()
