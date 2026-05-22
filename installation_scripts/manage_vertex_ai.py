#!/usr/bin/env python3
"""
Vertex AI Setup and Verification Manager

This script helps verify and manage Vertex AI setup requirements including
API enablement, authentication, permissions, and quota status.
"""

import os
from pathlib import Path
from typing import Annotated

import typer
import vertexai
from dotenv import load_dotenv
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError

# Import validation utilities
from installation_scripts.env_validation import is_placeholder_value


app = typer.Typer(
    add_completion=False,
    help="Manage and verify Vertex AI setup for the Google MCP Security Agent.",
)


class VertexAIManager:
    """Manages Vertex AI setup verification and configuration."""

    # Required APIs for the project
    REQUIRED_APIS = [
        "aiplatform.googleapis.com",
        "storage.googleapis.com",
        "cloudbuild.googleapis.com",
        "compute.googleapis.com",
    ]

    # Optional APIs depending on features used
    OPTIONAL_APIS = [
        "discoveryengine.googleapis.com",  # For AgentSpace
        "securitycenter.googleapis.com",  # For SCC tools
    ]

    # Required IAM roles
    REQUIRED_ROLES = [
        "roles/aiplatform.user",
        "roles/storage.admin",
    ]

    def __init__(self, env_file: Path):
        """
        Initialize the Vertex AI manager.

        Args:
            env_file: Path to the environment file.
        """
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project_id = None
        self.location = None
        self.credentials = None

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        env_vars = dict(os.environ)
        return env_vars

    def verify_setup(
        self, skip_apis: bool = False, skip_permissions: bool = False
    ) -> bool:
        """
        Run complete verification of Vertex AI setup.

        Args:
            skip_apis: Skip API enablement checks
            skip_permissions: Skip IAM permission checks

        Returns:
            True if all checks pass, False otherwise
        """
        typer.echo()
        typer.secho("=" * 80, fg=typer.colors.BLUE)
        typer.secho("Vertex AI Setup Verification", fg=typer.colors.BLUE, bold=True)
        typer.secho("=" * 80, fg=typer.colors.BLUE)
        typer.echo()

        all_passed = True

        # Check 1: Environment variables
        typer.secho(
            "1. Checking environment variables...", fg=typer.colors.CYAN, bold=True
        )
        if not self._check_env_vars():
            all_passed = False
        typer.echo()

        # Check 2: Authentication
        typer.secho("2. Checking authentication...", fg=typer.colors.CYAN, bold=True)
        if not self._check_authentication():
            all_passed = False
            return False  # Can't continue without auth
        typer.echo()

        # Check 3: Project access
        typer.secho("3. Verifying project access...", fg=typer.colors.CYAN, bold=True)
        if not self._check_project_access():
            all_passed = False
        typer.echo()

        # Check 4: API enablement
        if not skip_apis:
            typer.secho(
                "4. Checking API enablement...", fg=typer.colors.CYAN, bold=True
            )
            if not self._check_apis():
                all_passed = False
            typer.echo()

        # Check 5: Vertex AI initialization
        typer.secho(
            "5. Testing Vertex AI initialization...", fg=typer.colors.CYAN, bold=True
        )
        if not self._check_vertex_ai_init():
            all_passed = False
        typer.echo()

        # Check 6: IAM permissions (if not skipped)
        if not skip_permissions:
            typer.secho(
                "6. Checking IAM permissions...", fg=typer.colors.CYAN, bold=True
            )
            self._check_permissions()  # This is informational, doesn't fail
            typer.echo()

        # Final summary
        typer.secho("=" * 80, fg=typer.colors.BLUE)
        if all_passed:
            typer.secho("✓ All checks passed!", fg=typer.colors.GREEN, bold=True)
            typer.secho("Vertex AI is properly configured.", fg=typer.colors.GREEN)
        else:
            typer.secho("✗ Some checks failed", fg=typer.colors.RED, bold=True)
            typer.secho(
                "Please fix the issues above before proceeding.", fg=typer.colors.RED
            )
        typer.secho("=" * 80, fg=typer.colors.BLUE)
        typer.echo()

        return all_passed

    def _check_env_vars(self) -> bool:
        """Check required environment variables."""
        required_vars = ["GCP_PROJECT_ID", "GCP_LOCATION"]
        all_valid = True

        for var in required_vars:
            value = self.env_vars.get(var)
            if not value:
                typer.secho(f"  ✗ {var}: Not set", fg=typer.colors.RED)
                all_valid = False
            else:
                # Check if it's a placeholder value
                is_placeholder, reason = is_placeholder_value(var, value)
                if is_placeholder:
                    typer.secho(
                        f"  ✗ {var}: {value} ({reason})",
                        fg=typer.colors.RED,
                    )
                    all_valid = False
                else:
                    typer.secho(f"  ✓ {var}: {value}", fg=typer.colors.GREEN)
                    if var == "GCP_PROJECT_ID":
                        self.project_id = value
                    elif var == "GCP_LOCATION":
                        self.location = value

        # Check optional RAG location
        rag_location = self.env_vars.get("RAG_GCP_LOCATION")
        if rag_location:
            is_placeholder, reason = is_placeholder_value(
                "RAG_GCP_LOCATION", rag_location
            )
            if is_placeholder:
                typer.secho(
                    f"  ✗ RAG_GCP_LOCATION: {rag_location} ({reason})",
                    fg=typer.colors.RED,
                )
                all_valid = False
            else:
                typer.secho(
                    f"  ✓ RAG_GCP_LOCATION: {rag_location}", fg=typer.colors.GREEN
                )
        else:
            typer.secho(
                "  ℹ RAG_GCP_LOCATION: Not set (will use GCP_LOCATION)",
                fg=typer.colors.YELLOW,
            )

        return all_valid

    def _check_authentication(self) -> bool:
        """Check if application default credentials are configured."""
        try:
            credentials, project = default()
            self.credentials = credentials
            typer.secho(
                "  ✓ Application Default Credentials found", fg=typer.colors.GREEN
            )
            if project:
                typer.secho(
                    f"  ✓ Authenticated project: {project}", fg=typer.colors.GREEN
                )
            return True
        except DefaultCredentialsError as e:
            typer.secho(f"  ✗ Authentication failed: {e}", fg=typer.colors.RED)
            typer.echo()
            typer.echo("  To fix, run:")
            typer.secho(
                "    gcloud auth application-default login", fg=typer.colors.YELLOW
            )
            typer.secho(
                f"    gcloud auth application-default set-quota-project {self.project_id}",
                fg=typer.colors.YELLOW,
            )
            return False

    def _check_project_access(self) -> bool:
        """Verify access to the configured GCP project using Python API."""
        try:
            from google.cloud import resourcemanager_v3

            # Create projects client
            projects_client = resourcemanager_v3.ProjectsClient(
                credentials=self.credentials
            )

            # Try to get the project
            project_name = f"projects/{self.project_id}"
            request = resourcemanager_v3.GetProjectRequest(name=project_name)
            project = projects_client.get_project(request=request)

            typer.secho(
                f"  ✓ Project accessible: {project.display_name or self.project_id}",
                fg=typer.colors.GREEN,
            )
            return True

        except ImportError:
            typer.secho(
                "  ⚠ google-cloud-resource-manager not installed (skipping project check)",
                fg=typer.colors.YELLOW,
            )
            return True
        except Exception as e:
            typer.secho(
                f"  ✗ Cannot access project: {self.project_id}", fg=typer.colors.RED
            )
            typer.secho(f"    Error: {str(e)}", fg=typer.colors.RED)
            typer.echo()
            typer.echo("  To fix, ensure:")
            typer.echo("    1. Credentials are valid and not expired:")
            typer.secho(
                "       gcloud auth application-default login", fg=typer.colors.YELLOW
            )
            typer.echo("    2. Project ID is correct in .env")
            typer.echo(
                f"    3. You have access to project '{self.project_id}' with current credentials"
            )
            return False

    def _check_apis(self) -> bool:
        """Check if required APIs are enabled."""
        all_enabled = True

        for api in self.REQUIRED_APIS:
            if self._is_api_enabled(api):
                typer.secho(f"  ✓ {api}", fg=typer.colors.GREEN)
            else:
                typer.secho(f"  ✗ {api} (not enabled)", fg=typer.colors.RED)
                all_enabled = False

        if not all_enabled:
            typer.echo()
            typer.echo("  To enable required APIs, run:")
            typer.secho(
                f"    gcloud services enable {' '.join(self.REQUIRED_APIS)} --project={self.project_id}",
                fg=typer.colors.YELLOW,
            )

        return all_enabled

    def _is_api_enabled(self, api: str) -> bool:
        """Check if a specific API is enabled using Python API."""
        try:
            from googleapiclient import discovery

            # Create service usage client using google-api-python-client
            service = discovery.build(
                "serviceusage",
                "v1",
                credentials=self.credentials,
                cache_discovery=False,
            )

            # Build the service name
            service_name = f"projects/{self.project_id}/services/{api}"

            # Get the service state
            result = service.services().get(name=service_name).execute()

            # Check if service is enabled
            return result.get("state") == "ENABLED"

        except ImportError:
            # Fallback to assuming enabled if library not available
            return True
        except Exception:
            # If we can't check (API error, not found, etc), assume not enabled
            return False

    def _check_vertex_ai_init(self) -> bool:
        """Test Vertex AI initialization."""
        try:
            # Use RAG location if set, otherwise use GCP_LOCATION
            location = self.env_vars.get("RAG_GCP_LOCATION") or self.location

            vertexai.init(
                project=self.project_id, location=location, credentials=self.credentials
            )
            typer.secho("  ✓ Vertex AI initialized successfully", fg=typer.colors.GREEN)
            typer.secho(f"    Project: {self.project_id}", fg=typer.colors.GREEN)
            typer.secho(f"    Location: {location}", fg=typer.colors.GREEN)
            return True
        except Exception as e:
            typer.secho(
                f"  ✗ Vertex AI initialization failed: {e}", fg=typer.colors.RED
            )
            return False

    def _check_permissions(self) -> bool:
        """Check IAM permissions using Python library."""
        try:
            from google.cloud import resourcemanager_v3
            from google.iam.v1 import iam_policy_pb2

            typer.echo("  Checking IAM permissions...")

            # Get current user identity from credentials
            if not self.credentials:
                typer.secho(
                    "  ⚠ No credentials available to check permissions",
                    fg=typer.colors.YELLOW,
                )
                return True

            # Try to get user email from credentials
            user_email = None
            if hasattr(self.credentials, "service_account_email"):
                user_email = self.credentials.service_account_email
            elif hasattr(self.credentials, "id_token"):
                # For user credentials, try to extract email from token
                try:
                    import base64
                    import json

                    # ID tokens are JWT format: header.payload.signature
                    token_parts = self.credentials.id_token.split(".")
                    if len(token_parts) >= 2:
                        # Decode payload (add padding if needed)
                        payload = token_parts[1]
                        payload += "=" * (4 - len(payload) % 4)
                        decoded = json.loads(base64.b64decode(payload))
                        user_email = decoded.get("email")
                except Exception as e:
                    # Silently ignore token parsing errors, fallback to gcloud
                    _ = e  # Suppress unused variable warning
                    pass

            if user_email:
                typer.echo(f"  Current user: {user_email}")
            else:
                typer.echo("  Current user: (authenticated, unable to determine email)")

            # Get IAM policy for the project
            projects_client = resourcemanager_v3.ProjectsClient(
                credentials=self.credentials
            )
            request = iam_policy_pb2.GetIamPolicyRequest(
                resource=f"projects/{self.project_id}"
            )
            policy = projects_client.get_iam_policy(request=request)

            # Build member identifier
            member_identifiers = []
            if user_email:
                member_identifiers.append(f"user:{user_email}")
                # Also check for serviceAccount format
                if "@" in user_email and ".iam.gserviceaccount.com" in user_email:
                    member_identifiers.append(f"serviceAccount:{user_email}")

            # Check if user has required roles
            user_roles = set()
            for binding in policy.bindings:
                for member in binding.members:
                    if any(member == mid for mid in member_identifiers):
                        user_roles.add(binding.role)

            # Check required roles
            all_roles_present = True
            typer.echo()
            typer.echo("  Required roles:")
            for role in self.REQUIRED_ROLES:
                if role in user_roles:
                    typer.secho(f"    ✓ {role}", fg=typer.colors.GREEN)
                else:
                    typer.secho(f"    ✗ {role} (not granted)", fg=typer.colors.RED)
                    all_roles_present = False

            if not all_roles_present:
                typer.echo()
                typer.echo("  To grant required roles, run:")
                if user_email:
                    for role in self.REQUIRED_ROLES:
                        if role not in user_roles:
                            typer.secho(
                                f"    gcloud projects add-iam-policy-binding {self.project_id} \\\n"
                                f"      --member='user:{user_email}' \\\n"
                                f"      --role='{role}'",
                                fg=typer.colors.YELLOW,
                            )

            return all_roles_present

        except ImportError:
            typer.secho(
                "  ⚠ google-cloud-resource-manager not installed (skipping permission check)",
                fg=typer.colors.YELLOW,
            )
            return True
        except Exception as e:
            typer.secho(f"  ⚠ Could not check permissions: {e}", fg=typer.colors.YELLOW)
            typer.echo(
                "    Note: Use GCP Console IAM page to verify permissions manually"
            )
            return True

    def enable_apis(self) -> bool:
        """Display command to enable required APIs."""
        typer.echo(f"To enable required APIs for project: {self.project_id}")
        typer.echo()

        apis_to_enable = self.REQUIRED_APIS.copy()
        cmd = f"gcloud services enable {' '.join(apis_to_enable)} --project={self.project_id}"

        typer.echo("Run this command:")
        typer.secho(f"  {cmd}", fg=typer.colors.YELLOW)
        typer.echo()
        typer.echo("Or enable APIs via the Cloud Console:")
        typer.echo(
            f"  https://console.cloud.google.com/apis/library?project={self.project_id}"
        )
        typer.echo()
        typer.echo("Note: It may take a few minutes for APIs to be fully active")

        return True


@app.command()
def verify(
    skip_apis: Annotated[
        bool, typer.Option("--skip-apis", help="Skip API enablement checks")
    ] = False,
    skip_permissions: Annotated[
        bool, typer.Option("--skip-permissions", help="Skip IAM permission checks")
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Verify complete Vertex AI setup including APIs, auth, and permissions."""
    manager = VertexAIManager(env_file)
    if not manager.verify_setup(skip_apis=skip_apis, skip_permissions=skip_permissions):
        raise typer.Exit(code=1)


@app.command()
def enable_apis(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Enable all required APIs for Vertex AI."""
    manager = VertexAIManager(env_file)

    # Load environment first
    manager._check_env_vars()

    if not manager.enable_apis():
        raise typer.Exit(code=1)


@app.command()
def check_quota(
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Display quota information for Vertex AI services."""
    manager = VertexAIManager(env_file)
    manager._load_env_vars()

    typer.echo()
    typer.secho("Vertex AI Quota Information", fg=typer.colors.CYAN, bold=True)
    typer.secho("=" * 80, fg=typer.colors.CYAN)
    typer.echo()

    typer.echo("RAG Service Quotas:")
    typer.echo("  - List/Get operations: 60 requests/minute/region")
    typer.echo("  - Create/Delete operations: Limited (check GCP Console)")
    typer.echo()

    typer.echo("To view current quota usage:")
    typer.secho(
        f"  gcloud services quota list --service=aiplatform.googleapis.com --project={manager.project_id}",
        fg=typer.colors.YELLOW,
    )
    typer.echo()

    typer.echo("To request quota increase:")
    typer.secho(
        "  https://cloud.google.com/docs/quotas/help/request_increase",
        fg=typer.colors.YELLOW,
    )
    typer.echo()


if __name__ == "__main__":
    app()
