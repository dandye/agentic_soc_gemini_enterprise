#!/usr/bin/env python3
"""
IAM Manager for Google Cloud Platform

This script manages IAM policy bindings for service accounts required by
AgentSpace integration, including AI Platform Reasoning Engine and Discovery
Engine service accounts.
"""

import os
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from google.auth import default
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2, policy_pb2


app = typer.Typer(
    add_completion=False,
    help="Manage IAM permissions for AgentSpace service accounts.",
)


class IAMManager:
    """Manages IAM policy bindings for Google Cloud service accounts."""

    def __init__(self, env_file: Path):
        """
        Initialize the IAM manager.

        Args:
            env_file: Path to the environment file.
        """
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project_id = None
        self.project_number = None
        self.projects_client = None
        self._initialize_clients()

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        env_vars = dict(os.environ)
        return env_vars

    def _initialize_clients(self) -> None:
        """Initialize GCP clients with credentials."""
        self.project_id = self.env_vars.get("GCP_PROJECT_ID")
        self.project_number = self.env_vars.get("GCP_PROJECT_NUMBER")

        if not self.project_id:
            typer.secho(
                " Missing required variable: GCP_PROJECT_ID",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

        if not self.project_number:
            typer.secho(
                " Missing required variable: GCP_PROJECT_NUMBER",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

        try:
            credentials, _ = default()
            self.projects_client = resourcemanager_v3.ProjectsClient(
                credentials=credentials
            )
        except Exception as e:
            typer.secho(
                f" Failed to initialize Resource Manager client: {e}",
                fg=typer.colors.RED,
            )
            raise typer.Exit(code=1)

    def _get_service_account_email(self, service: str) -> str:
        """
        Get the service account email for a specific Google-managed service.

        Args:
            service: Service identifier (e.g., 'aiplatform-re', 'discoveryengine')

        Returns:
            Service account email
        """
        return f"service-{self.project_number}@gcp-sa-{service}.iam.gserviceaccount.com"

    def _get_iam_policy(self) -> policy_pb2.Policy:
        """Get the current IAM policy for the project."""
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{self.project_id}"
        )
        return self.projects_client.get_iam_policy(request=request)

    def _set_iam_policy(self, policy: policy_pb2.Policy) -> policy_pb2.Policy:
        """Set the IAM policy for the project."""
        request = iam_policy_pb2.SetIamPolicyRequest(
            resource=f"projects/{self.project_id}", policy=policy
        )
        return self.projects_client.set_iam_policy(request=request)

    def _add_role_binding(
        self, service_account: str, role: str, dry_run: bool = False
    ) -> bool:
        """
        Add a role binding to a service account.

        Args:
            service_account: Service account email
            role: IAM role to grant (e.g., 'roles/aiplatform.user')
            dry_run: If True, only simulate the change

        Returns:
            True if binding was added, False if it already exists
        """
        member = f"serviceAccount:{service_account}"

        # Get current policy
        policy = self._get_iam_policy()

        # Check if binding already exists
        for binding in policy.bindings:
            if binding.role == role:
                if member in binding.members:
                    return False

        if dry_run:
            return True

        # Add new binding
        new_binding = policy_pb2.Binding(role=role, members=[member])

        # Check if role exists in policy
        role_exists = False
        for binding in policy.bindings:
            if binding.role == role:
                binding.members.append(member)
                role_exists = True
                break

        if not role_exists:
            policy.bindings.append(new_binding)

        # Set updated policy
        self._set_iam_policy(policy)
        return True

    def _remove_role_binding(
        self, service_account: str, role: str, dry_run: bool = False
    ) -> bool:
        """
        Remove a role binding from a service account.

        Args:
            service_account: Service account email
            role: IAM role to remove
            dry_run: If True, only simulate the change

        Returns:
            True if binding was removed, False if it didn't exist
        """
        member = f"serviceAccount:{service_account}"

        # Get current policy
        policy = self._get_iam_policy()

        # Find and remove binding
        binding_found = False
        for binding in policy.bindings:
            if binding.role == role and member in binding.members:
                binding_found = True
                if not dry_run:
                    binding.members.remove(member)
                    # Remove binding if no members left
                    if not binding.members:
                        policy.bindings.remove(binding)
                break

        if not binding_found:
            return False

        if dry_run:
            return True

        # Set updated policy
        self._set_iam_policy(policy)
        return True

    def _check_role_binding(self, service_account: str, role: str) -> bool:
        """
        Check if a service account has a specific role.

        Args:
            service_account: Service account email
            role: IAM role to check

        Returns:
            True if binding exists, False otherwise
        """
        member = f"serviceAccount:{service_account}"
        policy = self._get_iam_policy()

        for binding in policy.bindings:
            if binding.role == role and member in binding.members:
                return True

        return False

    def setup_agentspace_permissions(
        self, dry_run: bool = False, verbose: bool = False
    ) -> dict[str, list[str]]:
        """
        Setup all required IAM permissions for AgentSpace integration.

        Args:
            dry_run: If True, only simulate the changes
            verbose: If True, print detailed information

        Returns:
            Dictionary with 'added', 'existing', and 'failed' role lists
        """
        results = {"added": [], "existing": [], "failed": []}

        # Define required service account permissions
        permissions = [
            {
                "service": "aiplatform-re",
                "name": "AI Platform Reasoning Engine",
                "roles": ["roles/aiplatform.user"],
                "purpose": "Query RAG corpus during agent execution",
            },
            {
                "service": "discoveryengine",
                "name": "Discovery Engine",
                "roles": ["roles/aiplatform.user", "roles/aiplatform.viewer"],
                "purpose": "Call ADK agent from AgentSpace",
            },
        ]

        for perm in permissions:
            sa_email = self._get_service_account_email(perm["service"])

            if verbose:
                typer.echo("")
                typer.secho(f"Service: {perm['name']}", fg=typer.colors.CYAN, bold=True)
                typer.echo(f"  Account: {sa_email}")
                typer.echo(f"  Purpose: {perm['purpose']}")
                typer.echo("")

            for role in perm["roles"]:
                try:
                    role_desc = f"{perm['name']}: {role}"

                    # Check if binding already exists
                    if self._check_role_binding(sa_email, role):
                        results["existing"].append(role_desc)
                        if verbose:
                            typer.secho(
                                f"  {role} - Already exists",
                                fg=typer.colors.YELLOW,
                            )
                        continue

                    # Add binding
                    added = self._add_role_binding(sa_email, role, dry_run=dry_run)

                    if added:
                        results["added"].append(role_desc)
                        if dry_run:
                            typer.secho(
                                f"  {role} - Would be added (dry run)",
                                fg=typer.colors.GREEN,
                            )
                        else:
                            typer.secho(
                                f"  {role} - Added successfully",
                                fg=typer.colors.GREEN,
                            )

                except Exception as e:
                    results["failed"].append(f"{role_desc}: {e}")
                    typer.secho(f"  {role} - Failed: {e}", fg=typer.colors.RED)

        return results

    def verify_agentspace_permissions(self) -> dict[str, bool]:
        """
        Verify all required AgentSpace permissions are configured.

        Returns:
            Dictionary mapping permission descriptions to boolean status
        """
        results = {}

        # Define required service account permissions
        permissions = [
            {
                "service": "aiplatform-re",
                "name": "AI Platform Reasoning Engine",
                "roles": ["roles/aiplatform.user"],
            },
            {
                "service": "discoveryengine",
                "name": "Discovery Engine",
                "roles": ["roles/aiplatform.user", "roles/aiplatform.viewer"],
            },
        ]

        for perm in permissions:
            sa_email = self._get_service_account_email(perm["service"])

            for role in perm["roles"]:
                role_desc = f"{perm['name']}: {role}"
                has_binding = self._check_role_binding(sa_email, role)
                results[role_desc] = has_binding

        return results

    def list_service_account_roles(self, service: str) -> list[str]:
        """
        List all roles granted to a specific Google-managed service account.

        Args:
            service: Service identifier (e.g., 'aiplatform-re', 'discoveryengine')

        Returns:
            List of role names
        """
        sa_email = self._get_service_account_email(service)
        member = f"serviceAccount:{sa_email}"
        policy = self._get_iam_policy()

        roles = []
        for binding in policy.bindings:
            if member in binding.members:
                roles.append(binding.role)

        return sorted(roles)


# CLI Commands


@app.command("setup")
def setup_command(
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Simulate changes without applying them",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed information",
        ),
    ] = False,
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            help="Path to .env file",
        ),
    ] = Path(".env"),
):
    """
    Setup all required IAM permissions for AgentSpace integration.

    This configures the following service accounts:
    - AI Platform Reasoning Engine Service Agent (for RAG access)
    - Discovery Engine Service Account (for calling agents from AgentSpace)
    """
    manager = IAMManager(env_file)

    typer.secho("=" * 50, fg=typer.colors.CYAN)
    typer.secho("AgentSpace IAM Permissions Setup", fg=typer.colors.CYAN, bold=True)
    typer.secho("=" * 50, fg=typer.colors.CYAN)
    typer.echo("")

    if dry_run:
        typer.secho("DRY RUN MODE - No changes will be made", fg=typer.colors.YELLOW)
        typer.echo("")

    typer.echo(f"Project ID: {manager.project_id}")
    typer.echo(f"Project Number: {manager.project_number}")
    typer.echo("")

    # Setup permissions
    results = manager.setup_agentspace_permissions(dry_run=dry_run, verbose=verbose)

    # Summary
    typer.echo("")
    typer.secho("=" * 50, fg=typer.colors.CYAN)
    typer.secho("Summary", fg=typer.colors.CYAN, bold=True)
    typer.secho("=" * 50, fg=typer.colors.CYAN)
    typer.echo("")

    if results["added"]:
        status = "Would add" if dry_run else "Added"
        typer.secho(f"{status}: {len(results['added'])}", fg=typer.colors.GREEN)
        for item in results["added"]:
            typer.echo(f"  - {item}")
        typer.echo("")

    if results["existing"]:
        typer.secho(
            f"Already configured: {len(results['existing'])}", fg=typer.colors.YELLOW
        )
        for item in results["existing"]:
            typer.echo(f"  - {item}")
        typer.echo("")

    if results["failed"]:
        typer.secho(f"Failed: {len(results['failed'])}", fg=typer.colors.RED)
        for item in results["failed"]:
            typer.echo(f"  - {item}")
        typer.echo("")

    if not dry_run and results["added"]:
        typer.secho(
            "IAM permissions configured successfully!", fg=typer.colors.GREEN, bold=True
        )
    elif dry_run:
        typer.secho(
            "Dry run complete. Use without --dry-run to apply changes.",
            fg=typer.colors.YELLOW,
        )


@app.command("verify")
def verify_command(
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            help="Path to .env file",
        ),
    ] = Path(".env"),
):
    """
    Verify all required AgentSpace IAM permissions are configured.
    """
    manager = IAMManager(env_file)

    typer.secho("=" * 50, fg=typer.colors.CYAN)
    typer.secho(
        "AgentSpace IAM Permissions Verification", fg=typer.colors.CYAN, bold=True
    )
    typer.secho("=" * 50, fg=typer.colors.CYAN)
    typer.echo("")

    typer.echo(f"Project ID: {manager.project_id}")
    typer.echo(f"Project Number: {manager.project_number}")
    typer.echo("")

    results = manager.verify_agentspace_permissions()

    all_configured = True
    for role_desc, has_binding in results.items():
        if has_binding:
            typer.secho(f"  {role_desc}", fg=typer.colors.GREEN)
        else:
            typer.secho(f"  {role_desc}", fg=typer.colors.RED)
            all_configured = False

    typer.echo("")

    if all_configured:
        typer.secho(
            "All required permissions are configured!", fg=typer.colors.GREEN, bold=True
        )
    else:
        typer.secho(
            "Some required permissions are missing.", fg=typer.colors.RED, bold=True
        )
        typer.echo("")
        typer.echo("Run 'python manage.py iam setup' to configure missing permissions.")
        raise typer.Exit(code=1)


@app.command("list-roles")
def list_roles_command(
    service: Annotated[
        str,
        typer.Argument(
            help="Service identifier (aiplatform-re or discoveryengine)",
        ),
    ],
    env_file: Annotated[
        Path,
        typer.Option(
            "--env-file",
            help="Path to .env file",
        ),
    ] = Path(".env"),
):
    """
    List all IAM roles granted to a specific Google-managed service account.

    SERVICE can be:
    - aiplatform-re: AI Platform Reasoning Engine Service Agent
    - discoveryengine: Discovery Engine Service Account
    """
    if service not in ["aiplatform-re", "discoveryengine"]:
        typer.secho(
            "Invalid service. Must be 'aiplatform-re' or 'discoveryengine'.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    manager = IAMManager(env_file)

    sa_email = manager._get_service_account_email(service)
    roles = manager.list_service_account_roles(service)

    service_names = {
        "aiplatform-re": "AI Platform Reasoning Engine Service Agent",
        "discoveryengine": "Discovery Engine Service Account",
    }

    typer.secho("=" * 50, fg=typer.colors.CYAN)
    typer.secho(service_names[service], fg=typer.colors.CYAN, bold=True)
    typer.secho("=" * 50, fg=typer.colors.CYAN)
    typer.echo("")
    typer.echo(f"Service Account: {sa_email}")
    typer.echo("")

    if roles:
        typer.secho(f"Granted Roles ({len(roles)}):", fg=typer.colors.GREEN, bold=True)
        for role in roles:
            typer.echo(f"  - {role}")
    else:
        typer.secho("No roles granted", fg=typer.colors.YELLOW)


if __name__ == "__main__":
    app()
