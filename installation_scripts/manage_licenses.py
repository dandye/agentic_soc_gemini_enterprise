#!/usr/bin/env python3
"""
License Manager for Google Gemini Enterprise

This script manages Gemini Enterprise user licenses including listing,
assigning, and removing licenses using the Discovery Engine API.

https://docs.cloud.google.com/gemini/enterprise/docs/licenses
"""

import builtins
import json
import os
import time
from pathlib import Path
from typing import Annotated, Any

import google.auth
import requests
import typer
from dotenv import load_dotenv
from google.auth.transport import requests as google_requests


app = typer.Typer(
    add_completion=False,
    help="Manage Gemini Enterprise user licenses for the Google MCP Security Agent.",
)


class LicenseManager:
    """Manages Gemini Enterprise user licenses."""

    def __init__(self, env_file: Path):
        """
        Initialize the license manager.

        Args:
            env_file: Path to the environment file.
        """
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.creds = None
        self.project_id = None
        self.project_number = None
        self._initialize_credentials()

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        env_vars = dict(os.environ)
        return env_vars

    def _initialize_credentials(self) -> None:
        """Initialize credentials from service account or fallback to ADC."""
        self.project_id = self.env_vars.get("GCP_PROJECT_ID")
        self.project_number = self.env_vars.get("GCP_PROJECT_NUMBER")

        # Check for service account path configurations
        sa_path = (
            self.env_vars.get("GOOGLE_APPLICATION_CREDENTIALS")
            or self.env_vars.get("CHRONICLE_SERVICE_ACCOUNT_PATH")
            or self.env_vars.get("SECOPS_SA_PATH")
        )

        if sa_path and Path(sa_path).exists():
            from google.oauth2 import service_account

            try:
                self.creds = service_account.Credentials.from_service_account_file(
                    sa_path, scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
                # Dry refresh to validate
                self.creds.refresh(google_requests.Request())
                debug = self.env_vars.get("DEBUG", "").lower() in ["true", "1", "yes"]
                if debug:
                    typer.echo(f"Loaded service account credentials from: {sa_path}")
            except Exception as e:
                typer.secho(
                    f"Warning: Failed to load service account: {e}. Falling back to ADC.",
                    fg=typer.colors.YELLOW,
                )
                self._load_adc()
        else:
            self._load_adc()

        # If project number is not configured, try to fetch it dynamically using Resource Manager API
        if self.project_id and not self.project_number:
            try:
                fetched_number = self._fetch_project_number()
                if fetched_number:
                    self.project_number = fetched_number
                    debug = self.env_vars.get("DEBUG", "").lower() in [
                        "true",
                        "1",
                        "yes",
                    ]
                    if debug:
                        typer.echo(
                            f"Dynamically resolved GCP_PROJECT_NUMBER: {self.project_number}"
                        )
            except Exception as e:
                debug = self.env_vars.get("DEBUG", "").lower() in [
                    "true",
                    "1",
                    "yes",
                ]
                if debug:
                    typer.secho(
                        f"Warning: Failed to fetch project number: {e}",
                        fg=typer.colors.YELLOW,
                    )

    def _fetch_project_number(self) -> str | None:
        """Fetch project number using Cloud Resource Manager API."""
        if not self.project_id:
            return None

        # If project_id is already a number, return it
        if self.project_id.isdigit():
            return self.project_id

        url = (
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{self.project_id}"
        )
        response = self._make_request("GET", url, silent=True)
        if response and response.status_code == 200:
            result = response.json()
            project_number = result.get("projectNumber")
            return project_number
        return None

    def _load_adc(self) -> None:
        """Load credentials using Application Default Credentials (ADC)."""
        try:
            self.creds, default_project = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            if not self.project_id:
                self.project_id = default_project
        except Exception as e:
            typer.secho(
                f"Failed to initialize ADC credentials: {e}", fg=typer.colors.RED
            )
            typer.echo(
                "Please make sure you have run: gcloud auth application-default login"
            )
            raise typer.Exit(code=1)

    def _get_access_token(self) -> str | None:
        """Get or refresh access token."""
        if not self.creds.valid:
            try:
                self.creds.refresh(google_requests.Request())
            except Exception as e:
                typer.secho(
                    f"Failed to refresh OAuth credentials token: {e}",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)
        return self.creds.token

    def _get_base_url(self, location: str) -> str:
        """Get the base URL for the discovery engine endpoint based on location."""
        if location == "global":
            return "https://discoveryengine.googleapis.com/v1"
        return f"https://{location}-discoveryengine.googleapis.com/v1"

    def _make_request(
        self, method: str, url: str, silent: bool = False, **kwargs: Any
    ) -> requests.Response | None:
        """Make an authenticated request to the Discovery Engine API."""
        access_token = self._get_access_token()
        if not access_token:
            return None

        # Check for X-Goog-User-Project billing header
        billing_project = self.project_id or self.env_vars.get("GCP_PROJECT_ID")
        if not billing_project:
            typer.secho(
                "Missing GCP_PROJECT_ID. Please set it in your environment or option.",
                fg=typer.colors.RED,
            )
            return None

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "X-Goog-User-Project": billing_project,
        }
        headers.update(kwargs.pop("headers", {}))

        if "timeout" not in kwargs:
            kwargs["timeout"] = 60

        debug = self.env_vars.get("DEBUG", "").lower() in ["true", "1", "yes"]
        if debug:
            typer.echo(f"DEBUG: {method} {url}")
            if "json" in kwargs:
                import json as json_lib

                typer.echo(f"DEBUG Payload: {json_lib.dumps(kwargs['json'], indent=2)}")

        try:
            kwargs.setdefault("timeout", 60)
            response = requests.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            if not silent:
                typer.secho(f"API request failed: {e}", fg=typer.colors.RED)
                if e.response is not None:
                    typer.echo(f"Response: {e.response.text}")
            return None

    def _poll_operation(self, operation_name: str, location: str) -> dict | None:
        """Poll a long running operation until completion."""
        base_url = self._get_base_url(location)
        url = f"{base_url}/{operation_name}"

        typer.echo("Waiting for operation to complete...")
        while True:
            response = self._make_request("GET", url)
            if not response:
                return None
            result = response.json()
            if result.get("done", False):
                return result
            time.sleep(1)

    def list_licenses(self, location: str, output_json: bool = False) -> bool:
        """
        List all user licenses in the user store.

        Args:
            location: API location/region (global, us, eu)
            output_json: Whether to print raw JSON output

        Returns:
            True if successful, False otherwise
        """
        project = self.project_id or self.env_vars.get("GCP_PROJECT_ID")
        if not project:
            typer.secho("Missing GCP_PROJECT_ID", fg=typer.colors.RED)
            return False

        base_url = self._get_base_url(location)
        url = f"{base_url}/projects/{project}/locations/{location}/userStores/default_user_store/userLicenses"

        if not output_json:
            typer.echo(
                f"Fetching user licenses from project '{project}' (location: {location})..."
            )
        response = self._make_request("GET", url)

        if response and response.status_code == 200:
            result = response.json()

            if output_json:
                typer.echo(json.dumps(result, indent=2))
                return True

            user_licenses = result.get("userLicenses", [])

            if not user_licenses:
                typer.echo("No user licenses found.")
                return True

            typer.echo(f"\nFound {len(user_licenses)} user license(s):\n")

            # Print table-like structure
            header_format = "{:<40} {:<12} {:<30} {:<28} {:<28} {:<28}"
            typer.secho(
                header_format.format(
                    "User Principal (Email)",
                    "State",
                    "License Config",
                    "Create Time",
                    "Update Time",
                    "Last Login",
                ),
                bold=True,
            )
            typer.echo("-" * 170)

            for ul in user_licenses:
                user = ul.get("userPrincipal", "N/A")
                state = ul.get("licenseAssignmentState", "N/A")
                config = ul.get("licenseConfig", "N/A")
                create_time = ul.get("createTime", "N/A")
                update_time = ul.get("updateTime", "N/A")
                last_login = ul.get("lastLoginTime", "N/A")

                # Format config to display basename config ID for readability
                if config and config.startswith("projects/"):
                    config_id = config.split("/")[-1]
                else:
                    config_id = config

                # Add color for assignment state
                if state == "ASSIGNED":
                    state_color = typer.colors.GREEN
                elif state == "NO_LICENSE":
                    state_color = typer.colors.YELLOW
                else:
                    state_color = typer.colors.RED

                colorized_state = typer.style(state, fg=state_color)

                # Account for ANSI escape character length in layout alignment
                state_pad = 12 + (len(colorized_state) - len(state))
                format_str = (
                    f"{{:<40}} {{:<{state_pad}}} {{:<30}} {{:<28}} {{:<28}} {{:<28}}"
                )

                typer.echo(
                    format_str.format(
                        user,
                        colorized_state,
                        config_id,
                        create_time,
                        update_time,
                        last_login,
                    )
                )

            typer.echo()
            return True
        else:
            typer.secho("Failed to list licenses.", fg=typer.colors.RED)
            return False

    def list_configs(self, location: str) -> bool:
        """
        List all license configs available in the project.

        Args:
            location: API location/region (global, us, eu)

        Returns:
            True if successful, False otherwise
        """
        project = self.project_id or self.env_vars.get("GCP_PROJECT_ID")
        if not project:
            typer.secho("Missing GCP_PROJECT_ID", fg=typer.colors.RED)
            return False

        base_url = self._get_base_url(location)
        url = f"{base_url}/projects/{project}/locations/{location}/licenseConfigs"

        typer.echo(
            f"Fetching available license configs for project '{project}' (location: {location})..."
        )
        response = self._make_request("GET", url)

        if response and response.status_code == 200:
            result = response.json()
            configs = result.get("licenseConfigs", [])

            if not configs:
                typer.echo("No license configs found.")
                return True

            typer.echo(f"\nFound {len(configs)} license config(s):\n")

            header_format = "{:<30} {:<10} {:<40} {:<12} {:<12}"
            typer.secho(
                header_format.format(
                    "Config ID", "Seats", "Subscription Tier", "State", "End Date"
                ),
                bold=True,
            )
            typer.echo("-" * 110)

            for cfg in configs:
                name = cfg.get("name", "")
                config_id = name.split("/")[-1] if "/" in name else name
                count = cfg.get("licenseCount", "N/A")
                tier = cfg.get("subscriptionTier", "N/A")
                tier_short = tier.replace("SUBSCRIPTION_TIER_", "")
                state = cfg.get("state", "N/A")

                end_date_obj = cfg.get("endDate", {})
                if end_date_obj:
                    end_date = f"{end_date_obj.get('year')}-{end_date_obj.get('month'):02d}-{end_date_obj.get('day'):02d}"
                else:
                    end_date = "N/A"

                if state == "ACTIVE":
                    state_color = typer.colors.GREEN
                elif state == "DEACTIVATING":
                    state_color = typer.colors.YELLOW
                else:
                    state_color = typer.colors.RED

                colorized_state = typer.style(state, fg=state_color)
                state_pad = 12 + (len(colorized_state) - len(state))
                format_str = f"{{:<30}} {{:<10}} {{:<40}} {{:<{state_pad}}} {{:<12}}"

                typer.echo(
                    format_str.format(
                        config_id, count, tier_short, colorized_state, end_date
                    )
                )

            typer.echo()
            return True
        else:
            typer.secho("Failed to list license configs.", fg=typer.colors.RED)
            return False

    def assign_licenses(
        self, users: list[str], subscription: str, location: str
    ) -> bool:
        """
        Assign subscription license config to list of users.

        Args:
            users: List of email addresses
            subscription: Subscription Config ID (or full resource path)
            location: API location/region (global, us, eu)

        Returns:
            True if successful, False otherwise
        """
        project = self.project_id or self.env_vars.get("GCP_PROJECT_ID")
        number = self.project_number or self.env_vars.get("GCP_PROJECT_NUMBER")

        if not project:
            typer.secho("Missing GCP_PROJECT_ID", fg=typer.colors.RED)
            return False

        if not number:
            typer.secho(
                "Warning: GCP_PROJECT_NUMBER not set. Trying to proceed using project ID instead.",
                fg=typer.colors.YELLOW,
            )
            number = project

        # Handle full resource paths vs shorthand config ID
        if subscription.startswith("projects/"):
            license_config = subscription
        else:
            license_config = (
                f"projects/{number}/locations/{location}/licenseConfigs/{subscription}"
            )

        base_url = self._get_base_url(location)
        url = f"{base_url}/projects/{project}/locations/{location}/userStores/default_user_store:batchUpdateUserLicenses"

        user_licenses = [
            {"userPrincipal": user, "licenseConfig": license_config} for user in users
        ]

        payload = {
            "inlineSource": {
                "userLicenses": user_licenses,
            },
            "deleteUnassignedUserLicenses": False,
        }

        typer.echo(
            f"Assigning subscription '{subscription}' to {len(users)} user(s)..."
        )
        response = self._make_request("POST", url, json=payload)

        if response and response.status_code == 200:
            result = response.json()
            if not result.get("done", False):
                operation_name = result.get("name")
                result = self._poll_operation(operation_name, location)

            if result and "error" not in result:
                response_data = result.get("response", {})
                updated_licenses = response_data.get("userLicenses", [])
                all_assigned = True
                for ul in updated_licenses:
                    state = ul.get("licenseAssignmentState", "N/A")
                    user_principal = ul.get("userPrincipal", "N/A")
                    if state == "ASSIGNED":
                        state_style = typer.style(state, fg=typer.colors.GREEN)
                    else:
                        all_assigned = False
                        state_style = typer.style(state, fg=typer.colors.YELLOW)
                    typer.echo(f"  - {user_principal}: {state_style}")

                if all_assigned and updated_licenses:
                    typer.secho("Licenses assigned successfully!", fg=typer.colors.GREEN)
                elif not updated_licenses:
                    typer.secho(
                        "Warning: No user licenses returned in response.",
                        fg=typer.colors.YELLOW,
                    )
                else:
                    typer.secho(
                        "Warning: Some licenses were not assigned with state ASSIGNED.",
                        fg=typer.colors.YELLOW,
                    )
                return all_assigned
            else:
                error_msg = result.get("error", {}).get("message", "Unknown error")
                typer.secho(
                    f"Failed during operation execution: {error_msg}",
                    fg=typer.colors.RED,
                )
                return False
        else:
            typer.secho("Failed to assign licenses.", fg=typer.colors.RED)
            return False

    def remove_licenses(
        self, users: list[str], location: str, delete_unassigned: bool = True
    ) -> bool:
        """
        Remove licenses from a list of users.

        Args:
            users: List of email addresses
            location: API location/region (global, us, eu)
            delete_unassigned: If True, deletes user license entry. If False, updates status to NO_LICENSE.

        Returns:
            True if successful, False otherwise
        """
        project = self.project_id or self.env_vars.get("GCP_PROJECT_ID")
        if not project:
            typer.secho("Missing GCP_PROJECT_ID", fg=typer.colors.RED)
            return False

        base_url = self._get_base_url(location)
        url = f"{base_url}/projects/{project}/locations/{location}/userStores/default_user_store:batchUpdateUserLicenses"

        # Create inline source entries
        user_licenses = [{"userPrincipal": user} for user in users]

        payload = {
            "inlineSource": {
                "userLicenses": user_licenses,
            },
            "deleteUnassignedUserLicenses": delete_unassigned,
        }

        action_desc = (
            "Unassigning and deleting"
            if delete_unassigned
            else "Unassigning (marking NO_LICENSE)"
        )
        typer.echo(f"{action_desc} licenses for {len(users)} user(s)...")
        response = self._make_request("POST", url, json=payload)

        if response and response.status_code == 200:
            result = response.json()
            if not result.get("done", False):
                operation_name = result.get("name")
                result = self._poll_operation(operation_name, location)

            if result and "error" not in result:
                typer.secho("Licenses removed successfully!", fg=typer.colors.GREEN)
                response_data = result.get("response", {})
                updated_licenses = response_data.get("userLicenses", [])
                for ul in updated_licenses:
                    state = ul.get("licenseAssignmentState", "DELETED")
                    typer.echo(f"  - {ul.get('userPrincipal')}: {state}")
                return True
            else:
                error_msg = result.get("error", {}).get("message", "Unknown error")
                typer.secho(
                    f"Failed during operation execution: {error_msg}",
                    fg=typer.colors.RED,
                )
                return False
        else:
            typer.secho("Failed to remove licenses.", fg=typer.colors.RED)
            return False


@app.command()
def list(
    location: Annotated[
        str,
        typer.Option("--location", "-l", help="API Endpoint Location (global, us, eu)"),
    ] = "global",
    output_json: Annotated[
        bool,
        typer.Option("--json", help="Output raw JSON response"),
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """List all Gemini Enterprise user licenses."""
    manager = LicenseManager(env_file)
    if not manager.list_licenses(location, output_json=output_json):
        raise typer.Exit(code=1)


@app.command("list-configs")
def list_configs(
    location: Annotated[
        str,
        typer.Option("--location", "-l", help="API Endpoint Location (global, us, eu)"),
    ] = "global",
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """List available Gemini Enterprise license configs (subscriptions)."""
    manager = LicenseManager(env_file)
    if not manager.list_configs(location):
        raise typer.Exit(code=1)


@app.command()
def assign(
    users: Annotated[
        builtins.list[str], typer.Argument(help="Email addresses of the users")
    ],
    subscription: Annotated[
        str,
        typer.Option(
            "--subscription",
            "-s",
            help="Gemini Enterprise Subscription Config ID or resource path",
        ),
    ],
    location: Annotated[
        str,
        typer.Option("--location", "-l", help="API Endpoint Location (global, us, eu)"),
    ] = "global",
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Assign Gemini Enterprise licenses to users."""
    manager = LicenseManager(env_file)
    if not manager.assign_licenses(users, subscription, location):
        raise typer.Exit(code=1)


@app.command()
def remove(
    users: Annotated[
        builtins.list[str], typer.Argument(help="Email addresses of the users")
    ],
    location: Annotated[
        str,
        typer.Option("--location", "-l", help="API Endpoint Location (global, us, eu)"),
    ] = "global",
    keep_entry: Annotated[
        bool,
        typer.Option(
            "--keep-entry", help="Keep user store entry but mark as NO_LICENSE"
        ),
    ] = False,
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Remove user licenses (Unassign them from Gemini Enterprise)."""
    manager = LicenseManager(env_file)
    # If keep_entry is True, deleteUnassignedUserLicenses should be False, so it just marks them as NO_LICENSE
    delete_unassigned = not keep_entry
    if not manager.remove_licenses(users, location, delete_unassigned):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
