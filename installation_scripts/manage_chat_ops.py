#!/usr/bin/env python3
"""
ChatOps Manager for Google SOC Agent

This script allows testing ChatOps cards by sending them to a configured Google Chat webhook
and provides tools to deploy the Cloud Function backend that handles button clicks.
"""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv


app = typer.Typer(
    add_completion=False,
    help="Manage ChatOps cards and backend functions for the SOC Agent.",
)


class ChatOpsManager:
    """Manages testing and deployment of ChatOps components."""

    def __init__(self, env_file: Path):
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.webhook_url = self.env_vars.get("WEBHOOK_URL")
        self.project_id = self.env_vars.get("GCP_PROJECT_ID")
        self.region = self.env_vars.get(
            "GCP_LOCATION", "us-east4"
        )  # Standard for this project

    def _load_env_vars(self) -> dict:
        """Load environment variables from .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        return dict(os.environ)

    def list_cards(self, cards_dir: Path):
        """List all available ChatOps test cards, preferring Python versions."""
        if not cards_dir.exists():
            typer.secho(
                f"Error: Cards directory {cards_dir} not found.", fg=typer.colors.RED
            )
            return []

        py_stems = {
            c.stem
            for c in cards_dir.glob("*.py")
            if c.name != "__init__.py" and c.name != "card_client.py"
        }
        sh_stems = {
            c.stem for c in cards_dir.glob("*.sh") if c.name != "refactor_sh_files.sh"
        }

        all_stems = sorted(py_stems | sh_stems)

        display_cards = []
        for stem in all_stems:
            if (cards_dir / f"{stem}.py").exists():
                display_cards.append(f"{stem}.py")
            else:
                display_cards.append(f"{stem}.sh")

        return display_cards

    def test_card(self, card_name: str, cards_dir: Path):
        """Execute a card test (Python version used if available)."""
        stem = Path(card_name).stem
        py_path = cards_dir / f"{stem}.py"
        sh_path = cards_dir / f"{stem}.sh"

        if not self.webhook_url:
            typer.secho("Error: WEBHOOK_URL not set in .env", fg=typer.colors.RED)
            return False

        if py_path.exists():
            return self._test_py_card(stem, cards_dir)
        elif sh_path.exists():
            return self._test_sh_card(sh_path, cards_dir)
        else:
            typer.secho(f"Error: Card {card_name} not found.", fg=typer.colors.RED)
            return False

    def _test_py_card(self, stem: str, cards_dir: Path):
        """Import and run a Python card definition."""
        module_name = f"chatops_card_{stem}"
        py_path = cards_dir / f"{stem}.py"

        typer.echo(
            f"Sending card (Python): {typer.style(py_path.name, fg=typer.colors.CYAN)}"
        )

        try:
            spec = importlib.util.spec_from_file_location(module_name, str(py_path))
            module = importlib.util.module_from_spec(spec)
            # Add cards_dir to path so it can find card_client
            if str(cards_dir) not in sys.path:
                sys.path.insert(0, str(cards_dir))

            spec.loader.exec_module(module)

            if not hasattr(module, "get_card"):
                typer.secho(
                    f"Error: {py_path.name} does not have a get_card() function.",
                    fg=typer.colors.RED,
                )
                return False

            card = module.get_card()

            # Import our client logic
            # We don't want to use the module's main because it might use relative imports that fail here
            from soc_agent.tools.chatops.card_client import send_card

            send_card(card, self.webhook_url)

            typer.secho("Card sent successfully via Python!", fg=typer.colors.GREEN)
            return True
        except Exception as e:
            typer.secho(f"Failed to send Python card: {e}", fg=typer.colors.RED)
            import traceback

            typer.echo(traceback.format_exc())
            return False

    def _test_sh_card(self, sh_path: Path, cards_dir: Path):
        """Execute a traditional shell card script."""
        typer.echo(
            f"Sending card (Shell fallback): {typer.style(sh_path.name, fg=typer.colors.YELLOW)}"
        )
        try:
            env = os.environ.copy()
            env["WEBHOOK_URL"] = self.webhook_url
            os.chmod(sh_path, 0o755)  # noqa: S103

            subprocess.run(
                [str(sh_path.absolute())],
                env=env,
                cwd=cards_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            typer.secho("Card sent successfully via Shell!", fg=typer.colors.GREEN)
            return True
        except subprocess.CalledProcessError as e:
            typer.secho(f"Failed to send shell card: {e}", fg=typer.colors.RED)
            return False

    def deploy_backend(
        self,
        function_dir: Path,
        language: str = "python",
        service: str = "chatops-handler",
    ):
        """Deploy the backend Cloud Function."""
        if not function_dir.exists():
            typer.secho(
                f"Error: Function directory {function_dir} not found.",
                fg=typer.colors.RED,
            )
            return False

        if not self.project_id:
            typer.secho("Error: GCP_PROJECT_ID not set in .env", fg=typer.colors.RED)
            return False

        typer.echo(f"Deploying Cloud Function from {function_dir} ({language})...")

        if language == "python":
            entry_points = ["chatops_handler", "alert_handler"]
            runtime = "python311"
        else:
            entry_points = ["chatopsHandler", "alertHandler"]
            runtime = "nodejs20"

        # Get project number for ENV variables
        try:
            project_number = subprocess.check_output(
                [
                    "gcloud",
                    "projects",
                    "describe",
                    self.project_id,
                    "--format",
                    "value(projectNumber)",
                ],
                text=True,
            ).strip()
        except Exception:
            typer.secho(
                "Warning: Could not fetch project number, some logic might fail.",
                fg=typer.colors.YELLOW,
            )
            project_number = "0"

        success = True
        for entry in entry_points:
            # If service name is provided, use it for the first entry point, then append suffix for others
            func_name = (
                entry
                if len(entry_points) == 1
                else f"{service}-{entry.replace('_', '-')}"
            )

            typer.echo(f"Deploying {typer.style(func_name, fg=typer.colors.CYAN)}...")
            cmd = [
                "gcloud",
                "functions",
                "deploy",
                func_name,
                "--project",
                self.project_id,
                "--region",
                self.region,
                "--runtime",
                runtime,
                "--trigger-http",
                "--allow-unauthenticated",
                "--gen2",
                f"--source={function_dir.absolute()}",
                f"--entry-point={entry}",
                f"--set-env-vars=PROJECT_NUMBER={project_number}",
            ]

            try:
                subprocess.run(cmd, check=True)
                typer.secho(f"Successfully deployed {func_name}", fg=typer.colors.GREEN)
            except subprocess.CalledProcessError as e:
                typer.secho(f"Failed to deploy {func_name}: {e}", fg=typer.colors.RED)
                success = False

        return success


@app.command("list")
def list_cards(
    env_file: Annotated[Path, typer.Option(help="Path to .env file")] = Path(".env"),
    cards_dir: Annotated[Path, typer.Option(help="Path to cards directory")] = Path(
        "soc_agent/tools/chatops"
    ),
):
    """List available ChatOps card test scripts."""
    manager = ChatOpsManager(env_file)
    cards = manager.list_cards(cards_dir)
    if cards:
        typer.secho("\nAvailable ChatOps Test Cards:", fg=typer.colors.BLUE, bold=True)
        for i, card in enumerate(cards, 1):
            color = typer.colors.CYAN if card.endswith(".py") else typer.colors.YELLOW
            typer.echo(f" {i:2d}. {typer.style(card, fg=color)}")
        typer.echo("\n(Cyan = Python, Yellow = Shell fallback)")
    else:
        typer.echo(f"No cards found in {cards_dir}")


@app.command("test")
def test_card(
    card_name: str,
    env_file: Annotated[Path, typer.Option(help="Path to .env file")] = Path(".env"),
    cards_dir: Annotated[Path, typer.Option(help="Path to cards directory")] = Path(
        "soc_agent/tools/chatops"
    ),
):
    """Execute a specific ChatOps card script to test delivery."""
    manager = ChatOpsManager(env_file)
    manager.test_card(card_name, cards_dir)


@app.command("deploy")
def deploy(
    env_file: Annotated[Path, typer.Option(help="Path to .env file")] = Path(".env"),
    func_dir: Annotated[Path, typer.Option(help="Path to function source")] = Path(
        "functions_python"
    ),
    lang: Annotated[str, typer.Option(help="Language (python/node)")] = "python",
    service: Annotated[str, typer.Option(help="Service prefix name")] = "chatops",
):
    """Deploy the backend Cloud Functions for handling card button clicks."""
    manager = ChatOpsManager(env_file)
    manager.deploy_backend(func_dir, lang, service)


if __name__ == "__main__":
    app()
