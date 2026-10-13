#!/usr/bin/env python3
"""
Ambient Quality Agent (AQuA) Sidecar & Snapshot Manager.

Provides CLI lifecycle commands (`init`, `deploy`, `run`, `ui`, `snapshot`,
`promote-insight`) and versioned source code snapshot generation (`Revision N`)
so AQuA outer-loop diagnostics always correlate production trajectories against
the exact deployed codebase snapshot.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Annotated, Any

from dotenv import load_dotenv
import typer

from installation_scripts.provenance_helper import write_stripped_goal_file

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_GOAL_PATH = REPO_ROOT / "docs" / "aqua_goal.md"
DEFAULT_EVAL_CONFIG = "aqua/eval_config.yaml"
DEFAULT_SNAPSHOT_ROOT = REPO_ROOT / "aqua" / "snapshots"

app = typer.Typer(
    name="aqua",
    help="Manage the Ambient Quality Agent (AQuA) outer-loop diagnostic sidecar.",
    add_completion=False,
    no_args_is_help=True,
)


def build_aqua_init_command(
    monitored_agent_id: str,
    agent_source_dir: str = "./agent_soc_manager",
    agent_goal_file: str | None = None,
) -> list[str]:
    """Build the `aqua init` command list with a frontmatter-stripped goal file."""
    if not monitored_agent_id:
        raise ValueError("monitored_agent_id is required for aqua init")
    goal_file_arg = agent_goal_file
    if goal_file_arg is None:
        stripped_path = write_stripped_goal_file(DEFAULT_GOAL_PATH)
        goal_file_arg = str(stripped_path)
    return [
        "aqua",
        "init",
        "--monitored-agent-id",
        monitored_agent_id,
        "--agent-source-dir",
        agent_source_dir,
        "--agent-goal-file",
        goal_file_arg,
    ]


def build_aqua_deploy_command(extra_args: list[str] | None = None) -> list[str]:
    """Build the `aqua deploy` command list."""
    cmd = ["aqua", "deploy"]
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def build_aqua_run_command(
    start_time: str = "-24h",
    eval_config: str = DEFAULT_EVAL_CONFIG,
    end_time: str | None = None,
) -> list[str]:
    """Build the `aqua run` command list."""
    cmd = [
        "aqua",
        "run",
        "--start-time",
        start_time,
        "--eval-config",
        eval_config,
    ]
    if end_time:
        cmd.extend(["--end-time", end_time])
    return cmd


def build_aqua_ui_command() -> list[str]:
    """Build the `aqua ui` command list."""
    return ["aqua", "ui"]


def _get_git_commit(repo_root: Path) -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "unknown"


def create_source_snapshot(
    agent_module: str = "agent_soc_manager",
    snapshot_root: Path | str | None = None,
    repo_root: Path | str | None = None,
) -> dict[str, Any]:
    """Package a versioned source code snapshot (`Revision N`) for AQuA citation grounding."""
    root = Path(repo_root) if repo_root is not None else REPO_ROOT
    snap_base = (
        Path(snapshot_root) if snapshot_root is not None else DEFAULT_SNAPSHOT_ROOT
    )
    snap_base.mkdir(parents=True, exist_ok=True)

    existing_revs: list[int] = []
    for child in snap_base.iterdir():
        if child.is_dir() and child.name.startswith("rev_"):
            suffix = child.name.removeprefix("rev_")
            if suffix.isdigit():
                existing_revs.append(int(suffix))
    next_rev = (max(existing_revs) + 1) if existing_revs else 1
    rev_dir = snap_base / f"rev_{next_rev}"
    rev_dir.mkdir(parents=True, exist_ok=True)

    module_dir = root / agent_module
    files_manifest: dict[str, dict[str, Any]] = {}
    if module_dir.exists():
        for src_file in sorted(module_dir.rglob("*")):
            if src_file.is_dir():
                continue
            if "__pycache__" in src_file.parts or src_file.suffix in (".pyc", ".pyo"):
                continue
            rel_path = src_file.relative_to(root).as_posix()
            dst_file = rev_dir / rel_path
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dst_file)
            try:
                line_count = len(
                    src_file.read_text(encoding="utf-8", errors="replace").splitlines()
                )
            except Exception:
                line_count = 0
            files_manifest[rel_path] = {
                "line_count": line_count,
                "size_bytes": src_file.stat().st_size,
            }

    manifest = {
        "revision": next_rev,
        "revision_label": f"Revision {next_rev}",
        "agent_module": agent_module,
        "git_commit": _get_git_commit(root),
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "snapshot_dir": str(rev_dir),
        "files": files_manifest,
    }
    manifest_path = rev_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    latest_path = snap_base / "latest.json"
    latest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


@app.command("init")
def cli_init(
    monitored_agent_id: Annotated[
        str | None,
        typer.Option("--monitored-agent-id", help="Reasoning Engine ID or resource name."),
    ] = None,
    agent_source_dir: Annotated[
        str,
        typer.Option("--agent-source-dir", help="Agent source directory to monitor."),
    ] = "./agent_soc_manager",
    goal_file: Annotated[
        Path,
        typer.Option("--goal-file", help="Path to OKF goal markdown file."),
    ] = DEFAULT_GOAL_PATH,
    env_file: Annotated[
        Path,
        typer.Option("--env-file", help="Path to .env file."),
    ] = Path(".env"),
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print command without executing."),
    ] = False,
) -> None:
    """Initialize AQuA sidecar configuration with stripped OKF goal file."""
    if env_file.exists():
        load_dotenv(env_file, override=False)
    agent_id = (
        monitored_agent_id
        or os.environ.get("AGENT_ENGINE_ID")
        or os.environ.get("AGENT_ENGINE_RESOURCE_NAME")
    )
    if not agent_id:
        typer.echo(
            "[FAIL] AGENT_ENGINE_ID or AGENT_ENGINE_RESOURCE_NAME must be set or passed via --monitored-agent-id."
        )
        raise typer.Exit(code=1)

    stripped_path = write_stripped_goal_file(goal_file)
    cmd = build_aqua_init_command(
        monitored_agent_id=agent_id,
        agent_source_dir=agent_source_dir,
        agent_goal_file=str(stripped_path),
    )
    typer.echo(f"[INFO] Stripped OKF frontmatter from {goal_file} -> {stripped_path}")
    typer.echo(f"[INFO] Command: {' '.join(cmd)}")
    if dry_run:
        return
    subprocess.run(cmd, check=True)


@app.command("deploy")
def cli_deploy(
    agent_module: Annotated[
        str,
        typer.Option("--agent-module", help="Agent module to snapshot before deploying AQuA."),
    ] = "agent_soc_manager",
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Create snapshot and print command without executing aqua CLI."),
    ] = False,
) -> None:
    """Create a versioned source code snapshot (Revision N) and deploy the AQuA sidecar."""
    manifest = create_source_snapshot(agent_module=agent_module)
    typer.echo(
        f"[PASS] Created source snapshot {manifest['revision_label']} ({len(manifest['files'])} files) at {manifest['snapshot_dir']}"
    )
    cmd = build_aqua_deploy_command()
    typer.echo(f"[INFO] Command: {' '.join(cmd)}")
    if dry_run:
        return
    subprocess.run(cmd, check=True)


@app.command("run")
def cli_run(
    start_time: Annotated[
        str,
        typer.Option("--start-time", help="Lookback start time (e.g. -24h)."),
    ] = "-24h",
    eval_config: Annotated[
        str,
        typer.Option("--eval-config", help="Path to AQuA eval_config.yaml."),
    ] = DEFAULT_EVAL_CONFIG,
    end_time: Annotated[
        str | None,
        typer.Option("--end-time", help="Optional end time."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print command without executing."),
    ] = False,
) -> None:
    """Trigger an AQuA outer-loop analysis run over production traces."""
    cmd = build_aqua_run_command(
        start_time=start_time, eval_config=eval_config, end_time=end_time
    )
    typer.echo(f"[INFO] Command: {' '.join(cmd)}")
    if dry_run:
        return
    subprocess.run(cmd, check=True)


@app.command("ui")
def cli_ui(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print command without executing."),
    ] = False,
) -> None:
    """Launch the AQuA visualization UI."""
    cmd = build_aqua_ui_command()
    typer.echo(f"[INFO] Command: {' '.join(cmd)}")
    if dry_run:
        return
    subprocess.run(cmd, check=True)


@app.command("snapshot")
def cli_snapshot(
    agent_module: Annotated[
        str,
        typer.Option("--agent-module", help="Agent module directory to snapshot."),
    ] = "agent_soc_manager",
) -> None:
    """Record a new versioned source code snapshot (Revision N)."""
    manifest = create_source_snapshot(agent_module=agent_module)
    typer.echo(
        f"[PASS] Recorded {manifest['revision_label']} for {agent_module} at {manifest['snapshot_dir']}"
    )


if __name__ == "__main__":
    app()
