#!/usr/bin/env python3
"""
Legacy environment-variable aliasing and migration for the Gemini Enterprise
rebrand (issue #36).

AgentSpace is now Gemini Enterprise, so the AGENTSPACE_* variables were
renamed to GEM_ENT_*. Existing .env files must keep working, so:

  * `apply_legacy_env_aliases` fills any unset new-style variable from its
    legacy counterpart at load time. Every manager's `_load_env_vars` calls
    it, which is why the rename needed one seam rather than 45 edits.
  * `manage.py env migrate` rewrites a .env in place, renaming legacy keys
    and leaving a backup.

Precedence: an explicitly-set new-style variable always wins over a legacy
one, so a half-migrated .env resolves to the new value.
"""

import os
import shutil
from pathlib import Path
from typing import Annotated

import typer


# new canonical name -> legacy name it replaced
LEGACY_ENV_ALIASES: dict[str, str] = {
    "GEM_ENT_APP_ID": "AGENTSPACE_APP_ID",
    "GEM_ENT_AGENT_ID": "AGENTSPACE_AGENT_ID",
    "GEM_ENT_ALLOYDB_AGENT_ID": "AGENTSPACE_ALLOYDB_AGENT_ID",
    "GEM_ENT_COLLECTION": "AGENTSPACE_COLLECTION",
    "GEM_ENT_ASSISTANT": "AGENTSPACE_ASSISTANT",
}

# reverse lookup for migration
LEGACY_TO_CANONICAL: dict[str, str] = {v: k for k, v in LEGACY_ENV_ALIASES.items()}


def apply_legacy_env_aliases(env_vars: dict) -> list[str]:
    """
    Fill unset canonical variables from their legacy counterparts, in place.

    Args:
        env_vars: Mutable mapping of environment variables.

    Returns:
        Sorted list of legacy variable names that were relied on, so callers
        can surface a deprecation hint. Empty when the environment is clean.
    """
    used_legacy = []
    for canonical, legacy in LEGACY_ENV_ALIASES.items():
        if not env_vars.get(canonical) and env_vars.get(legacy):
            env_vars[canonical] = env_vars[legacy]
            used_legacy.append(legacy)
    return sorted(used_legacy)


def legacy_deprecation_notice(used_legacy: list[str]) -> str:
    """Human-readable nudge for callers that relied on legacy names."""
    if not used_legacy:
        return ""
    names = ", ".join(used_legacy)
    return (
        f"Note: using legacy environment variable(s): {names}. "
        "These still work; run 'python manage.py env migrate' to rename them."
    )


def find_legacy_vars(env_file: Path) -> dict[str, str]:
    """Return {legacy_name: canonical_name} for legacy keys present in a .env."""
    if not env_file.is_file():
        return {}
    found = {}
    for raw in env_file.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key in LEGACY_TO_CANONICAL:
            found[key] = LEGACY_TO_CANONICAL[key]
    return found


def migrate_env_file(env_file: Path, dry_run: bool = False) -> tuple[dict, Path | None]:
    """
    Rename legacy keys in a .env file to their canonical names.

    Comments, ordering, blank lines, and values are preserved; only the key
    token on matching assignment lines changes. A .bak copy is written first.

    Returns:
        (mapping of renamed keys, path to the backup file or None)
    """
    found = find_legacy_vars(env_file)
    if not found or dry_run:
        return found, None

    backup = env_file.with_suffix(env_file.suffix + ".bak")
    shutil.copy2(env_file, backup)

    out = []
    for raw in env_file.read_text().splitlines(keepends=True):
        stripped = raw.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _, rest = raw.partition("=")
            if key.strip() in found:
                raw = f"{key.replace(key.strip(), found[key.strip()])}={rest}"
        out.append(raw)
    env_file.write_text("".join(out))
    return found, backup


def resolve(name: str, default: str | None = None) -> str | None:
    """
    Read a canonical variable from os.environ, falling back to its legacy name.

    For call sites that read os.environ directly rather than a loaded dict.
    """
    value = os.environ.get(name)
    if value:
        return value
    legacy = LEGACY_ENV_ALIASES.get(name)
    if legacy:
        return os.environ.get(legacy, default)
    return default


app = typer.Typer(
    name="env",
    help="Inspect and migrate environment variable names",
    no_args_is_help=True,
)


@app.command("check")
def check_command(
    env_file: Annotated[
        Path, typer.Option("--env-file", help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Report legacy environment variable names present in a .env file."""
    found = find_legacy_vars(env_file)
    if not env_file.is_file():
        typer.secho(f"No such file: {env_file}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    if not found:
        typer.secho(
            f"{env_file}: no legacy variable names found.", fg=typer.colors.GREEN
        )
        return
    typer.secho(
        f"{env_file}: {len(found)} legacy variable name(s):", fg=typer.colors.YELLOW
    )
    for legacy, canonical in sorted(found.items()):
        typer.echo(f"  {legacy}  ->  {canonical}")
    typer.echo("\nThese still work. Run 'manage.py env migrate' to rename them.")


@app.command("migrate")
def migrate_command(
    env_file: Annotated[
        Path, typer.Option("--env-file", help="Path to the environment file.")
    ] = Path(".env"),
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would change without writing.")
    ] = False,
) -> None:
    """Rename legacy environment variable names to their canonical form."""
    if not env_file.is_file():
        typer.secho(f"No such file: {env_file}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    found, backup = migrate_env_file(env_file, dry_run=dry_run)
    if not found:
        typer.secho(f"{env_file}: nothing to migrate.", fg=typer.colors.GREEN)
        return
    verb = "Would rename" if dry_run else "Renamed"
    for legacy, canonical in sorted(found.items()):
        typer.echo(f"  {verb}: {legacy} -> {canonical}")
    if dry_run:
        typer.echo("\nDry run; no changes written.")
    else:
        typer.secho(
            f"\nMigrated {len(found)} variable(s). Backup: {backup}",
            fg=typer.colors.GREEN,
        )


if __name__ == "__main__":
    app()
