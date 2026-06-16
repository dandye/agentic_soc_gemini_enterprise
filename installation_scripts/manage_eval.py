#!/usr/bin/env python3
"""
Evaluation Management CLI for Security Operations Agents

This script handles systematic evaluation runs against deployed cloud agents
using the structured evaluation sets in evalsets/, logs each run in a structured
local ledger under eval_runs/, and provides regression and trajectory diffing tools.
All outputs are strictly plain text (no emojis or unicode symbols).
"""

import asyncio
import hashlib
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
import vertexai
from dotenv import load_dotenv
from vertexai import agent_engines


app = typer.Typer(
    add_completion=False,
    help="Manage and run evaluations for the Google MCP Security Agent.",
)


class EvaluationRunner:
    """Runs systematic evaluations and manages the evaluation ledger."""

    def __init__(self, env_file: Path):
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project_id = self.env_vars.get("GCP_PROJECT_ID")
        self.location = self.env_vars.get("GCP_LOCATION", "us-central1")

        if self.project_id:
            vertexai.init(project=self.project_id, location=self.location)

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from .env."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        return dict(os.environ)

    def _get_git_metadata(self) -> dict:
        """Gather current git repository metadata for ledger tracking."""
        try:
            commit = (
                subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .strip()
            )
            branch = (
                subprocess.check_output(
                    ["git", "branch", "--show-current"], stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .strip()
            )
            status = (
                subprocess.check_output(
                    ["git", "status", "--porcelain"], stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .strip()
            )
            is_dirty = len(status) > 0

            # Submodule tracking for runbooks
            submodules = {}
            try:
                sub_out = (
                    subprocess.check_output(
                        ["git", "submodule", "status"], stderr=subprocess.DEVNULL
                    )
                    .decode("utf-8")
                    .strip()
                )
                for line in sub_out.split("\n"):
                    if not line:
                        continue
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        commit_hash = parts[0].strip("+- ")
                        path = parts[1]
                        submodules[path] = commit_hash
            except Exception:
                # Submodule lookup failed or not a git repository
                return submodules

            return {
                "commit": commit,
                "branch": branch,
                "dirty": is_dirty,
                "submodules": submodules,
            }
        except Exception:
            return {
                "commit": "unknown",
                "branch": "unknown",
                "dirty": False,
                "submodules": {},
            }

    def _get_file_hash(self, file_path: Path) -> str:
        """Calculate the MD5 hash of a database file for grounding tracking."""
        if not file_path.exists():
            return "not_found"
        try:
            hash_md5 = hashlib.md5(usedforsecurity=False)
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return "error"

    def _get_agent_resource(self, evalset_id: str) -> str | None:
        """Resolve the deployed agent resource name based on the evalset ID."""
        if evalset_id == "cti_research":
            return self.env_vars.get("CTI_RESEARCHER_AGENT_RESOURCE_NAME")
        elif evalset_id == "detection_engineering":
            return self.env_vars.get("DETECTION_ENGINEER_AGENT_RESOURCE_NAME")
        elif evalset_id == "threat_hunting":
            return self.env_vars.get("THREAT_HUNTER_AGENT_RESOURCE_NAME")
        elif evalset_id == "incident_response":
            return self.env_vars.get("TIER2_AGENT_RESOURCE_NAME")
        elif evalset_id == "tier1_triage":
            return self.env_vars.get("AGENT_ENGINE_RESOURCE_NAME")  # Orchestrator
        elif evalset_id == "soc_basic":
            return self.env_vars.get("AGENT_ENGINE_RESOURCE_NAME")  # Orchestrator
        elif evalset_id == "multi_specialist":
            return self.env_vars.get("AGENT_ENGINE_RESOURCE_NAME")  # Orchestrator
        return None

    async def _async_run_case(
        self,
        remote_app,
        query: str,
        reference: dict,
        verbose: bool = False,
    ) -> dict:
        """Execute a single evaluation case and return evaluation results."""
        user_id = "eval_user"
        session = await remote_app.async_create_session(user_id=user_id)
        session_id = session.get("id")

        typer.echo(f"  Session ID: {session_id}")

        events = []
        tool_calls = []
        final_response = ""

        # Stream query execution
        async for event in remote_app.async_stream_query(
            user_id=user_id, session_id=session_id, message=query
        ):
            events.append(event)

            # Check for tool calls or sub-agent events
            if "content" in event and "parts" in event["content"]:
                for part in event["content"]["parts"]:
                    if "function_call" in part:
                        tool_name = part["function_call"]["name"]
                        tool_calls.append(tool_name)
                        typer.secho(
                            f"    [Tool Call] {tool_name}", fg=typer.colors.YELLOW
                        )
                    elif "text" in part and verbose:
                        typer.echo(f"    [Thought] {part['text']}")

            # Capture final response text
            if event.get("role") == "model" and "content" in event:
                for part in event["content"].get("parts", []):
                    if "text" in part:
                        final_response += part["text"]

        # If final_response is still empty, look in the last few event payloads
        if not final_response and events:
            for event in reversed(events):
                if "content" in event and "parts" in event["content"]:
                    for part in event["content"]["parts"]:
                        if "text" in part:
                            final_response += part["text"]

        # Evaluate assertions
        expected_specialist = reference.get("expected_specialist")
        expected_tools = reference.get("tool_trajectory", [])
        must_contain = reference.get("final_response_must_contain", [])
        success_criteria = reference.get("success_criteria", {})

        results = {
            "query": query,
            "response": final_response,
            "tool_calls": tool_calls,
            "assertions": {},
            "score": 0.0,
        }

        # Assertion 1: Specialist Attribution
        if expected_specialist:
            attributed = False
            specialist_clean = expected_specialist.replace("_", " ").lower()
            if (
                specialist_clean in final_response.lower()
                or expected_specialist.lower() in final_response.lower()
            ):
                attributed = True
            elif expected_specialist == "orchestrator_direct":
                attributed = True

            results["assertions"]["specialist_attribution"] = attributed

        # Assertion 2: Tool Trajectory Coverage
        tools_passed = True
        for expected_tool in expected_tools:
            if expected_tool not in tool_calls:
                tools_passed = False
                break
        results["assertions"]["tool_trajectory"] = tools_passed

        # Assertion 3: Mandatory Keyword Content Match
        keywords_passed = True
        for keyword in must_contain:
            if keyword.lower() not in final_response.lower():
                keywords_passed = False
                break
        results["assertions"]["keyword_matching"] = keywords_passed

        # Assertion 4: Success Criteria Checklist
        criteria_results = {}
        for criterion, value in success_criteria.items():
            passed = False
            if (
                criterion == "has_grounding_citation"
                or criterion == "includes_source_attribution"
            ):
                passed = (
                    "[" in final_response
                    or "source" in final_response.lower()
                    or "document" in final_response.lower()
                )
            elif (
                criterion == "specialist_attribution"
                or criterion == "mentions_cti_researcher"
            ):
                passed = results["assertions"].get("specialist_attribution", False)
            elif criterion == "tool_name_mentioned":
                passed = len(tool_calls) > 0 or any(
                    t in final_response for t in expected_tools
                )
            elif criterion == "provides_verdict":
                passed = any(
                    w in final_response.lower()
                    for w in ["malicious", "clean", "suspicious", "safe", "verdict"]
                )
            else:
                passed = len(final_response) > 50

            criteria_results[criterion] = passed

        results["assertions"]["success_criteria"] = criteria_results

        # Calculate score (percentage of passed assertions)
        total_assertions = len(results["assertions"]) - 1 + len(criteria_results)
        passed_assertions = sum(
            1 for v in results["assertions"].values() if isinstance(v, bool) and v
        )
        passed_assertions += sum(1 for v in criteria_results.values() if v)

        results["score"] = (
            passed_assertions / total_assertions if total_assertions > 0 else 1.0
        )

        return results

    def run_evaluation(
        self,
        evalset_path: Path,
        resource_name: str | None = None,
        verbose: bool = False,
    ):
        """Load the evalset and execute all cases against the agent."""
        if not evalset_path.exists():
            typer.secho(
                f"[ERROR] Evalset file not found: {evalset_path}", fg=typer.colors.RED
            )
            raise typer.Exit(1)

        with open(evalset_path) as f:
            evalset = json.load(f)

        evalset_id = evalset.get("evalset_id", "unknown")
        name = evalset.get("name", "Unknown Evaluation Set")
        eval_cases = evalset.get("eval_cases", [])

        typer.echo("\n" + "=" * 80)
        typer.secho(f"Running Evaluation Set: {name}", fg=typer.colors.BLUE, bold=True)
        typer.echo(f"Description: {evalset.get('description', '')}")
        typer.echo(f"Total Cases: {len(eval_cases)}")
        typer.echo("=" * 80 + "\n")

        # Resolve agent resource
        agent_resource = resource_name or self._get_agent_resource(evalset_id)
        if not agent_resource:
            typer.secho(
                f"[ERROR] Could not resolve agent resource name for evalset '{evalset_id}'. "
                "Please make sure it is set in .env or passed via --resource.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)

        typer.secho(
            f"Connecting to live Agent Engine:\n  {agent_resource}\n",
            fg=typer.colors.CYAN,
        )
        remote_app = agent_engines.get(agent_resource)

        case_results = []
        for i, case in enumerate(eval_cases, start=1):
            eval_id = case.get("eval_id", f"case_{i}")
            case_name = case.get("name", f"Case {i}")

            # Extract query from conversation
            conversation = case.get("conversation", [])
            query = ""
            for turn in conversation:
                if turn.get("role") == "user":
                    query = turn.get("content", "")
                    break

            reference = case.get("reference", {})

            typer.secho(
                f"[{i}/{len(eval_cases)}] Running Case: {case_name} ({eval_id})",
                fg=typer.colors.BLUE,
                bold=True,
            )
            typer.echo(f"  Query: {query}")

            # Run case async
            result = asyncio.run(
                self._async_run_case(remote_app, query, reference, verbose)
            )
            case_results.append((eval_id, case_name, result))

            # Report case result
            score_pct = result["score"] * 100
            if score_pct >= 80:
                fg_color = typer.colors.GREEN
            elif score_pct >= 50:
                fg_color = typer.colors.YELLOW
            else:
                fg_color = typer.colors.RED

            typer.secho(f"  Case Score: {score_pct:.1f}%\n", fg=fg_color, bold=True)

        # Print final scorecard
        typer.echo("\n" + "=" * 80)
        typer.secho("EVALUATION SCORECARD", fg=typer.colors.GREEN, bold=True)
        typer.echo("=" * 80)

        total_score = 0.0
        for eval_id, case_name, res in case_results:
            score_pct = res["score"] * 100
            status_char = (
                "[PASS]"
                if score_pct >= 80
                else "[WARN]"
                if score_pct >= 50
                else "[FAIL]"
            )
            status_color = (
                typer.colors.GREEN
                if score_pct >= 80
                else typer.colors.YELLOW
                if score_pct >= 50
                else typer.colors.RED
            )

            typer.echo("  ")
            typer.secho(
                f"{status_char:<8} {case_name:<45} {score_pct:>5.1f}%", fg=status_color
            )
            total_score += res["score"]

        avg_score = (total_score / len(eval_cases)) * 100 if eval_cases else 0.0
        typer.echo("-" * 80)

        final_color = (
            typer.colors.GREEN
            if avg_score >= 85
            else typer.colors.YELLOW
            if avg_score >= 70
            else typer.colors.RED
        )
        typer.echo("  ")
        typer.secho(
            f"OVERALL EVALUATION SCORE: {avg_score:.1f}%", fg=final_color, bold=True
        )
        typer.echo("=" * 80 + "\n")

        # Get git metadata, timestamp, and commit hash once
        git_meta = self._get_git_metadata()
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        commit_short = git_meta["commit"][:7]

        # Save markdown report directly in the local runs directory
        self._save_report_artifact(
            evalset_id, name, avg_score, case_results, timestamp, commit_short
        )

        # Write structured JSON run to Local Ledger
        self._write_to_ledger(
            evalset_id,
            agent_resource,
            eval_cases,
            case_results,
            avg_score,
            git_meta,
            timestamp,
            commit_short,
        )

    def _write_to_ledger(
        self,
        evalset_id: str,
        agent_resource: str,
        eval_cases: list,
        case_results: list,
        avg_score: float,
        git_meta: dict,
        timestamp: str,
        commit_short: str,
    ):
        """Write a structured JSON summary of the evaluation run to the local ledger."""
        kg_path = Path("harvested_investigations/knowledge_graph.json")

        run_data = {
            "metadata": {
                "evalset_id": evalset_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "git": git_meta,
                "environment": {
                    "project_id": self.project_id,
                    "location": self.location,
                    "orchestrator_model": self.env_vars.get(
                        "ORCHESTRATOR_MODEL", "gemini-3.1-pro-preview"
                    ),
                    "agent_resource": agent_resource,
                    "knowledge_graph_hash": self._get_file_hash(kg_path),
                },
            },
            "summary": {
                "total_cases": len(eval_cases),
                "average_score": avg_score,
                "status": "PASS"
                if avg_score >= 85.0
                else "WARNING"
                if avg_score >= 70.0
                else "FAIL",
            },
            "cases": {},
        }

        for eval_id, case_name, res in case_results:
            run_data["cases"][eval_id] = {
                "name": case_name,
                "score": res["score"],
                "tool_calls": res["tool_calls"],
                "assertions_passed": [
                    k for k, v in res["assertions"].items() if isinstance(v, bool) and v
                ],
                "assertions_failed": [
                    k
                    for k, v in res["assertions"].items()
                    if isinstance(v, bool) and not v
                ],
            }
            sc = res["assertions"].get("success_criteria", {})
            run_data["cases"][eval_id]["success_criteria_passed"] = [
                k for k, v in sc.items() if v
            ]
            run_data["cases"][eval_id]["success_criteria_failed"] = [
                k for k, v in sc.items() if not v
            ]

        runs_dir = Path("evalsets/eval_runs")
        runs_dir.mkdir(exist_ok=True)
        run_file = runs_dir / f"run_{evalset_id}_{timestamp}_{commit_short}.json"

        with open(run_file, "w") as f:
            json.dump(run_data, f, indent=2)

        typer.secho(
            f"[SUCCESS] Saved structured run ledger to:\n  {run_file}\n",
            fg=typer.colors.GREEN,
        )

    def _save_report_artifact(
        self,
        evalset_id: str,
        evalset_name: str,
        avg_score: float,
        case_results: list,
        timestamp: str,
        commit_short: str,
    ):
        """Save a premium markdown evaluation report in the local runs directory."""
        runs_dir = Path("evalsets/eval_runs")
        runs_dir.mkdir(exist_ok=True)

        report_path = runs_dir / f"report_{evalset_id}_{timestamp}_{commit_short}.md"

        md_content = f"""---
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "{datetime.utcnow().isoformat() + 'Z'}"
---
# Evaluation Report: {evalset_name}

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** {evalset_name}
* **Overall Score:** **{avg_score:.1f}%**
* **Status:** {"PASS" if avg_score >= 85.0 else "WARNING" if avg_score >= 70.0 else "FAIL"}

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
"""
        for eval_id, case_name, res in case_results:
            status = (
                "[PASS]"
                if res["score"] >= 0.8
                else "[WARNING]"
                if res["score"] >= 0.5
                else "[FAIL]"
            )
            tools_called = ", ".join([f"`{t}`" for t in res["tool_calls"]]) or "*None*"
            assertions_passed = []
            for k, v in res["assertions"].items():
                if k == "success_criteria":
                    for ck, cv in v.items():
                        if cv:
                            assertions_passed.append(ck)
                elif v:
                    assertions_passed.append(k)

            md_content += f"| {status} | **{case_name}** | {res['score']*100:.1f}% | {tools_called} | {', '.join(assertions_passed)} |\n"

        md_content += "\n---\n\n## Detailed Case Runs\n\n"

        for i, (eval_id, case_name, res) in enumerate(case_results, start=1):
            md_content += f"""### Case {i}: {case_name} ({eval_id})

* **User Query:** "{res['query']}"
* **Score:** **{res['score']*100:.1f}%**

#### Tool Trajectory
{chr(10).join([f'* Called tool: `{t}`' for t in res['tool_calls']]) or '*No tools called.*'}

#### Heuristic Success Checklist
"""
            for k, v in res["assertions"].items():
                if k == "success_criteria":
                    for ck, cv in v.items():
                        md_content += f"* {'[X]' if cv else '[ ]'} **{ck}**\n"
                else:
                    md_content += f"* {'[X]' if v else '[ ]'} **{k}**\n"

            md_content += f"""
#### Model Final Response
```markdown
{res['response'].strip()}
```

---
"""

        with open(report_path, "w") as f:
            f.write(md_content)

        typer.secho(
            f"[SUCCESS] Saved detailed evaluation report to:\n  {report_path}\n",
            fg=typer.colors.GREEN,
        )


def _save_compare_report(
    evalset_id: str,
    base_name: str,
    new_name: str,
    base_score: float,
    new_score: float,
    delta_str: str,
    trajectory_changes: list,
    submodule_changes: list,
    base_commit: str,
    new_commit: str,
):
    """Save a premium markdown comparison report to the local runs directory."""
    runs_dir = Path("evalsets/eval_runs")
    runs_dir.mkdir(exist_ok=True)
    report_path = runs_dir / f"compare_{evalset_id}.md"

    changelog_md = "*No commits between these runs (same codebase).*"
    if (
        base_commit != "unknown"
        and new_commit != "unknown"
        and base_commit != new_commit
    ):
        try:
            changelog_raw = (
                subprocess.check_output(
                    ["git", "log", f"{base_commit}..{new_commit}", "--oneline"],
                    stderr=subprocess.DEVNULL,
                )
                .decode("utf-8")
                .strip()
            )
            if changelog_raw:
                changelog_md = "\n".join(
                    [f"* {line}" for line in changelog_raw.split("\n")]
                )
        except Exception:
            changelog_md = "*Could not extract changelog.*"

    trajectory_md = (
        "\n".join(trajectory_changes)
        if trajectory_changes
        else "*No changes in tool trajectories between these runs.*"
    )
    grounding_md = (
        "\n".join(submodule_changes)
        if submodule_changes
        else "*No changes in database grounding or runbooks between these runs.*"
    )

    md_content = f"""---
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "{datetime.utcnow().isoformat() + 'Z'}"
---
# Evaluation Comparison Report: {evalset_id}

> [!NOTE]
> This comparison was compiled automatically by diffing two structured evaluation ledgers and extracting the Git commit delta.

## Executive Summary

* **Evalset ID:** `{evalset_id}`
* **Baseline Run:** `{base_name}` (Score: **{base_score:.1f}%**)
* **New Run:** `{new_name}` (Score: **{new_score:.1f}%**)
* **Performance Delta:** **{delta_str}**

---

## Tool Trajectory Changes

{trajectory_md}

---

## Grounding & Database Changes

{grounding_md}

---

## Git Changelog Between Runs

{changelog_md}

---

## Next Steps
Use this log to correlate codebase modifications directly to prompt performance and tool-use behaviors.
"""
    with open(report_path, "w") as f:
        f.write(md_content)

    typer.secho(
        f"[SUCCESS] Saved detailed comparison report to:\n  {report_path}\n",
        fg=typer.colors.GREEN,
    )


@app.command("run")
def run(
    evalset_file: Annotated[
        Path, typer.Option("--file", "-f", help="Path to the evalset JSON file")
    ],
    resource: Annotated[
        str, typer.Option("--resource", "-r", help="Optional cloud agent resource name")
    ] = None,
    env_file: Annotated[
        Path, typer.Option("--env-file", "-e", help="Path to .env file")
    ] = Path(".env"),
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose", "-v", help="Print verbose intermediate thought events"
        ),
    ] = False,
) -> None:
    """Run systematic evaluations using evalsets against deployed cloud agents."""
    runner = EvaluationRunner(env_file)
    runner.run_evaluation(evalset_file, resource, verbose)


@app.command("compare")
def compare(
    evalset_id: str = typer.Argument(..., help="The ID of the evalset to compare"),
    base: Annotated[
        Path, typer.Option("--base", "-b", help="Path to specific baseline run JSON")
    ] = None,
    new: Annotated[
        Path, typer.Option("--new", "-n", help="Path to specific new run JSON")
    ] = None,
) -> None:
    """Compare evaluation scores, trajectories, and extract git changelog between runs."""
    runs_dir = Path("evalsets/eval_runs")
    if not runs_dir.exists() or not list(runs_dir.glob(f"run_{evalset_id}_*.json")):
        typer.secho(
            f"[ERROR] No evaluation runs found for evalset '{evalset_id}' in evalsets/eval_runs/",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    if base and new:
        base_path = base
        new_path = new
    else:
        matching_runs = sorted(runs_dir.glob(f"run_{evalset_id}_*.json"))
        if len(matching_runs) < 2:
            typer.secho(
                f"[ERROR] Need at least 2 runs to compare. Only found 1: {matching_runs[0].name}",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)
        base_path = matching_runs[-2]
        new_path = matching_runs[-1]

    typer.echo("\n" + "=" * 80)
    typer.secho(
        f"COMPARING RUNS FOR EVALSET: {evalset_id}", fg=typer.colors.BLUE, bold=True
    )
    typer.echo(f"  Baseline Run: {base_path.name}")
    typer.echo(f"  New Run:      {new_path.name}")
    typer.echo("=" * 80 + "\n")

    with open(base_path) as f:
        base_data = json.load(f)
    with open(new_path) as f:
        new_data = json.load(f)

    base_score = base_data["summary"]["average_score"]
    new_score = new_data["summary"]["average_score"]
    delta = new_score - base_score
    delta_str = f"+{delta:.1f}%" if delta > 0 else f"{delta:.1f}%"
    delta_color = (
        typer.colors.GREEN
        if delta > 0
        else typer.colors.RED
        if delta < 0
        else typer.colors.WHITE
    )

    typer.echo("OVERALL PERFORMANCE COMPARISON:")
    typer.echo(f"  Baseline Score: {base_score:.1f}%")
    typer.echo(f"  New Score:      {new_score:.1f}%")
    typer.echo("  Delta:          ", nl=False)
    typer.secho(f"{delta_str}", fg=delta_color, bold=True)
    typer.echo("-" * 80)

    typer.echo("\nCASE SCORECARD DELTA:")
    base_cases = base_data.get("cases", {})
    new_cases = new_data.get("cases", {})

    trajectory_changes = []

    for case_id, new_case_details in new_cases.items():
        case_name = new_case_details.get("name", case_id)
        n_score = new_case_details.get("score", 0.0) * 100

        b_case = base_cases.get(case_id, {})
        b_score = b_case.get("score", 0.0) * 100

        c_delta = n_score - b_score
        c_delta_str = f"+{c_delta:.1f}%" if c_delta > 0 else f"{c_delta:.1f}%"
        c_delta_color = (
            typer.colors.GREEN
            if c_delta > 0
            else typer.colors.RED
            if c_delta < 0
            else typer.colors.WHITE
        )

        typer.echo(
            f"  {case_name:<45} {b_score:>5.1f}% -> {n_score:>5.1f}% (", nl=False
        )
        typer.secho(f"{c_delta_str:<7}", fg=c_delta_color, nl=False)
        typer.echo(")")

        b_tools = b_case.get("tool_calls", [])
        n_tools = new_case_details.get("tool_calls", [])

        added_tools = [t for t in n_tools if t not in b_tools]
        removed_tools = [t for t in b_tools if t not in n_tools]

        if added_tools:
            trajectory_changes.append(
                f"  [ADDED] {case_name}: Added tool calls: {', '.join([f'`{t}`' for t in added_tools])}"
            )
        if removed_tools:
            trajectory_changes.append(
                f"  [REMOVED] {case_name}: Stopped calling: {', '.join([f'`{t}`' for t in removed_tools])}"
            )

    if trajectory_changes:
        typer.echo("\n" + "-" * 80)
        typer.echo("TOOL TRAJECTORY CHANGES:")
        for tc in trajectory_changes:
            typer.echo(tc)

    # Compare grounding database states and runbooks submodules
    base_subs = base_data["metadata"]["git"].get("submodules", {})
    new_subs = new_data["metadata"]["git"].get("submodules", {})

    sub_changes = []
    for path, new_commit_hash in new_subs.items():
        base_commit_hash = base_subs.get(path, "unknown")
        if base_commit_hash != new_commit_hash:
            sub_changes.append(
                f"  [CHANGED] Grounding Runbooks (`{path}`): {base_commit_hash[:7]} -> {new_commit_hash[:7]}"
            )

    base_kg = base_data["metadata"]["environment"].get(
        "knowledge_graph_hash", "unknown"
    )
    new_kg = new_data["metadata"]["environment"].get("knowledge_graph_hash", "unknown")
    if base_kg != new_kg:
        sub_changes.append(
            "  [CHANGED] Threat Graph telemetry (`knowledge_graph.json`) was modified."
        )

    if sub_changes:
        typer.echo("\n" + "-" * 80)
        typer.secho("GROUNDING & DATABASE CHANGES:", fg=typer.colors.CYAN, bold=True)
        for sc in sub_changes:
            typer.echo(sc)

    base_commit = base_data["metadata"]["git"].get("commit", "unknown")
    new_commit = new_data["metadata"]["git"].get("commit", "unknown")

    if (
        base_commit != "unknown"
        and new_commit != "unknown"
        and base_commit != new_commit
    ):
        typer.echo("\n" + "-" * 80)
        typer.secho("GIT CHANGELOG BETWEEN RUNS:", fg=typer.colors.CYAN, bold=True)
        try:
            changelog = (
                subprocess.check_output(
                    ["git", "log", f"{base_commit}..{new_commit}", "--oneline"],
                    stderr=subprocess.DEVNULL,
                )
                .decode("utf-8")
                .strip()
            )
            if changelog:
                typer.echo(changelog)
            else:
                typer.echo("  No commits between these runs (same codebase).")
        except Exception as e:
            typer.echo(f"  Could not extract changelog: {e}")
    else:
        typer.echo("\n" + "-" * 80)
        typer.echo("  No codebase changes detected between runs (same git commit).")

    typer.echo("=" * 80 + "\n")

    _save_compare_report(
        evalset_id,
        base_path.name,
        new_path.name,
        base_score,
        new_score,
        delta_str,
        trajectory_changes,
        sub_changes,
        base_commit,
        new_commit,
    )


if __name__ == "__main__":
    app()
