#!/usr/bin/env python3
"""
Evaluation Management CLI for Security Operations Agents

This script handles systematic evaluation runs against deployed cloud agents
using the structured evaluation sets in evalsets/.
"""

import asyncio
import json
import os
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
    """Runs systematic evaluations against deployed cloud agents."""

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
                f"✗ Evalset file not found: {evalset_path}", fg=typer.colors.RED
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
                f"✗ Could not resolve agent resource name for evalset '{evalset_id}'. "
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
            status_char = "✓" if score_pct >= 80 else "⚠" if score_pct >= 50 else "✗"
            status_color = (
                typer.colors.GREEN
                if score_pct >= 80
                else typer.colors.YELLOW
                if score_pct >= 50
                else typer.colors.RED
            )

            typer.echo("  ")
            typer.secho(
                f"{status_char}  {case_name:<45} {score_pct:>5.1f}%", fg=status_color
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

        # Save markdown report artifact
        self._save_report_artifact(evalset_id, name, avg_score, case_results)

    def _save_report_artifact(
        self, evalset_id: str, evalset_name: str, avg_score: float, case_results: list
    ):
        """Save a premium markdown evaluation report as an artifact."""
        artifacts_dir = Path(
            "/Users/dandye/.gemini/jetski/brain/5a85dba2-4972-4b15-92b8-1afd3f5c9aad"
        )
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        report_path = artifacts_dir / f"evaluation_report_{evalset_id}.md"

        md_content = f"""---
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "{os.environ.get('TIMESTAMP', '2026-06-16T16:30:00Z')}"
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
                "🟢 Pass"
                if res["score"] >= 0.8
                else "🟡 Warning"
                if res["score"] >= 0.5
                else "🔴 Fail"
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
                        md_content += f"* {'✅' if cv else '❌'} **{ck}**\n"
                else:
                    md_content += f"* {'✅' if v else '❌'} **{k}**\n"

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
            f"✓ Saved detailed evaluation report to:\n  {report_path}\n",
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


if __name__ == "__main__":
    app()
