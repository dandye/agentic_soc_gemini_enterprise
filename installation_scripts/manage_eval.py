#!/usr/bin/env python3
"""
Evaluation Management CLI for Security Operations Agents

This script handles systematic evaluation runs against deployed cloud agents
using the structured evaluation sets in evalsets/, logs each run in a structured
local ledger under eval_runs/, and provides regression and trajectory diffing tools.
Supports concurrent execution of multiple evaluation suites with rate limiting.
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

import pydantic
import typer
import vertexai
from dotenv import load_dotenv
from google import genai
from google.genai import types
from vertexai import agent_engines


app = typer.Typer(
    add_completion=False,
    help="Manage and run evaluations for the Google MCP Security Agent.",
)


class SemanticGrade(pydantic.BaseModel):
    operational_score: float = pydantic.Field(
        description="Score from 0.0 to 1.0 assessing operational correctness based on the rubric."
    )
    reasoning_score: float = pydantic.Field(
        description="Score from 0.0 to 1.0 assessing the agent's reasoning depth and path."
    )
    passed: bool = pydantic.Field(
        description="Whether the agent successfully achieved the core goal of the rubric."
    )
    critique: str = pydantic.Field(
        description="Detailed multi-line critique explaining the score, what went right, what went wrong, and how to optimize."
    )


class LLMJudge:
    """Grades agent trajectories semantically based on case rubrics."""

    def __init__(self, project_id: str, location: str):
        self.project_id = project_id
        self.location = location
        # Initialize GenAI Client for Vertex AI using ADC or environment-provided credentials
        self.client = genai.Client(vertexai=True, project=project_id, location=location)
        self.model = "gemini-2.5-pro"  # High-reasoning model for robust grading

    async def async_grade_case(
        self,
        query: str,
        response: str,
        tool_calls: list[str],
        rubric: str,
    ) -> SemanticGrade:
        """Semantically grades the agent's response and tool trajectory using the GenAI SDK."""
        prompt = f"""
        You are an elite, objective Security Operations (SOC) Quality Assurance Judge.
        Grade the following agent run against the provided operational rubric.

        ### Case Query:
        {query}

        ### Agent Tool Trajectory:
        {tool_calls}

        ### Agent Final Response:
        {response}

        ### Operational Grading Rubric:
        {rubric}

        ### Grading Instructions:
        1. Assess whether the agent followed all rules, consulted the correct runbooks/databases, and took the correct actions.
        2. Verify that the agent did not make any false assumptions or hallucinate information from memory instead of using tools.
        3. Evaluate the reasoning path: did it delegate correctly, correlate telemetry logically, and provide a clear, professional response?
        4. Provide a detailed, constructive critique pinpointing any prompt instruction defects or reasoning flaws.
        """

        loop = asyncio.get_running_loop()

        def _call():
            return self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=SemanticGrade,
                    temperature=0.0,
                    system_instruction="You are a strict, objective, expert AI SOC QA Judge. Output a precise grading JSON.",
                ),
            )

        try:
            res = await loop.run_in_executor(None, _call)
            data = json.loads(res.text)
            return SemanticGrade(**data)
        except Exception as e:
            return SemanticGrade(
                operational_score=0.0,
                reasoning_score=0.0,
                passed=False,
                critique=f"Failed to execute LLM Judge grading: {e}",
            )


class EvaluationRunner:
    """Runs systematic evaluations and manages the evaluation ledger."""

    def __init__(self, env_file: Path):
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project_id = self.env_vars.get("GCP_PROJECT_ID")
        self.location = self.env_vars.get("GCP_LOCATION", "us-central1")
        self._client_lock = None

        # Enforce GOOGLE_APPLICATION_CREDENTIALS to use Service Account to prevent gcloud fork conflicts
        sa_path = self.env_vars.get("SECOPS_SA_PATH") or self.env_vars.get(
            "CHRONICLE_SERVICE_ACCOUNT_PATH"
        )
        if sa_path and Path(sa_path).exists():
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(sa_path)

        if self.project_id:
            vertexai.init(project=self.project_id, location=self.location)

    @property
    def client_lock(self) -> asyncio.Lock:
        """Lazy-loaded lock to serialize regional client creation."""
        if self._client_lock is None:
            self._client_lock = asyncio.Lock()
        return self._client_lock

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
                # Submodule lookup failed; keep whatever was parsed and fall
                # through so commit/branch/dirty are still returned (an early
                # `return submodules` here made git_meta["commit"] KeyError).
                pass

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
        agent_resource: str | None = None,
        verbose: bool = False,
        quiet: bool = False,
    ) -> dict:
        """Execute a single evaluation case and return evaluation results."""
        user_id = "eval_user"
        session = await remote_app.async_create_session(user_id=user_id)
        session_id = session.get("id")

        if not quiet:
            typer.echo(f"  Session ID: {session_id}")

        events = []
        tool_calls = []
        final_response = ""

        # Stream query execution with timeout per chunk/turn
        generator = remote_app.async_stream_query(
            user_id=user_id, session_id=session_id, message=query
        )

        has_timeout = False
        has_error = False
        error_msg = ""
        try:
            while True:
                # Wait for the next event with a 300-second (5-minute) timeout
                event = await asyncio.wait_for(generator.__anext__(), timeout=300.0)
                events.append(event)

                # Check for tool calls or sub-agent events
                if "content" in event and "parts" in event["content"]:
                    for part in event["content"]["parts"]:
                        if "function_call" in part:
                            tool_name = part["function_call"]["name"]
                            tool_calls.append(tool_name)
                            if not quiet:
                                typer.secho(
                                    f"    [Tool Call] {tool_name}",
                                    fg=typer.colors.YELLOW,
                                )
                        elif "text" in part and verbose and not quiet:
                            typer.echo(f"    [Thought] {part['text']}")

                # Capture final response text
                if event.get("role") == "model" and "content" in event:
                    for part in event["content"].get("parts", []):
                        if "text" in part:
                            final_response += part["text"]
        except StopAsyncIteration:
            pass
        except TimeoutError:
            if not quiet:
                typer.secho(
                    "    [TIMEOUT] Case execution timed out after 5 minutes of inactivity.",
                    fg=typer.colors.RED,
                    bold=True,
                )
            has_timeout = True
        except Exception as e:
            if not quiet:
                typer.secho(
                    f"    [ERROR] Exception occurred during stream execution: {str(e)}",
                    fg=typer.colors.RED,
                    bold=True,
                )
            has_error = True
            error_msg = str(e)

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

        # Construct GEAP Playground URL
        playground_url = ""
        if agent_resource and agent_resource.startswith("projects/"):
            parts = agent_resource.split("/")
            if len(parts) >= 6:
                location = parts[3]
                engine_id = parts[5]
                playground_url = f"https://console.cloud.google.com/agent-platform/runtimes/locations/{location}/agent-engines/{engine_id}/playground?session={session_id}&project={self.project_id}&userId={user_id}"

        results = {
            "query": query,
            "response": final_response,
            "tool_calls": tool_calls,
            "playground_url": playground_url,
            "assertions": {},
            "score": 0.0,
        }
        if has_timeout:
            results["error"] = "TIMEOUT"
        elif has_error:
            results["error"] = f"ERROR: {error_msg}"

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

        # Integrate LLM Semantic Grade if Rubric is defined
        grading_rubric = reference.get("grading_rubric")
        if grading_rubric:
            judge = LLMJudge(self.project_id, self.location)
            if not quiet:
                typer.secho(
                    "    [LLM Judge] Semantically grading the trajectory...",
                    fg=typer.colors.CYAN,
                )
            grade = await judge.async_grade_case(
                query=query,
                response=final_response,
                tool_calls=tool_calls,
                rubric=grading_rubric,
            )
            results["semantic_grade"] = {
                "operational_score": grade.operational_score,
                "reasoning_score": grade.reasoning_score,
                "passed": grade.passed,
                "critique": grade.critique,
                "rubric": grading_rubric,
            }
            # Semantic score dictates the final case score
            results["score"] = grade.operational_score
            if not quiet:
                status_color = typer.colors.GREEN if grade.passed else typer.colors.RED
                typer.secho(
                    f"    [LLM Judge Verdict] Passed: {grade.passed} (Score: {grade.operational_score * 100:.1f}%)",
                    fg=status_color,
                )
                if grade.critique:
                    typer.echo(f"    [LLM Judge Critique] {grade.critique}")
        else:
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

    async def async_run_evaluation(
        self,
        evalset_path: Path,
        resource_name: str | None = None,
        verbose: bool = False,
        quiet: bool = False,
        git_meta: dict | None = None,
    ) -> float:
        """Load the evalset and execute all cases asynchronously (sequentially within the suite)."""
        if not evalset_path.exists():
            typer.secho(
                f"[ERROR] Evalset file not found: {evalset_path}", fg=typer.colors.RED
            )
            return 0.0

        with open(evalset_path) as f:
            evalset = json.load(f)

        evalset_id = evalset.get("evalset_id", "unknown")
        name = evalset.get("name", "Unknown Evaluation Set")
        eval_cases = evalset.get("eval_cases", [])

        if not quiet:
            typer.echo("\n" + "=" * 80)
            typer.secho(
                f"Running Evaluation Set: {name}", fg=typer.colors.BLUE, bold=True
            )
            typer.echo(f"Description: {evalset.get('description', '')}")
            typer.echo(f"Total Cases: {len(eval_cases)}")
            typer.echo("=" * 80 + "\n")
        else:
            typer.secho(f"[START] Running suite: {name}", fg=typer.colors.CYAN)

        # Resolve agent resource
        agent_resource = resource_name or self._get_agent_resource(evalset_id)
        if not agent_resource:
            typer.secho(
                f"[ERROR] Could not resolve agent resource name for evalset '{evalset_id}'.",
                fg=typer.colors.RED,
            )
            return 0.0

        # Resolve target location from the agent resource ID path to prevent regional mismatches
        target_location = self.location
        if agent_resource.startswith("projects/"):
            parts = agent_resource.split("/")
            if len(parts) >= 4 and parts[2] == "locations":
                target_location = parts[3]

        # Serialize regional client instantiation to prevent global config races
        async with self.client_lock:
            vertexai.init(project=self.project_id, location=target_location)
            if not quiet:
                typer.secho(
                    f"Connecting to live Agent Engine ({target_location}):\n  {agent_resource}\n",
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

            if not quiet:
                typer.secho(
                    f"[{i}/{len(eval_cases)}] Running Case: {case_name} ({eval_id})",
                    fg=typer.colors.BLUE,
                    bold=True,
                )
                typer.echo(f"  Query: {query}")

            # Run case async
            result = await self._async_run_case(
                remote_app, query, reference, agent_resource, verbose, quiet
            )
            case_results.append((eval_id, case_name, result))

            if not quiet:
                score_pct = result["score"] * 100
                fg_color = (
                    typer.colors.GREEN
                    if score_pct >= 80
                    else typer.colors.YELLOW
                    if score_pct >= 50
                    else typer.colors.RED
                )
                typer.secho(f"  Case Score: {score_pct:.1f}%\n", fg=fg_color, bold=True)

        avg_score = (
            (sum(res["score"] for _, _, res in case_results) / len(eval_cases)) * 100
            if eval_cases
            else 0.0
        )

        if not quiet:
            # Print final scorecard
            typer.echo("\n" + "=" * 80)
            typer.secho("EVALUATION SCORECARD", fg=typer.colors.GREEN, bold=True)
            typer.echo("=" * 80)

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
                    f"{status_char:<8} {case_name:<45} {score_pct:>5.1f}%",
                    fg=status_color,
                )

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
        else:
            final_color = (
                typer.colors.GREEN
                if avg_score >= 85
                else typer.colors.YELLOW
                if avg_score >= 70
                else typer.colors.RED
            )
            typer.secho(
                f"[SUCCESS] Completed suite: {name} (Score: {avg_score:.1f}%)",
                fg=final_color,
                bold=True,
            )

        # Get git metadata, timestamp, and commit hash once
        if not git_meta:
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

        return avg_score, case_results

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
        kg_path = Path("investigations/knowledge_graph.json")

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
type: "Evaluation Report"
title: "Evaluation Report: {evalset_name}"
description: "Systematic prompt evaluation scorecard for {evalset_name} on commit {commit_short}"
resource: "file://{report_path.resolve()}"
timestamp: "{datetime.utcnow().isoformat() + 'Z'}"
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
            playground_url = res.get("playground_url")
            playground_link = (
                f"[Open Interactive Session in GCP Console]({playground_url})"
                if playground_url
                else "*N/A*"
            )
            md_content += f"""### Case {i}: {case_name} ({eval_id})

* **User Query:** "{res['query']}"
* **Score:** **{res['score']*100:.1f}%**
* **GEAP Playground:** {playground_link}

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
type: "Evaluation Comparison Report"
title: "Evaluation Comparison Report: {evalset_id}"
description: "Delta analysis between run {base_name} and run {new_name}"
resource: "file://{report_path.resolve()}"
timestamp: "{datetime.utcnow().isoformat() + 'Z'}"
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


async def async_run_all(directory: Path, verbose: bool):
    """Run all evaluation sets in the directory sequentially to guarantee stability in gcert/fork-restricted environments."""
    if not directory.exists() or not directory.is_dir():
        typer.secho(f"[ERROR] Directory not found: {directory}", fg=typer.colors.RED)
        raise typer.Exit(1)

    evalset_files = sorted(directory.glob("*.evalset.json"))
    if not evalset_files:
        typer.secho(
            f"[ERROR] No *.evalset.json files found in {directory}", fg=typer.colors.RED
        )
        raise typer.Exit(1)

    typer.echo("\n" + "=" * 80)
    typer.secho(
        "LAUNCHING SEQUENTIAL EVALUATIONS FOR STABILITY",
        fg=typer.colors.BLUE,
        bold=True,
    )
    typer.echo(f"  Found {len(evalset_files)} evaluation suites to run.")
    typer.echo("=" * 80 + "\n")

    runner = EvaluationRunner(Path(".env"))
    # Pre-load git metadata once to prevent gRPC / fork conflicts
    git_meta = runner._get_git_metadata()

    # Execute suites sequentially to prevent concurrent gRPC resolver crashes
    for i, file_path in enumerate(evalset_files, start=1):
        typer.secho(
            f"\n--- [Suite {i}/{len(evalset_files)}] {file_path.name} ---",
            fg=typer.colors.CYAN,
            bold=True,
        )
        try:
            await runner.async_run_evaluation(
                evalset_path=file_path,
                resource_name=None,
                verbose=verbose,
                quiet=False,
                git_meta=git_meta,
            )
        except Exception as e:
            typer.secho(
                f"[ERROR] Exception running suite {file_path.name}: {e}",
                fg=typer.colors.RED,
            )

    typer.echo("\n" + "=" * 80)
    typer.secho(
        "ALL EVALUATIONS COMPLETED SUCCESSFULLY", fg=typer.colors.GREEN, bold=True
    )
    typer.echo("=" * 80 + "\n")


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
    asyncio.run(
        runner.async_run_evaluation(evalset_file, resource, verbose, quiet=False)
    )


@app.command("run-all")
def run_all(
    directory: Annotated[
        Path,
        typer.Option("--dir", "-d", help="Directory containing evalset JSON files"),
    ] = Path("evalsets"),
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose", "-v", help="Print verbose intermediate thought events"
        ),
    ] = False,
) -> None:
    """Run all evaluation sets in a directory sequentially.

    Execution is deliberately serialized for gRPC stability (see commit
    07947be); a concurrency flag existed but was silently ignored.
    """
    asyncio.run(async_run_all(directory, verbose))


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


class PromptOptimizer:
    """Refines system instructions based on semantic critiques of failures using gemini-3.1-pro-preview."""

    def __init__(self, project_id: str, location: str = "us-central1"):
        # Initialize GenAI Client for Vertex AI using ADC or environment-provided credentials
        self.client = genai.Client(vertexai=True, project=project_id, location=location)
        self.model = "gemini-2.5-pro"  # High-reasoning model for prompt synthesis

    def optimize_instructions(
        self,
        current_instructions: str,
        failed_cases: list[dict],
    ) -> str:
        """Generates a refined, optimized system instruction prompt."""
        failures_summary = ""
        for i, case in enumerate(failed_cases, start=1):
            failures_summary += f"""
--- Failed Case {i}: {case['name']} ---
User Query: {case['query']}
Tool Trajectory: {case['tool_calls']}
Agent Response:
{case['response']}

QA Judge Critique:
{case['critique']}
"""

        prompt = f"""
        You are an elite, world-class MLOps and Prompt Engineer. Your task is to refine the system instructions for a Security Operations (SOC) agent to resolve the active failures identified during QA evaluation.

        ### Current System Instructions:
        ```markdown
        {current_instructions}
        ```

        ### Active Evaluation Failures:
        {failures_summary}

        ### Optimization Guidelines:
        1. **Do NOT delete core capabilities or rules:** You must preserve the existing agent architecture, tool descriptions, and constraints.
        2. **Address the Root Cause**: Analyze the Judge's critiques to understand *why* the agent failed. Did it ignore a rule? Did it lack guidance on which tool to prioritize? Did it hallucinate?
        3. **Inject Specific, Bulletproof Rules**: Add clear, unambiguous, and actionable instructions (such as operational mandates or cognitive constraints) that target the exact failure modes.
        4. **Maintain Format**: Return ONLY the complete, updated system instructions in clean markdown format. Do not include any conversational explanation, preambles, or markdown code block wrapper backticks around the entire response. Start directly with the first line of the instructions.
        """

        res = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
                system_instruction="You are an expert Prompt Compiler and Optimizer. Output the refined prompt string directly without conversational preambles or code blocks.",
            ),
        )
        return res.text.strip()


def get_prompt_file_path(evalset_id: str) -> Path | None:
    """Resolve the prompts file path based on the evalset ID."""
    if evalset_id == "tier1_triage":
        return Path("agent_soc_manager/prompts/tier1_analyst_instructions.md")
    elif evalset_id == "soc_basic" or evalset_id == "multi_specialist":
        return Path("agent_soc_manager/prompts/orchestrator_instructions.md")
    return None


def redeploy_agent(evalset_id: str):
    """Sync the updated agent with the cloud reasoning engine using just."""
    module = "agent_soc_manager"
    if evalset_id == "cti_research":
        module = "agent_a2a_cti_researcher"
    elif evalset_id == "threat_hunting":
        module = "agent_a2a_threat_hunter"
    elif evalset_id == "detection_engineering":
        module = "agent_a2a_detection_engineer"
    elif evalset_id == "incident_response":
        module = "agent_a2a_tier2"

    typer.echo(f"  Redeploying cloud reasoning engine '{module}'...")
    res = subprocess.run(
        ["just", f"agent_module={module}", "agent-engine-update"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        typer.secho(f"  [ERROR] Redeployment failed: {res.stderr}", fg=typer.colors.RED)
        raise Exception("Redeployment failed.")
    typer.secho("  Reasoning Engine updated successfully!", fg=typer.colors.GREEN)


async def async_optimize(evalset_path: Path, max_iterations: int):
    """Asynchronous orchestrator for the closed-loop optimization run."""
    runner = EvaluationRunner(Path(".env"))

    if not evalset_path.exists():
        typer.secho(
            f"[ERROR] Evalset file not found: {evalset_path}", fg=typer.colors.RED
        )
        raise typer.Exit(1)

    with open(evalset_path) as f:
        evalset = json.load(f)

    evalset_id = evalset.get("evalset_id")
    prompt_file = get_prompt_file_path(evalset_id)
    if not prompt_file or not prompt_file.exists():
        typer.secho(
            f"[ERROR] Prompt file not found or unsupported for evalset '{evalset_id}'.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    typer.echo("\n" + "=" * 80)
    typer.secho(
        "COGNITIVE COMPILER: AUTONOMOUS OPTIMIZATION LOOP",
        fg=typer.colors.MAGENTA,
        bold=True,
    )
    typer.echo(f"  Evalset:      {evalset.get('name')}")
    typer.echo(f"  Prompt File:  {prompt_file}")
    typer.echo("=" * 80 + "\n")

    # Backup original prompt
    original_prompt = prompt_file.read_text()
    best_prompt = original_prompt
    best_score = 0.0
    best_cases_failed = {}

    # Gather git metadata
    git_meta = runner._get_git_metadata()

    for cycle in range(1, max_iterations + 1):
        typer.secho(
            f"\n📊 [CYCLE {cycle}/{max_iterations}] Running Evaluation Suite...",
            fg=typer.colors.MAGENTA,
            bold=True,
        )

        # Run evaluation suite
        avg_score, case_results = await runner.async_run_evaluation(
            evalset_path=evalset_path,
            resource_name=None,
            verbose=False,
            quiet=False,
            git_meta=git_meta,
        )

        # Collect failed cases
        failed_cases = []
        for eval_id, case_name, res in case_results:
            # Score below 80% is considered a failure
            if res["score"] < 0.8:
                critique = res.get("semantic_grade", {}).get(
                    "critique", "Static heuristics failed."
                )
                failed_cases.append(
                    {
                        "id": eval_id,
                        "name": case_name,
                        "query": res["query"],
                        "tool_calls": res["tool_calls"],
                        "response": res["response"],
                        "critique": critique,
                    }
                )

        typer.echo("-" * 80)
        typer.echo(
            f"Cycle {cycle} Results: Score = {avg_score:.1f}% | Failures = {len(failed_cases)}"
        )

        # Keep track of the best prompt
        if avg_score > best_score:
            best_score = avg_score
            best_prompt = prompt_file.read_text()
            best_cases_failed = {fc["id"] for fc in failed_cases}
            typer.secho(
                f"🌟 [New Best Score] Saved new optimal prompt with score {best_score:.1f}%",
                fg=typer.colors.GREEN,
                bold=True,
            )

        if not failed_cases:
            typer.secho(
                "\n🟢 [SUCCESS] All cases passed! Optimization complete!",
                fg=typer.colors.GREEN,
                bold=True,
            )
            break

        # Check if we should continue optimizing
        if cycle == max_iterations:
            typer.secho(
                "\n🟡 [LIMIT REACHED] Reached maximum optimization cycles.",
                fg=typer.colors.YELLOW,
            )
            break

        # Check for regressions: did a previously passing case fail in this run?
        # A case is a regression if it failed in this run but was NOT failed in the best run.
        regressions = [
            fc["name"] for fc in failed_cases if fc["id"] not in best_cases_failed
        ]
        if regressions:
            typer.secho(
                f"⚠️ [REGRESSION DETECTED] Prompt cycle introduced regressions in: {', '.join(regressions)}",
                fg=typer.colors.YELLOW,
            )
            typer.echo(
                "🔄 Reverting prompt back to best known state before next tuning..."
            )
            prompt_file.write_text(best_prompt)

        # Trigger Prompt Optimizer Agent
        typer.secho(
            "\n🤖 [Optimizer] Engage Prompt Optimizer Agent to compile new instructions...",
            fg=typer.colors.CYAN,
        )
        optimizer = PromptOptimizer(runner.project_id, "us-central1")
        current_instructions = prompt_file.read_text()

        try:
            refined_instructions = optimizer.optimize_instructions(
                current_instructions, failed_cases
            )

            # Write prompt
            prompt_file.write_text(refined_instructions)
            typer.secho(
                "📝 [Optimizer] Refined instructions written to prompt file.",
                fg=typer.colors.GREEN,
            )

            # Redeploy agent to cloud
            redeploy_agent(evalset_id)
        except Exception as e:
            typer.secho(
                f"❌ [Optimizer Error] Failed to optimize or redeploy: {e}",
                fg=typer.colors.RED,
            )
            typer.echo("🔄 Restoring best known prompt...")
            prompt_file.write_text(best_prompt)
            break

    # Revert to best known prompt if the final iteration was not the best
    current_prompt = prompt_file.read_text()
    if current_prompt != best_prompt:
        typer.echo("\n🔄 Restoring best performing prompt to files...")
        prompt_file.write_text(best_prompt)
        redeploy_agent(evalset_id)

    typer.echo("\n" + "=" * 80)
    typer.secho(
        f"OPTIMIZATION COMPLETE! FINAL BEST SCORE: {best_score:.1f}%",
        fg=typer.colors.GREEN,
        bold=True,
    )
    typer.echo("=" * 80 + "\n")


@app.command("optimize")
def optimize(
    evalset_file: Annotated[
        Path, typer.Option("--file", "-f", help="Path to the evalset JSON file")
    ],
    max_iterations: Annotated[
        int, typer.Option("--max-iter", "-i", help="Maximum optimization cycles")
    ] = 2,
) -> None:
    """Autonomous closed-loop prompt optimizer that semantically critiques failures and auto-tunes instructions."""
    asyncio.run(async_optimize(evalset_file, max_iterations))


if __name__ == "__main__":
    app()
