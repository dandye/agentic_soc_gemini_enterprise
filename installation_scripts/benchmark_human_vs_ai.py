#!/usr/bin/env python3
"""
Autonomous SOC Agent Turing Test: Human vs. AI Comparative Benchmarker.
Loads a historical security incident telemetry, runs the Multi-Agent Orchestrator
live in simulation, and semantically grades the AI's investigation quality
against the gold-standard human analyst's report.
"""
import asyncio
import json
import os
import sys
from datetime import UTC
from pathlib import Path
from typing import Annotated

import pydantic
import typer
import vertexai
from dotenv import load_dotenv
from google import genai
from google.cloud import aiplatform
from google.genai import types
from vertexai import agent_engines


# =========================================================================
# Monkeypatch aiohttp to support extremely large streaming lines (e.g., 10MB)
# to prevent LineTooLong errors during large threat intel/hunting telemetry dumps.
# =========================================================================
try:
    import logging

    import aiohttp.streams

    logger = logging.getLogger("aiohttp_patch")
    original_init = aiohttp.streams.StreamReader.__init__

    def _patched_init(self, *args, **kwargs):
        if "limit" in kwargs:
            kwargs["limit"] = 10 * 1024 * 1024
        elif len(args) >= 2:
            args = (args[0], 10 * 1024 * 1024) + args[2:]
        else:
            kwargs["limit"] = 10 * 1024 * 1024
        original_init(self, *args, **kwargs)

    aiohttp.streams.StreamReader.__init__ = _patched_init

    original_readline = aiohttp.streams.StreamReader.readline

    async def _patched_readline(self, *args, **kwargs):
        kwargs["max_line_length"] = 10 * 1024 * 1024
        return await original_readline(self, *args, **kwargs)

    aiohttp.streams.StreamReader.readline = _patched_readline
    logger.warning(
        "Successfully patched aiohttp StreamReader limit and readline to 10MB locally"
    )
except Exception as e:
    print(f"Failed to patch aiohttp StreamReader: {e}")


app = typer.Typer(
    add_completion=False,
    help="Turing Test: Compare AI Agent investigations against historical human analyst reports.",
)


class ComparativeGrade(pydantic.BaseModel):
    telemetry_coverage_score: float = pydantic.Field(
        description="Score from 0.0 to 1.0 assessing whether the AI identified the same entities, IOCs, processes, and network connections as the human."
    )
    timeline_accuracy_score: float = pydantic.Field(
        description="Score from 0.0 to 1.0 assessing whether the AI reconstructed the correct sequence of threat events."
    )
    containment_precision_score: float = pydantic.Field(
        description="Score from 0.0 to 1.0 assessing whether the AI recommended the correct containment, isolation, or escalation actions."
    )
    overall_grade: float = pydantic.Field(
        description="Overall comparison grade from 0.0 to 1.0 assessing the AI's investigation quality compared to the human report."
    )
    strengths: list[str] = pydantic.Field(
        description="List of areas where the AI matched or exceeded the human analyst's performance (e.g. speed, extra CTI details)."
    )
    weaknesses: list[str] = pydantic.Field(
        description="List of areas where the AI missed details, hallucinated, or fell short of the human analyst's report."
    )
    detailed_analysis: str = pydantic.Field(
        description="A comprehensive, multi-paragraph comparative critique analyzing the AI's investigation quality vs. the human's ground truth report."
    )


class ComparativeJudge:
    """Grades AI investigations semantically against human analyst reports."""

    def __init__(self, project_id: str, location: str = "us-central1"):
        self.client = genai.Client(
            vertexai=True,
            project=project_id,
            location=location,
            http_options={"timeout": 120},
        )
        self.model = "gemini-2.5-pro"  # GA high-reasoning model for elite QA

    async def async_compare(
        self,
        alert_summary: str,
        ai_trajectory: list[str],
        ai_report: str,
        human_report: str,
    ) -> ComparativeGrade:
        """Runs the semantic comparative Turing test."""
        prompt = f"""
        You are a highly senior, objective, elite SOC Quality Assurance Director.
        Your task is to conduct a rigorous, blind comparative audit of a security incident investigation.
        You will compare an AI Agent's autonomous threat investigation report against a Gold-Standard Human Analyst's report.

        ### Initial Incident Alert:
        {alert_summary}

        ### AI Agent Tool Trajectory:
        {ai_trajectory}

        ### AI Agent Synthesized Investigation Report:
        {ai_report}

        ### Gold-Standard Human Analyst Report:
        {human_report}

        ### Grading Instructions:
        1. **Telemetry Coverage (0.0 - 1.0)**: Did the AI isolate the same critical elements (hashes, IPs, users, file paths, MITRE tactics) as the human? Deduct score if the AI missed key indicators or hallucinated fake telemetry.
        2. **Timeline Accuracy (0.0 - 1.0)**: Did the AI map out the timeline of events correctly? Did it identify the root process parent-child chain as cleanly as the human?
        3. **Containment Precision (0.0 - 1.0)**: Did the AI propose the same containment, host isolation, credential reset, or manual remediation steps as the human?
        4. **Overall Grade (0.0 - 1.0)**: Summarize the overall investigation quality. An AI report that is faster, contains more up-to-date threat actor intelligence, or pulls extra logs without missing core items can score higher than a human report.
        5. Provide concrete list of Strengths (where AI shined or exceeded human capability) and Weaknesses (where it missed context or hallucinated).
        """

        loop = asyncio.get_running_loop()

        def _call():
            return self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ComparativeGrade,
                    temperature=0.0,
                    system_instruction="You are a strict, objective, expert SOC QA Director. Output a precise comparative grading JSON.",
                ),
            )

        try:
            res = await loop.run_in_executor(None, _call)
            data = json.loads(res.text)
            return ComparativeGrade(**data)
        except Exception as e:
            return ComparativeGrade(
                telemetry_coverage_score=0.0,
                timeline_accuracy_score=0.0,
                containment_precision_score=0.0,
                overall_grade=0.0,
                strengths=[],
                weaknesses=[f"Comparative grading failed: {e}"],
                detailed_analysis=f"Failed to execute comparative LLM Judge: {e}",
            )


async def async_run_benchmark(incident_uuid: str, verbose: bool, local: bool = False):
    """Orchestrates the Turing Test benchmark execution."""
    load_dotenv(Path(".env"))
    project_id = os.getenv("GCP_PROJECT_ID")
    location = os.getenv("GCP_LOCATION", "us-east4")
    agent_resource = os.getenv("AGENT_ENGINE_RESOURCE_NAME")

    if not project_id or (not agent_resource and not local):
        typer.secho(
            "[ERROR] GCP_PROJECT_ID or AGENT_ENGINE_RESOURCE_NAME not set in .env",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    incident_json_path = Path("investigations") / f"{incident_uuid}.json"
    incident_md_path = Path("investigations") / f"{incident_uuid}.md"

    if not incident_json_path.exists() or not incident_md_path.exists():
        typer.secho(
            f"[ERROR] Incident files not found for UUID: {incident_uuid}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    with open(incident_json_path) as f:
        incident_data = json.load(f)

    alert_summary = incident_data.get("summary", "")
    display_name = incident_data.get("displayName", "Security Alert")
    human_verdict = incident_data.get("verdict", "UNKNOWN")

    typer.echo("\n" + "=" * 80)
    typer.secho(
        "TURING TEST BENCHMARK: HUMAN VS. AI AGENT INVESTIGATION",
        fg=typer.colors.MAGENTA,
        bold=True,
    )
    typer.echo(f"  Incident ID:  {incident_uuid}")
    typer.echo(f"  Alert Type:   {display_name}")
    typer.echo(f"  Human Verdict: {human_verdict}")
    typer.echo("=" * 80 + "\n")

    # 1. Initialize Vertex AI client for the Orchestrator
    target_location = location
    if agent_resource and agent_resource.startswith("projects/"):
        parts = agent_resource.split("/")
        if len(parts) >= 4 and parts[2] == "locations":
            target_location = parts[3]

    vertexai.init(project=project_id, location=target_location)
    aiplatform.init(project=project_id, location=target_location)

    # Parse alert time range
    time_range = incident_data.get("timeRange", {})
    start_time = time_range.get("startTime", "")
    end_time = time_range.get("endTime", "")

    # Parse alert and case IDs
    case_id = incident_data.get("name", "").split("/")[-1]
    alerts = incident_data.get("alerts", [])
    if isinstance(alerts, dict):
        alert_ids = alerts.get("ids", [])
    else:
        alert_ids = alerts
    alert_id = alert_ids[0] if alert_ids else ""

    import time

    user_id = f"turing_eval_{incident_uuid}_{int(time.time())}"
    query = (
        f"Please perform a complete, end-to-end investigation of this alert.\n"
        f"- **Alert Type**: {display_name}\n"
        f"- **Alert ID**: {alert_id}\n"
        f"- **Case ID**: {case_id}\n"
        f"- **Alert Time Range**: From {start_time} to {end_time}\n"
        f"- **Summary**: {alert_summary}"
    )

    typer.secho(
        "🤖 [AI Agent] Launching autonomous investigation query...",
        fg=typer.colors.CYAN,
    )
    if verbose:
        typer.echo(f"  Query: {query}")

    if local:
        typer.secho(
            "🤖 [AI Agent] Initializing Local Orchestrator Agent (in-process)...",
            fg=typer.colors.CYAN,
        )
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"

        # Add root path to sys.path to resolve agent_soc_manager
        sys.path.append(str(Path(".").absolute()))
        from google.adk.apps import App
        from google.adk.runners import InMemoryRunner

        from agent_soc_manager.agent import create_agent

        # Instantiate local agent
        agent_obj = create_agent()

        app = App(name="secops_assistant", root_agent=agent_obj)
        runner = InMemoryRunner(app=app)
        runner.auto_create_session = True

        session_id = f"local_bench_{incident_uuid}"

        # Wrap query in ADK Content type
        new_message = types.Content(role="user", parts=[types.Part(text=query)])

        generator = runner.run_async(
            user_id=user_id, session_id=session_id, new_message=new_message
        )
    else:
        typer.secho(
            f"🤖 [AI Agent] Initializing Orchestrator Agent session ({target_location})...",
            fg=typer.colors.CYAN,
        )
        remote_app = agent_engines.get(agent_resource)

        session = await remote_app.async_create_session(user_id=user_id)
        session_id = session.get("id")
        typer.secho(
            f"Created remote session: {session_id}",
            fg=typer.colors.MAGENTA,
        )

        generator = remote_app.async_stream_query(
            user_id=user_id, session_id=session_id, message=query
        )

    tool_calls = []
    ai_report = ""

    try:
        while True:
            event = await asyncio.wait_for(generator.__anext__(), timeout=300.0)

            # If the event is a Pydantic model (local run), convert to dict
            if not isinstance(event, dict):
                event_dict = (
                    event.model_dump() if hasattr(event, "model_dump") else dict(event)
                )
            else:
                event_dict = event

            if verbose:
                # Pretty print the raw event for streaming diagnostics
                # Filter out extremely large binary objects if present to keep output readable
                event_copy = json.loads(json.dumps(event_dict))
                typer.secho(
                    f"\n[RAW EVENT] {json.dumps(event_copy, indent=2)}",
                    fg=typer.colors.CYAN,
                )

            if (
                "content" in event_dict
                and event_dict["content"]
                and "parts" in event_dict["content"]
            ):
                for part in event_dict["content"]["parts"]:
                    if "function_call" in part and part["function_call"]:
                        tool_name = part["function_call"]["name"]
                        tool_calls.append(tool_name)
                        typer.secho(
                            f"    [AI Tool Call] {tool_name}", fg=typer.colors.YELLOW
                        )

            if "content" in event_dict and event_dict["content"]:
                content = event_dict["content"]
                if content.get("role") == "model":
                    for part in content.get("parts", []):
                        if "text" in part and part["text"]:
                            ai_report += part["text"]
    except StopAsyncIteration:
        pass
    except Exception as e:
        typer.secho(
            f"❌ [AI Error] Investigation failed during execution: {e}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    typer.secho(
        "🟢 [AI Agent] Autonomous investigation complete! Report generated.",
        fg=typer.colors.GREEN,
    )

    # 3. Load Human Ground Truth Report
    human_report = incident_md_path.read_text()

    # 4. Invoke the Comparative Judge
    typer.secho(
        "\n⚖️  [Comparative Judge] Invoking Senior SOC QA Judge to compare AI vs. Human...",
        fg=typer.colors.CYAN,
    )
    judge = ComparativeJudge(project_id, "us-central1")

    grade = await judge.async_compare(
        alert_summary=alert_summary,
        ai_trajectory=tool_calls,
        ai_report=ai_report,
        human_report=human_report,
    )

    # 5. Generate and Save Beautiful Markdown Artifact Report
    artifact_dir = Path(
        "/Users/dandye/.gemini/jetski/brain/39525e8a-aae4-4a3e-8010-e6cbe24b229d"
    )
    artifact_path = artifact_dir / f"benchmark_{incident_uuid}_report.md"

    # Generate timestamped filename for historical tracking
    from datetime import UTC, datetime

    file_ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    timestamped_path = artifact_dir / f"benchmark_{incident_uuid}_{file_ts}_report.md"

    strengths_md = "\n".join([f"- {s}" for s in grade.strengths])
    weaknesses_md = "\n".join([f"- {w}" for w in grade.weaknesses])

    report_content = f"""---
type: "Evaluation Report"
title: "Turing Test Quality Benchmark: AI vs. Human Analyst ({display_name})"
description: "Rigorous semantic comparative audit of the AI Multi-Agent SOC network against a Gold-Standard Human Analyst report on incident {incident_uuid}."
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/investigations/{incident_uuid}.md"
timestamp: "{pd_timestamp()}"
provenance:
  source_type: "generative_ai"
  source_tool: "ComparativeJudge"
  timestamp: "{pd_timestamp()}"
---

# Turing Test Quality Benchmark: AI vs. Human Analyst

This report documents the blind comparative audit of the autonomous **AI Multi-Agent SOC Network** against a **Gold-Standard Human Analyst** on historical incident **`{incident_uuid}`**.

## 📊 Performance Scorecard

| Assessment Dimension | Benchmark Score | Rating / Verdict |
| :--- | :---: | :---: |
| **Telemetry Coverage** | {grade.telemetry_coverage_score * 100:.1f}% | {rating_label(grade.telemetry_coverage_score)} |
| **Timeline Accuracy** | {grade.timeline_accuracy_score * 100:.1f}% | {rating_label(grade.timeline_accuracy_score)} |
| **Containment Precision** | {grade.containment_precision_score * 100:.1f}% | {rating_label(grade.containment_precision_score)} |
| **OVERALL INVESTIGATION GRADE** | **{grade.overall_grade * 100:.1f}%** | **{rating_label(grade.overall_grade)}** |

---

## ⚖️ Blind Audit Verdict Summary

{grade.detailed_analysis}

---

## 🟢 AI Strengths (Matched / Exceeded Human Analyst)

{strengths_md if grade.strengths else "- None documented."}

## 🔴 AI Weaknesses (Missed Details / Hallucinations)

{weaknesses_md if grade.weaknesses else "- None documented."}

---

## 🛠️ Execution Trace & Raw Reports

### AI Tool Trajectory
```json
{json.dumps(tool_calls, indent=2)}
```

### AI Synthesized Report
```markdown
{ai_report}
```

### Human Gold-Standard Report
```markdown
{human_report}
```
"""
    artifact_path.write_text(report_content)
    timestamped_path.write_text(report_content)

    # 6. Output Gorgeous Scorecard in Terminal
    typer.echo("\n" + "=" * 80)
    typer.secho(
        "TURING TEST AUDIT RESULTS COMPLETE", fg=typer.colors.MAGENTA, bold=True
    )
    typer.echo("=" * 80)

    print_row("Telemetry Coverage", grade.telemetry_coverage_score)
    print_row("Timeline Accuracy", grade.timeline_accuracy_score)
    print_row("Containment Precision", grade.containment_precision_score)
    typer.echo("-" * 80)
    print_row("OVERALL QUALITY GRADE", grade.overall_grade, bold=True)
    typer.echo("=" * 80 + "\n")

    typer.secho(
        f"📝 Benchmark Report Saved as Artifact: {artifact_path.name}",
        fg=typer.colors.GREEN,
        bold=True,
    )
    typer.echo(f"   View full details: file://{artifact_path}")
    typer.echo("\n" + "=" * 80 + "\n")


def pd_timestamp() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat()


def rating_label(score: float) -> str:
    if score >= 0.9:
        return "🏆 EXPERT (Exceeds Human)"
    elif score >= 0.8:
        return "🟢 PROFICIENT (Human-Grade)"
    elif score >= 0.6:
        return "🟡 COMPETENT (Needs Triage)"
    return "🔴 INSUFFICIENT (Buggy/Hallucinated)"


def print_row(label: str, score: float, bold: bool = False):
    color = typer.colors.WHITE
    if score >= 0.9:
        color = typer.colors.GREEN
    elif score >= 0.7:
        color = typer.colors.YELLOW
    else:
        color = typer.colors.RED

    label_str = f"  {label:<35}"
    score_str = f"{score * 100:>5.1f}% ({rating_label(score)})"

    if bold:
        typer.secho(f"{label_str} {score_str}", fg=color, bold=True)
    else:
        typer.echo(label_str, nl=False)
        typer.secho(score_str, fg=color)


@app.command("run")
def run(
    uuid: Annotated[
        str, typer.Option("--uuid", "-u", help="Historical Incident UUID to benchmark")
    ],
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Display verbose thought logs")
    ] = False,
    local: Annotated[
        bool,
        typer.Option(
            "--local",
            "-l",
            help="Run agent locally instead of cloud Vertex Reasoning Engine",
        ),
    ] = False,
):
    """Run a blind human-vs-AI Turing test quality benchmark on a historical incident."""
    asyncio.run(async_run_benchmark(uuid, verbose, local))


if __name__ == "__main__":
    app()
