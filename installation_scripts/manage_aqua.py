#!/usr/bin/env python3
"""
Ambient Quality Agent (AQuA) Sidecar & Snapshot Manager.

Provides CLI lifecycle commands (`init`, `deploy`, `run`, `ui`, `snapshot`,
`promote-insight`) and versioned source code snapshot generation (`Revision N`)
so AQuA outer-loop diagnostics always correlate production trajectories against
the exact deployed codebase snapshot.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from dotenv import load_dotenv

from installation_scripts.provenance_helper import write_stripped_goal_file


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_GOAL_PATH = REPO_ROOT / "docs" / "aqua_goal.md"
DEFAULT_EVAL_CONFIG = "aqua/eval_config.yaml"
DEFAULT_SNAPSHOT_ROOT = REPO_ROOT / "aqua" / "snapshots"

ALL_AGENT_MODULES = (
    "agent_soc_manager",
    "agent_a2a_tier2",
    "agent_a2a_threat_hunter",
    "agent_a2a_detection_engineer",
    "agent_a2a_cti_researcher",
)

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
    project_id: str | None = None,
) -> list[str]:
    """Build the `agents-cli aqua init` command list with a frontmatter-stripped goal file."""
    if not monitored_agent_id:
        raise ValueError("monitored_agent_id is required for aqua init")
    goal_file_arg = agent_goal_file
    if goal_file_arg is None:
        stripped_path = write_stripped_goal_file(DEFAULT_GOAL_PATH)
        goal_file_arg = str(stripped_path)
    cmd = [
        "agents-cli",
        "aqua",
        "init",
        "--monitored-agent-id",
        monitored_agent_id,
        "--agent-source-dir",
        agent_source_dir,
        "--agent-goal-file",
        goal_file_arg,
    ]
    if project_id:
        cmd.extend(["--project-id", project_id])
    return cmd


def build_aqua_deploy_command(
    project_id: str | None = None,
    agent_source_dir: str = ".",
    agent_goal_file: str | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
    """Build the `agents-cli aqua deploy` command list."""
    cmd = ["agents-cli", "aqua", "deploy"]
    if project_id:
        cmd.extend(["--project-id", project_id])
    if agent_source_dir:
        cmd.extend(["--agent-source-dir", agent_source_dir])
    if agent_goal_file:
        cmd.extend(["--agent-goal-file", agent_goal_file])
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def build_aqua_run_command(
    start_time: str = "-24h",
    eval_config: str = DEFAULT_EVAL_CONFIG,
    end_time: str | None = None,
    project_id: str | None = None,
    trace_lookup_hours: int = 24,
    limit: int = 100,
) -> list[str]:
    """Build the `agents-cli aqua run` command list."""
    cmd = [
        "agents-cli",
        "aqua",
        "run",
        "--start-time",
        start_time,
        "--trace-lookup-hours",
        str(trace_lookup_hours),
        "--limit",
        str(limit),
        "--eval-config",
        eval_config,
    ]
    if project_id:
        cmd.extend(["--project-id", project_id])
    if end_time:
        cmd.extend(["--end-time", end_time])
    return cmd


def build_aqua_ui_command(
    project_id: str | None = None,
    port: int = 8080,
) -> list[str]:
    """Build the `agents-cli aqua ui-proxy` command list."""
    cmd = ["agents-cli", "aqua", "ui-proxy", "--port", str(port)]
    if project_id:
        cmd.extend(["--project-id", project_id])
    return cmd


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

    # Include the requested agent_module plus all 4 A2A specialist directories if present
    modules_to_snapshot = [agent_module]
    for mod in ALL_AGENT_MODULES:
        if mod not in modules_to_snapshot and (root / mod).exists():
            modules_to_snapshot.append(mod)

    files_manifest: dict[str, dict[str, Any]] = {}
    for mod_name in modules_to_snapshot:
        module_dir = root / mod_name
        if not module_dir.exists():
            continue
        for src_file in sorted(module_dir.rglob("*")):
            if not src_file.is_file():
                continue
            if (
                "__pycache__" in src_file.parts
                or ".git" in src_file.parts
                or src_file.suffix in (".pyc", ".pyo")
            ):
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
        "included_modules": modules_to_snapshot,
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
        typer.Option(
            "--monitored-agent-id", help="Reasoning Engine ID or resource name."
        ),
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
            "[FAIL] Neither --monitored-agent-id nor AGENT_ENGINE_ID/AGENT_ENGINE_RESOURCE_NAME is set.",
            err=True,
        )
        raise typer.Exit(code=1)

    stripped_goal = write_stripped_goal_file(goal_file)
    project_id = os.environ.get("GCP_PROJECT_ID")
    cmd = build_aqua_init_command(
        monitored_agent_id=agent_id,
        agent_source_dir=agent_source_dir,
        agent_goal_file=str(stripped_goal),
        project_id=project_id,
    )
    typer.echo(f"[INFO] Stripped OKF frontmatter from {goal_file} -> {stripped_goal}")
    typer.echo(f"[INFO] Command: {' '.join(cmd)}")
    if dry_run:
        return
    subprocess.run(cmd, check=True)


@app.command("deploy")
def cli_deploy(
    agent_module: Annotated[
        str,
        typer.Option(
            "--agent-module", help="Agent module to snapshot before deploying AQuA."
        ),
    ] = "agent_soc_manager",
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
        typer.Option(
            "--dry-run", help="Record snapshot and print command without executing."
        ),
    ] = False,
) -> None:
    """Create a versioned source snapshot and deploy AQuA to Vertex AI Agent Engine."""
    if env_file.exists():
        load_dotenv(env_file, override=False)
    manifest = create_source_snapshot(agent_module=agent_module)
    stripped_goal = write_stripped_goal_file(goal_file)
    project_id = os.environ.get("GCP_PROJECT_ID")
    typer.echo(
        f"[PASS] Created source snapshot {manifest['revision_label']} ({len(manifest['files'])} files) at {manifest['snapshot_dir']}"
    )
    cmd = build_aqua_deploy_command(
        project_id=project_id,
        agent_source_dir=manifest["snapshot_dir"],
        agent_goal_file=str(stripped_goal),
    )
    typer.echo(f"[INFO] Command: {' '.join(cmd)}")
    if dry_run:
        return
    subprocess.run(cmd, check=True)


def _has_agents_cli_aqua() -> bool:
    """Return True if `agents-cli` is on PATH and supports the `aqua` subcommand."""
    bin_path = shutil.which("agents-cli")
    if not bin_path:
        return False
    try:
        res = subprocess.run(
            [bin_path, "aqua", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


_METRIC_CITATION_MAP: dict[str, dict[str, Any]] = {
    "timerange_propagation_check": {
        "title": "Lookback Time Window Dropped Across SIEM Tool or Specialist Delegation",
        "severity": "HIGH",
        "impact": "HIGH",
        "code_citations": [
            "agent_soc_manager/prompts/orchestrator_instructions.md:1-35",
            "agent_a2a_threat_hunter/prompts/threat_hunter_instructions.md:1-25",
        ],
        "expected_behavior": "Preserve the user-requested hours_back lookback window across all time-sensitive SIEM tool calls and specialist delegations.",
    },
    "soar_phase2_fallback_check": {
        "title": "SOAR Phase 2 Empty Native list_cases Without Siemplify Fallback",
        "severity": "HIGH",
        "impact": "HIGH",
        "code_citations": [
            "agent_soc_manager/prompts/tier1_analyst_instructions.md:1-30",
        ],
        "expected_behavior": "When native Chronicle list_cases returns {} on non-Phase-2 tenants, immediately fall back to standalone Siemplify SOAR (/api/1p/external/v1/cases).",
    },
    "subagent_context_forwarding_check": {
        "title": "Multi-Turn Pivot Context Entities Dropped During Specialist Delegation",
        "severity": "HIGH",
        "impact": "HIGH",
        "code_citations": [
            "agent_soc_manager/prompts/orchestrator_instructions.md:1-40",
        ],
        "expected_behavior": "Forward all prior-turn entities, hosts, IPs, hashes, and case IDs when invoking delegate_to_specialist or delegate_concurrently.",
    },
    "design_spec_attribution_check": {
        "title": "Missing or Unverified Specialist Attribution Footer in Final Response",
        "severity": "MEDIUM",
        "impact": "MEDIUM",
        "code_citations": [
            "agent_soc_manager/prompts/orchestrator_instructions.md:1-40",
            "agent_a2a_tier2/prompts/tier2_responder_instructions.md:1-25",
        ],
        "expected_behavior": "Include the mandatory *Agent: <Name> | Model: <Model> | Tools: <Executed Tools>* footer grounded in actually executed tools.",
    },
}


def _collect_vertex_session_traces(
    project_id: str | None,
    trace_lookup_hours: int = 24,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Harvest multi-turn and single-turn sessions directly from Vertex AI Reasoning Engine Session Service."""
    if not project_id:
        return []
    agent_resource = os.environ.get("AGENT_ENGINE_RESOURCE_NAME")
    if not agent_resource:
        return []
    try:
        from datetime import timedelta
        import vertexai
        from vertexai import agent_engines

        location = "us-central1"
        if agent_resource.startswith("projects/"):
            parts = agent_resource.split("/")
            if len(parts) >= 4 and parts[2] == "locations":
                location = parts[3]
        vertexai.init(project=project_id, location=location)
        remote_app = agent_engines.get(agent_resource)
        sessions_resp = remote_app.list_sessions(user_id="eval_user")
        session_items = (
            sessions_resp.get("sessions", [])
            if isinstance(sessions_resp, dict)
            else []
        )
        cutoff_epoch = (
            datetime.now(UTC) - timedelta(hours=max(1, trace_lookup_hours))
        ).timestamp()

        harvested: list[dict[str, Any]] = []
        for s_meta in session_items:
            if not isinstance(s_meta, dict):
                continue
            sid = str(s_meta.get("id") or "")
            last_update = float(s_meta.get("lastUpdateTime") or 0.0)
            if not sid or (last_update and last_update < cutoff_epoch):
                continue
            sess = remote_app.get_session(user_id="eval_user", session_id=sid)
            events = sess.get("events", []) if isinstance(sess, dict) else []
            conversation: list[dict[str, str]] = []
            tool_calls: list[dict[str, Any]] = []
            response_chunks: list[str] = []

            for ev in events:
                if not isinstance(ev, dict):
                    continue
                author = str(ev.get("author") or "")
                content = ev.get("content")
                if not isinstance(content, dict):
                    continue
                role = str(content.get("role") or "")
                parts = content.get("parts") or []
                for part in parts:
                    if not isinstance(part, dict):
                        continue
                    fc = part.get("functionCall") or part.get("function_call")
                    if isinstance(fc, dict) and fc.get("name"):
                        tool_calls.append(
                            {
                                "turn": max(1, len(conversation)),
                                "name": str(fc.get("name")),
                                "args": fc.get("args") or {},
                            }
                        )
                    txt = part.get("text")
                    if isinstance(txt, str) and txt.strip():
                        clean_txt = txt.strip()
                        if author == "user" or role == "user":
                            if (
                                clean_txt
                                != "Please continue and complete the previous request in this session."
                            ):
                                conversation.append(
                                    {"role": "user", "content": clean_txt}
                                )
                        elif role == "model":
                            response_chunks.append(clean_txt)

            if conversation or tool_calls or response_chunks:
                harvested.append(
                    {
                        "session_id": sid,
                        "source": "vertex_session_service",
                        "user_prompt": " ".join(
                            t["content"] for t in conversation
                        ).strip(),
                        "conversation": conversation,
                        "tool_calls": tool_calls,
                        "final_response": "\n\n".join(response_chunks).strip(),
                    }
                )
            if len(harvested) >= limit:
                break
        return harvested
    except Exception as exc:
        typer.echo(f"[WARN] Vertex AI Session trace query skipped: {exc}")
        return []


def _collect_cloud_trace_spans(
    project_id: str | None,
    trace_lookup_hours: int = 24,
    limit: int = 50,
    target_session_id: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Harvest OpenTelemetry span trees from Cloud Trace (trace_v1) and group by session_id.

    Returns:
        Tuple of (session_trace_records, trace_id_to_session_id_map).
    """
    if not project_id:
        return [], {}
    try:
        from datetime import timedelta
        from google.cloud import trace_v1
        from google.protobuf.timestamp_pb2 import Timestamp
        from aqua.custom_metrics import _normalize_trace_info

        tc = trace_v1.TraceServiceClient()
        start_dt = datetime.now(UTC) - timedelta(hours=max(1, trace_lookup_hours))
        start_ts = Timestamp()
        start_ts.FromDatetime(start_dt)

        req: dict[str, Any] = {
            "project_id": project_id,
            "start_time": start_ts,
            "view": trace_v1.ListTracesRequest.ViewType.COMPLETE,
            "page_size": min(max(limit, 30), 100),
        }
        traces_pager = tc.list_traces(request=req)

        grouped_by_sid: dict[str, dict[str, Any]] = {}
        trace_to_sid: dict[str, str] = {}

        for idx, tr in enumerate(traces_pager):
            if idx >= max(limit * 2, 60):
                break
            tid = str(tr.trace_id or "")
            if not tid:
                continue

            # Determine session_id and reasoning_engine_id from span labels
            sid: str | None = None
            re_id: str | None = None
            serialized_spans: list[dict[str, Any]] = []

            for sp in tr.spans:
                labels = dict(sp.labels) if sp.labels else {}
                if not sid:
                    sid = (
                        labels.get("gen_ai.conversation.id")
                        or labels.get("gcp.vertex.agent.session_id")
                    )
                res_id = labels.get("cloud.resource_id", "")
                if not re_id and "reasoningEngines/" in res_id:
                    re_id = res_id.split("reasoningEngines/")[-1]

                start_iso = (
                    sp.start_time.isoformat()
                    if hasattr(sp.start_time, "isoformat") and sp.start_time
                    else None
                )
                end_iso = (
                    sp.end_time.isoformat()
                    if hasattr(sp.end_time, "isoformat") and sp.end_time
                    else None
                )
                dur_ms = None
                if (
                    hasattr(sp.start_time, "timestamp")
                    and hasattr(sp.end_time, "timestamp")
                    and sp.start_time
                    and sp.end_time
                ):
                    dur_ms = round(
                        max(0.0, (sp.end_time.timestamp() - sp.start_time.timestamp()) * 1000.0),
                        2,
                    )
                serialized_spans.append(
                    {
                        "trace_id": tid,
                        "span_id": str(sp.span_id),
                        "parent_span_id": (
                            str(sp.parent_span_id) if sp.parent_span_id else None
                        ),
                        "name": str(sp.name or ""),
                        "start_time": start_iso,
                        "end_time": end_iso,
                        "duration_ms": dur_ms,
                        "attributes": labels,
                    }
                )

            if target_session_id and sid != target_session_id:
                continue

            # Skip internal sub-traces without agent/LLM/tool spans and without a session_id
            has_agent_spans = any(
                s["name"].startswith(
                    ("invoke_agent", "call_llm", "execute_tool", "generate_content", "a2a.")
                )
                for s in serialized_spans
            )
            if not sid and not has_agent_spans:
                continue

            effective_sid = str(sid or f"trace-{tid[:16]}")
            trace_to_sid[tid] = effective_sid

            rec = grouped_by_sid.setdefault(
                effective_sid,
                {
                    "session_id": effective_sid,
                    "reasoning_engine_id": re_id,
                    "source": "cloud_trace",
                    "trace_ids": [],
                    "spans": [],
                },
            )
            if tid not in rec["trace_ids"]:
                rec["trace_ids"].append(tid)
            if re_id and not rec.get("reasoning_engine_id"):
                rec["reasoning_engine_id"] = re_id
            rec["spans"].extend(serialized_spans)

        results: list[dict[str, Any]] = []
        for sid_key, rec in grouped_by_sid.items():
            # Sort spans chronologically by start_time
            rec["spans"].sort(key=lambda s: str(s.get("start_time") or ""))
            normalized = _normalize_trace_info(rec)
            results.append(normalized)
            if len(results) >= limit:
                break

        return results, trace_to_sid
    except Exception as exc:
        typer.echo(f"[WARN] Cloud Trace span query skipped: {exc}")
        return [], {}


def _collect_cloud_logging_traces(
    project_id: str | None,
    trace_lookup_hours: int = 24,
    limit: int = 50,
    trace_to_session_map: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Harvest multi-turn / single-turn OpenTelemetry GenAI traces from Cloud Logging."""
    if not project_id:
        return []
    try:
        from datetime import timedelta

        from google.cloud import logging as cloud_logging

        client = cloud_logging.Client(project=project_id)
        cutoff = (
            datetime.now(UTC) - timedelta(hours=max(1, trace_lookup_hours))
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        filter_str = (
            f'timestamp >= "{cutoff}" AND ('
            f'labels."event.name"=("gen_ai.user.message" OR "gen_ai.choice" OR "gen_ai.system.message" OR "gen_ai.client.inference.operation.details") OR '
            f'logName="projects/{project_id}/logs/gen_ai.user.message" OR '
            f'logName="projects/{project_id}/logs/gen_ai.choice")'
        )
        entries = list(
            client.list_entries(
                filter_=filter_str,
                order_by=cloud_logging.ASCENDING,
                max_results=min(limit * 8, 400),
            )
        )
        grouped: dict[str, dict[str, Any]] = {}
        t_map = trace_to_session_map or {}
        for entry in entries:
            trace_id = (
                getattr(entry, "trace", None)
                or getattr(entry, "span_id", None)
                or f"cloud-log-{getattr(entry, 'insert_id', 'unknown')}"
            )
            trace_key = str(trace_id).split("/")[-1]
            mapped_sid = t_map.get(trace_key) or f"otel-{trace_key[:16]}"
            rec = grouped.setdefault(
                mapped_sid,
                {
                    "session_id": mapped_sid,
                    "source": "cloud_logging",
                    "trace_ids": [],
                    "otel_events_count": 0,
                    "conversation": [],
                    "tool_calls": [],
                    "final_response": "",
                },
            )
            if trace_key not in rec["trace_ids"]:
                rec["trace_ids"].append(trace_key)
            rec["otel_events_count"] = int(rec.get("otel_events_count", 0)) + 1

            payload = entry.payload if isinstance(entry.payload, dict) else {}
            labels = getattr(entry, "labels", None) or {}
            event_name = str(labels.get("event.name") or getattr(entry, "log_name", "") or "")

            content = payload.get("content") or payload.get("message") or payload
            parts = content.get("parts") if isinstance(content, dict) else None

            if isinstance(parts, list):
                for part in parts:
                    if not isinstance(part, dict):
                        continue
                    fc = part.get("function_call") or part.get("functionCall")
                    if isinstance(fc, dict) and fc.get("name"):
                        rec["tool_calls"].append(
                            {
                                "name": str(fc.get("name", "")),
                                "args": fc.get("args") or {},
                            }
                        )
                    fr = part.get("function_response") or part.get("functionResponse")
                    if isinstance(fr, dict) and fr.get("name"):
                        f_name = str(fr.get("name"))
                        f_resp = fr.get("response")
                        for existing_tc in reversed(rec["tool_calls"]):
                            if existing_tc.get("name") == f_name and existing_tc.get("response") is None:
                                existing_tc["response"] = f_resp
                                break
                    txt = part.get("text")
                    if isinstance(txt, str) and txt.strip():
                        clean_txt = txt.strip()
                        if clean_txt.startswith("For context:") or clean_txt.startswith("[secops_assistant]"):
                            continue
                        if "gen_ai.user.message" in event_name:
                            if not any(c["content"] == clean_txt for c in rec["conversation"]):
                                rec["conversation"].append({"role": "user", "content": clean_txt})
                        elif "gen_ai.choice" in event_name:
                            rec["final_response"] = f"{rec['final_response']}\n{clean_txt}".strip()
            elif "gen_ai.user.message" in event_name:
                raw_text = str(content).strip() if content else ""
                if raw_text and not any(c["content"] == raw_text for c in rec["conversation"]):
                    rec["conversation"].append({"role": "user", "content": raw_text})

        return [
            t
            for t in grouped.values()
            if t.get("conversation") or t.get("tool_calls") or t.get("final_response")
        ][:limit]
    except Exception as exc:
        typer.echo(f"[WARN] Cloud Logging trace query skipped: {exc}")
        return []


def _collect_eval_run_traces(limit: int = 100) -> list[dict[str, Any]]:
    """Collect multi-turn and single-turn trajectories from evalsets/eval_runs/run_*.json."""
    runs_dir = REPO_ROOT / "evalsets" / "eval_runs"
    if not runs_dir.exists():
        return []
    traces: list[dict[str, Any]] = []
    run_files = sorted(
        runs_dir.glob("run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    for run_file in run_files[:10]:
        try:
            data = json.loads(run_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        evalset_id = data.get("metadata", {}).get("evalset_id", run_file.stem)
        cases = data.get("cases") or {}
        for case_id, cdata in cases.items():
            if not isinstance(cdata, dict):
                continue
            conv = cdata.get("conversation") or []
            query = str(cdata.get("query") or "")
            final_resp = str(cdata.get("response") or "")
            # Skip legacy pre-HYP-007 ledger files that omitted both conversation and response
            if not conv and not query and not final_resp and not cdata.get("session_id"):
                continue
            if not conv and query:
                conv = [{"role": "user", "content": query}]
            raw_tools = cdata.get("detailed_tool_calls") or cdata.get("tool_calls") or []
            norm_tools = [
                t if isinstance(t, dict) else {"name": str(t), "args": {}}
                for t in raw_tools
            ]
            traces.append(
                {
                    "session_id": str(
                        cdata.get("session_id") or f"{evalset_id}:{case_id}"
                    ),
                    "case_id": case_id,
                    "evalset_id": evalset_id,
                    "source": f"eval_run:{run_file.name}",
                    "user_prompt": " ".join(
                        str(t.get("content") or "") for t in conv if isinstance(t, dict)
                    ).strip()
                    or query,
                    "conversation": conv,
                    "tool_calls": norm_tools,
                    "final_response": final_resp,
                }
            )
            if len(traces) >= limit:
                return traces
    return traces


def _merge_telemetry_sources(
    vertex_traces: list[dict[str, Any]],
    eval_traces: list[dict[str, Any]],
    cloud_trace_spans: list[dict[str, Any]],
    cloud_log_traces: list[dict[str, Any]],
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Merge Vertex Session traces, Cloud Trace span trees, Cloud Logging OTel events, and Eval Runs by session_id."""
    from aqua.custom_metrics import _normalize_trace_info

    merged_by_sid: dict[str, dict[str, Any]] = {}

    for trace in vertex_traces + eval_traces:
        sid = str(trace.get("session_id") or "")
        if not sid:
            continue
        if sid not in merged_by_sid:
            merged_by_sid[sid] = dict(trace)
            merged_by_sid[sid].setdefault("sources", [trace.get("source", "unknown")])
        else:
            existing = merged_by_sid[sid]
            src = trace.get("source", "unknown")
            if src not in existing.setdefault("sources", []):
                existing["sources"].append(src)

    # Merge Cloud Trace span trees
    for ct in cloud_trace_spans:
        sid = str(ct.get("session_id") or "")
        if not sid:
            continue
        if sid not in merged_by_sid:
            rec = dict(ct)
            rec["sources"] = ["cloud_trace"]
            merged_by_sid[sid] = rec
        else:
            existing = merged_by_sid[sid]
            if "cloud_trace" not in existing.setdefault("sources", []):
                existing["sources"].append("cloud_trace")
            existing["spans"] = ct.get("spans") or existing.get("spans") or []
            existing["trace_ids"] = sorted(
                set(existing.get("trace_ids") or []) | set(ct.get("trace_ids") or [])
            )
            if ct.get("otel_summary"):
                existing["otel_summary"] = ct["otel_summary"]
            if ct.get("reasoning_engine_id") and not existing.get("reasoning_engine_id"):
                existing["reasoning_engine_id"] = ct["reasoning_engine_id"]

    # Merge Cloud Logging OTel GenAI events
    for cl in cloud_log_traces:
        sid = str(cl.get("session_id") or "")
        if not sid:
            continue
        if sid not in merged_by_sid:
            rec = dict(cl)
            rec["sources"] = ["cloud_logging"]
            merged_by_sid[sid] = rec
        else:
            existing = merged_by_sid[sid]
            if "cloud_logging" not in existing.setdefault("sources", []):
                existing["sources"].append("cloud_logging")
            existing["otel_events_count"] = int(
                existing.get("otel_events_count", 0)
            ) + int(cl.get("otel_events_count", 0))
            existing["trace_ids"] = sorted(
                set(existing.get("trace_ids") or []) | set(cl.get("trace_ids") or [])
            )
            if not existing.get("conversation") and cl.get("conversation"):
                existing["conversation"] = cl["conversation"]
            if not existing.get("final_response") and cl.get("final_response"):
                existing["final_response"] = cl["final_response"]

    final_list: list[dict[str, Any]] = []
    for sid, item in merged_by_sid.items():
        norm = _normalize_trace_info(item)
        norm["source"] = "+".join(norm.get("sources") or [norm.get("source", "unknown")])
        final_list.append(norm)
        if len(final_list) >= limit:
            break
    return final_list


def run_native_aqua_audit(
    start_time: str = "-24h",
    trace_lookup_hours: int = 24,
    limit: int = 100,
    eval_config: str = DEFAULT_EVAL_CONFIG,
    project_id: str | None = None,
    insights_out: Path | None = None,
) -> dict[str, Any]:
    """Evaluate multi-turn trajectories with the 4 custom evaluators in aqua/custom_metrics.py and write aqua/insights.json."""
    from aqua.custom_metrics import evaluate as evaluate_aqua_trace

    latest_snap_path = DEFAULT_SNAPSHOT_ROOT / "latest.json"
    if latest_snap_path.exists():
        snap_manifest = json.loads(latest_snap_path.read_text(encoding="utf-8"))
    else:
        snap_manifest = create_source_snapshot(agent_module="agent_soc_manager")
    revision_label = snap_manifest.get("revision_label", "Revision 1")

    vertex_traces = _collect_vertex_session_traces(
        project_id=project_id,
        trace_lookup_hours=trace_lookup_hours,
        limit=limit,
    )
    eval_traces = _collect_eval_run_traces(limit=limit)
    cloud_trace_spans, trace_to_sid = _collect_cloud_trace_spans(
        project_id=project_id,
        trace_lookup_hours=trace_lookup_hours,
        limit=limit,
    )
    cloud_log_traces = _collect_cloud_logging_traces(
        project_id=project_id,
        trace_lookup_hours=trace_lookup_hours,
        limit=limit,
        trace_to_session_map=trace_to_sid,
    )

    all_traces = _merge_telemetry_sources(
        vertex_traces=vertex_traces,
        eval_traces=eval_traces,
        cloud_trace_spans=cloud_trace_spans,
        cloud_log_traces=cloud_log_traces,
        limit=limit,
    )

    total_spans_harvested = sum(len(t.get("spans") or []) for t in all_traces)
    total_otel_events = sum(int(t.get("otel_events_count", 0)) for t in all_traces)

    typer.echo("\n" + "=" * 80)
    typer.secho(
        f"AQuA OUTER-LOOP TRAJECTORY AUDIT ({revision_label}, config={eval_config}, window={start_time})",
        fg=typer.colors.CYAN,
        bold=True,
    )
    typer.echo(
        f"  Evaluated Traces: {len(all_traces)} "
        f"({len(vertex_traces)} Vertex Session(s), {len(cloud_trace_spans)} Cloud Trace Session(s) [{total_spans_harvested} OTel spans], "
        f"{len(cloud_log_traces)} Cloud Logging OTel Session(s) [{total_otel_events} GenAI events], {len(eval_traces)} Eval Run(s))"
    )
    typer.echo("=" * 80)

    metric_totals: dict[str, list[float]] = {
        "timerange_propagation_check": [],
        "soar_phase2_fallback_check": [],
        "subagent_context_forwarding_check": [],
        "design_spec_attribution_check": [],
    }
    failure_clusters: dict[str, list[dict[str, Any]]] = {
        m: [] for m in metric_totals
    }
    trace_reports: list[dict[str, Any]] = []

    for idx, trace in enumerate(all_traces, start=1):
        suite_res = evaluate_aqua_trace(trace)
        metrics_map = suite_res.get("metrics", {})
        turns_count = len(trace.get("conversation") or []) or 1
        sid = trace.get("session_id", f"trace-{idx}")
        otel_sum = trace.get("otel_summary") or {}
        span_cnt = int(otel_sum.get("span_count", len(trace.get("spans") or [])))
        ev_cnt = int(trace.get("otel_events_count", 0))
        in_tok = int(otel_sum.get("total_input_tokens", 0))
        out_tok = int(otel_sum.get("total_output_tokens", 0))
        status_str = "PASS" if suite_res["passed"] else "FAIL"
        typer.echo(
            f"  [{idx:02d}] {sid:<30} | turns={turns_count} | spans={span_cnt:<3} | otel_ev={ev_cnt:<3} | tokens={in_tok + out_tok:<7} | score={suite_res['score']:.2f} | {status_str}"
        )
        for m_name, m_res in metrics_map.items():
            if m_name in metric_totals:
                metric_totals[m_name].append(float(m_res.get("score", 0.0)))
            if not m_res.get("passed", True):
                typer.echo(f"       -> [FAIL] {m_name}: {m_res.get('explanation')}")
                failure_clusters.setdefault(m_name, []).append(
                    {"trace": trace, "metric_result": m_res}
                )
        trace_reports.append(
            {
                "session_id": sid,
                "source": trace.get("source", "unknown"),
                "turns": turns_count,
                "span_count": span_cnt,
                "otel_events_count": ev_cnt,
                "otel_summary": otel_sum,
                "score": suite_res["score"],
                "passed": suite_res["passed"],
                "metrics": metrics_map,
            }
        )

    insights: list[dict[str, Any]] = []
    for cluster_idx, (m_name, failures) in enumerate(failure_clusters.items(), start=1):
        if not failures:
            continue
        meta = _METRIC_CITATION_MAP.get(m_name, {})
        sample_trace = failures[0]["trace"]
        sample_explanation = failures[0]["metric_result"].get("explanation", "")
        insight_id = f"AQUA-INS-2026-01{cluster_idx:02d}"
        insights.append(
            {
                "insight_id": insight_id,
                "status": "NEW",
                "metric": m_name,
                "title": meta.get("title", f"AQuA Trajectory Failure: {m_name}"),
                "severity": meta.get("severity", "HIGH"),
                "impact": meta.get("impact", "HIGH"),
                "agent_revision": revision_label,
                "affected_sessions_count": len(failures),
                "code_citations": meta.get(
                    "code_citations",
                    ["agent_soc_manager/prompts/orchestrator_instructions.md:1-35"],
                ),
                "expected_behavior": f"{meta.get('expected_behavior', '')} ({sample_explanation})".strip(),
                "expected_specialist": "orchestrator_direct",
                "failing_trajectory": {
                    "session_id": sample_trace.get("session_id", "unknown"),
                    "user_prompt": sample_trace.get("user_prompt", ""),
                    "conversation": sample_trace.get("conversation", []),
                    "tool_calls": sample_trace.get("tool_calls", []),
                    "final_response": sample_trace.get("final_response", ""),
                },
            }
        )

    typer.echo("-" * 80)
    typer.echo("AQuA 4-EVALUATOR SUMMARY:")
    for m_name, scores in metric_totals.items():
        avg_m = (sum(scores) / len(scores) * 100.0) if scores else 100.0
        fail_n = len(failure_clusters.get(m_name, []))
        typer.echo(
            f"  - {m_name:<36}: {avg_m:6.1f}% pass score ({fail_n} failing session(s))"
        )
    typer.echo(f"  Discovered Failure Clusters (Insights): {len(insights)}")
    typer.echo("=" * 80 + "\n")

    out_path = insights_out or (REPO_ROOT / "aqua" / "insights.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_revision": revision_label,
        "evaluated_traces_count": len(all_traces),
        "insights": insights,
        "trace_reports": trace_reports,
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    typer.echo(f"[PASS] Wrote {len(insights)} AQuA insight(s) to {out_path}")
    return payload


@app.command("run")
def cli_run(
    start_time: Annotated[
        str,
        typer.Option("--start-time", help="Lookback start time (e.g. -24h)."),
    ] = "-24h",
    trace_lookup_hours: Annotated[
        int,
        typer.Option("--trace-lookup-hours", help="Trace lookup window in hours."),
    ] = 24,
    limit: Annotated[
        int,
        typer.Option("--limit", help="Maximum number of traces to sweep."),
    ] = 100,
    eval_config: Annotated[
        str,
        typer.Option("--eval-config", help="Path to AQuA eval_config.yaml."),
    ] = DEFAULT_EVAL_CONFIG,
    end_time: Annotated[
        str | None,
        typer.Option("--end-time", help="Optional end time."),
    ] = None,
    env_file: Annotated[
        Path,
        typer.Option("--env-file", help="Path to .env file."),
    ] = Path(".env"),
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print command without executing."),
    ] = False,
) -> None:
    """Trigger an AQuA outer-loop analysis run over production traces."""
    if env_file.exists():
        load_dotenv(env_file, override=False)
    project_id = os.environ.get("GCP_PROJECT_ID")
    cmd = build_aqua_run_command(
        start_time=start_time,
        eval_config=eval_config,
        end_time=end_time,
        project_id=project_id,
        trace_lookup_hours=trace_lookup_hours,
        limit=limit,
    )
    typer.echo(f"[INFO] Command: {' '.join(cmd)}")
    if dry_run:
        return
    if _has_agents_cli_aqua():
        subprocess.run(cmd, check=True)
    else:
        typer.echo(
            "[INFO] `agents-cli aqua` extension not installed; executing native AQuA 4-evaluator trajectory audit..."
        )
        run_native_aqua_audit(
            start_time=start_time,
            trace_lookup_hours=trace_lookup_hours,
            limit=limit,
            eval_config=eval_config,
            project_id=project_id,
        )


@app.command("ui")
def cli_ui(
    port: Annotated[
        int,
        typer.Option("--port", help="Local port for AQuA UI proxy."),
    ] = 8080,
    env_file: Annotated[
        Path,
        typer.Option("--env-file", help="Path to .env file."),
    ] = Path(".env"),
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print command without executing."),
    ] = False,
) -> None:
    """Launch the AQuA visualization UI proxy."""
    if env_file.exists():
        load_dotenv(env_file, override=False)
    project_id = os.environ.get("GCP_PROJECT_ID")
    cmd = build_aqua_ui_command(project_id=project_id, port=port)
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
