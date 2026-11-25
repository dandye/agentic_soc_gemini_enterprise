#!/usr/bin/env python3
"""Workflow 2: Progressive MCP Tool & SOC Runbook Pruning via Gemini Decision 1.

Demonstrates the flat-latency multi-question advantage of ``gemini-decision-1``
(1 ``choice`` question + N ``noul`` questions in 1 pass, 0 output tokens) and
verifies multi-turn prefix KV-cache pinning across a 3-step ReAct trajectory:
  - Step 1: User turn -> 1 Decision 1 RPC, pins ``kept_tools`` + ``selected_runbook``.
  - Step 2: Tool response turn -> 0 RPCs, 0.0 ms, byte-identical prefix hash.
  - Step 3: Tool response turn -> 0 RPCs, 0.0 ms, byte-identical prefix hash.

Usage:
    .venv/bin/python scripts/governance/workflows/run_workflow2_tool_pruning.py
    .venv/bin/python scripts/governance/workflows/run_workflow2_tool_pruning.py --dry-run
    .venv/bin/python scripts/governance/workflows/run_workflow2_tool_pruning.py --threshold 0.50
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import pathlib
import statistics
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any

from google.genai import types


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from governed_agents.shared_decision_guards.progressive_tool_pruner import (  # noqa: E402
    DEFAULT_PRUNE_THRESHOLD,
    SOC_TOOL_CATALOG,
    ToolCatalogEntry,
    apply_decision_pruning,
    build_baseline_llm_request,
    compute_prefix_hash,
    prune_with_session_pinning_async,
)


DEFAULT_JSON_OUT = str(
    pathlib.Path(tempfile.gettempdir())
    / "decision1_v2_results"
    / "workflow2_tool_pruning.json"
)


@dataclass(frozen=True)
class PruningScenario:
    scenario_id: str
    title: str
    prompt: str
    expected_runbook: str
    required_tools: tuple[str, ...]
    extra_dynamic_tools: tuple[ToolCatalogEntry, ...] = ()


_DYNAMIC_ONEMCP_TOOLS: tuple[ToolCatalogEntry, ...] = (
    ToolCatalogEntry(
        name="chronicle_export_udm_timeline",
        category="dynamic_onemcp",
        description=(
            "Export a chronological UDM timeline CSV/JSON bundle for a host or "
            "user investigation."
        ),
        decision_prompt="",
        parameters={
            "type": "OBJECT",
            "properties": {
                "hostname": {"type": "STRING", "description": "Target hostname."},
                "start_time": {"type": "STRING", "description": "RFC3339 start."},
                "end_time": {"type": "STRING", "description": "RFC3339 end."},
            },
            "required": ["hostname"],
        },
    ),
    ToolCatalogEntry(
        name="chronicle_list_case_comments",
        category="dynamic_onemcp",
        description=(
            "List analyst comments and timeline notes on a Chronicle SOAR case."
        ),
        decision_prompt="",
        parameters={
            "type": "OBJECT",
            "properties": {
                "case_id": {"type": "STRING", "description": "SOAR case ID."}
            },
            "required": ["case_id"],
        },
    ),
)


SCENARIOS: tuple[PruningScenario, ...] = (
    PruningScenario(
        scenario_id="udm_credential_dump_hunt",
        title="UDM Credential Dump Hunt",
        prompt=(
            "Investigate alert alt-9921 on host wkstn-fin-04 where rundll32.exe "
            "invoked comsvcs.dll MiniDump against lsass.exe at 2026-11-14T03:15:00Z. "
            "Fetch the alert details, search UDM process telemetry around that "
            "window, and summarize the host and user entity activity."
        ),
        expected_runbook="credential_dump_hunt",
        required_tools=(
            "get_security_alert",
            "fetch_alert_data",
            "udm_search",
            "search_entity",
            "summarize_entity",
        ),
    ),
    PruningScenario(
        scenario_id="cti_hash_lookup",
        title="CTI Hash & Campaign Enrichment",
        prompt=(
            "Look up SHA-256 file hash "
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f "
            "in Google Threat Intelligence (GTI) and fetch threat collection "
            "col-apt29-lumma to see if it is linked to an active campaign."
        ),
        expected_runbook="cti_enrichment",
        required_tools=(
            "lookup_file_hash_reputation",
            "get_threat_collection",
        ),
    ),
    PruningScenario(
        scenario_id="yaral_rule_tuning",
        title="YARA-L 2.0 Rule Tuning",
        prompt=(
            "Rule ru_4410 is generating noisy false positives. Fetch the rule "
            "definition, list its recent detections and any runtime errors, "
            "validate the updated YARA-L 2.0 syntax, and evaluate historical "
            "coverage over the past 7 days."
        ),
        expected_runbook="detection_rule_tuning",
        required_tools=(
            "get_rule",
            "list_rule_detections",
            "list_rule_errors",
            "validate_rule",
            "evaluate_rule_coverage",
        ),
    ),
    PruningScenario(
        scenario_id="tier2_containment",
        title="Tier-2 Crown Jewel Containment",
        prompt=(
            "Confirmed ransomware staging on crown-jewel server srv-ad-02 via "
            "account svc_backup (alert alt-7741). Isolate the endpoint host, "
            "disable the compromised account, add C2 IP 198.51.100.44 to the "
            "containment reference list, and update alert alt-7741 to CLOSED."
        ),
        expected_runbook="crown_jewel_containment",
        required_tools=(
            "isolate_endpoint_host",
            "disable_compromised_account",
            "update_reference_list",
            "update_security_alert",
        ),
    ),
    PruningScenario(
        scenario_id="phishing_triage",
        title="Phishing Email & Link Triage",
        prompt=(
            "Triage a user-reported phishing email from billing@paypa1-secure.com "
            "with attachment SHA-256 a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0. "
            "Enrich the sender domain and attachment hash in GTI, search UDM "
            "email/proxy logs for other recipients, and post a phishing summary card."
        ),
        expected_runbook="phishing_triage",
        required_tools=(
            "lookup_domain_reputation",
            "lookup_file_hash_reputation",
            "udm_search",
            "trigger_phishing_report_summary_card",
        ),
    ),
    PruningScenario(
        scenario_id="general_alert_queue_triage",
        title="General Alert Queue Triage",
        prompt=(
            "Give me a situational awareness summary of all open HIGH and "
            "CRITICAL Chronicle SIEM security alerts from the last 24 hours."
        ),
        expected_runbook="general_triage",
        required_tools=("list_security_alerts",),
    ),
    PruningScenario(
        scenario_id="multi_domain_c2_containment",
        title="Multi-Domain C2 Enrichment & Containment",
        prompt=(
            "Alert alt-8830 shows wkstn-eng-19 beaconing to IP 203.0.113.77. "
            "Enrich the IP in GTI, check Chronicle IoC matches, and isolate "
            "wkstn-eng-19 immediately."
        ),
        expected_runbook="crown_jewel_containment",
        required_tools=(
            "get_security_alert",
            "lookup_ip_reputation",
            "get_ioc_match",
            "isolate_endpoint_host",
        ),
    ),
    PruningScenario(
        scenario_id="unstructured_cti_advisory",
        title="Unstructured CTI Advisory Triage",
        prompt=(
            "Extract IOCs and actionability from this unstructured CTI advisory "
            "about Scattered Spider, and check if any extracted indicators "
            "matched internal Chronicle IoC feeds."
        ),
        expected_runbook="cti_enrichment",
        required_tools=(
            "triage_unstructured_cti_artifact",
            "get_ioc_match",
        ),
    ),
    PruningScenario(
        scenario_id="synthetic_rule_coverage_check",
        title="Synthetic Event YARA-L Verification",
        prompt=(
            "Generate synthetic UDM events for MITRE T1003.001, translate our "
            "natural-language hunt criteria into UDM, and validate the new "
            "YARA-L 2.0 detection rule."
        ),
        expected_runbook="detection_rule_tuning",
        required_tools=(
            "generate_synthetic_events",
            "translate_udm_query",
            "validate_rule",
        ),
    ),
    PruningScenario(
        scenario_id="dynamic_onemcp_timeline_export",
        title="Dynamic Non-Catalog OneMCP Tool Discovery",
        prompt=(
            "Hunt UDM logs for lateral movement on srv-app-07 and use "
            "`chronicle_export_udm_timeline` to export the chronological UDM "
            "timeline bundle for the host."
        ),
        expected_runbook="credential_dump_hunt",
        required_tools=(
            "udm_search",
            "chronicle_export_udm_timeline",
        ),
        extra_dynamic_tools=_DYNAMIC_ONEMCP_TOOLS,
    ),
)


def _ensure_api_key(secret_name: str) -> None:
    if (
        os.getenv("GEMINI_AUTH_PROVIDER", "").strip()
        or os.getenv("GEMINI_API_KEY", "").strip()
    ):
        return
    proc = subprocess.run(
        [
            "gcloud",
            "secrets",
            "versions",
            "access",
            "latest",
            f"--secret={secret_name}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        os.environ["GEMINI_API_KEY"] = proc.stdout.strip()
        return
    raise RuntimeError(
        "GEMINI_API_KEY / GEMINI_AUTH_PROVIDER unset and `gcloud secrets "
        f"versions access latest --secret={secret_name}` failed."
    )


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return round(ordered[idx], 2)


def _compute_recall_precision(
    kept_tools: tuple[str, ...], required_tools: tuple[str, ...]
) -> tuple[float, float, tuple[str, ...]]:
    kept_set = set(kept_tools)
    req_set = set(required_tools)
    hits = req_set & kept_set
    missing = tuple(sorted(req_set - kept_set))
    recall = len(hits) / len(req_set) if req_set else 1.0
    precision = len(hits) / len(kept_set) if kept_set else 0.0
    return round(recall, 4), round(precision, 4), missing


def _simulate_dry_decision(
    scenario: PruningScenario, tools: tuple[ToolCatalogEntry, ...]
) -> dict[str, Any]:
    answers: dict[str, Any] = {
        "select_runbook": {
            "type": "choice",
            "choice": scenario.expected_runbook,
            "confidence": 0.95,
        }
    }
    req_set = set(scenario.required_tools)
    for entry in tools:
        is_req = entry.name in req_set
        answers[f"tool_needed_{entry.name}"] = {
            "type": "noul",
            "noul": 0.92 if is_req else 0.06,
            "confidence": 0.94,
        }
    return {
        "enabled": True,
        "model": "gemini-decision-1",
        "answers": answers,
        "usage": {
            "total_input_tokens": 1150,
            "total_output_tokens": 0,
        },
    }


def _append_simulated_tool_step(req: Any, tool_name: str, step_idx: int) -> None:
    req.contents.append(
        types.Content(
            role="model",
            parts=[
                types.Part(
                    function_call=types.FunctionCall(
                        name=tool_name,
                        args={"step": step_idx},
                    )
                )
            ],
        )
    )
    req.contents.append(
        types.Content(
            role="user",
            parts=[
                types.Part(
                    function_response=types.FunctionResponse(
                        name=tool_name,
                        response={"status": "ok", "step": step_idx},
                    )
                )
            ],
        )
    )


async def run_workflow(
    *,
    dry_run: bool = False,
    threshold: float = DEFAULT_PRUNE_THRESHOLD,
    secret_name: str = "gemini-api-key",
    json_out: str | None = DEFAULT_JSON_OUT,
) -> dict[str, Any]:
    if not dry_run:
        _ensure_api_key(secret_name)

    records: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        tools = SOC_TOOL_CATALOG + scenario.extra_dynamic_tools
        state: dict[str, Any] = {}

        # Step 1: Initial user turn -> 1 Decision 1 RPC
        req_step1 = build_baseline_llm_request(scenario.prompt, tools=tools)
        if dry_run:
            tool_names = [entry.name for entry in tools]
            res1 = apply_decision_pruning(
                req_step1,
                _simulate_dry_decision(scenario, tools),
                tool_names=tool_names,
                threshold=threshold,
                decision_latency_ms=195.0,
            )
            state["tool_pruner_pinned_prompt"] = scenario.prompt
            state["tool_pruner_pinned_plan"] = {
                "kept_tools": list(res1.kept_tools),
                "selected_runbook": res1.selected_runbook,
                "runbook_confidence": res1.runbook_confidence,
                "decision_input_tokens": res1.decision_input_tokens,
            }
            step1_rpcs = 1
        else:
            res1 = await prune_with_session_pinning_async(
                state, req_step1, threshold=threshold
            )
            step1_rpcs = int(res1.extra.get("rpc_count", 0))
        hash1 = compute_prefix_hash(req_step1)

        # Step 2: Tool-response turn -> 0 RPCs, 0.0 ms, byte-identical prefix hash
        req_step2 = build_baseline_llm_request(scenario.prompt, tools=tools)
        first_tool = res1.kept_tools[0] if res1.kept_tools else "udm_search"
        _append_simulated_tool_step(req_step2, first_tool, 2)
        res2 = await prune_with_session_pinning_async(
            state, req_step2, threshold=threshold
        )
        hash2 = compute_prefix_hash(req_step2)

        # Step 3: Second tool-response turn -> 0 RPCs, 0.0 ms, byte-identical prefix hash
        req_step3 = build_baseline_llm_request(scenario.prompt, tools=tools)
        _append_simulated_tool_step(req_step3, first_tool, 2)
        _append_simulated_tool_step(req_step3, first_tool, 3)
        res3 = await prune_with_session_pinning_async(
            state, req_step3, threshold=threshold
        )
        hash3 = compute_prefix_hash(req_step3)

        kv_cache_intact = hash1 == hash2 == hash3
        total_rpcs_3step = (
            step1_rpcs
            + int(res2.extra.get("rpc_count", 0))
            + int(res3.extra.get("rpc_count", 0))
        )
        net_3step_tokens_saved = (
            3 * res1.estimated_tokens_saved - res1.decision_input_tokens
        )

        recall, precision, missing = _compute_recall_precision(
            res1.kept_tools, scenario.required_tools
        )
        records.append(
            {
                "scenario_id": scenario.scenario_id,
                "title": scenario.title,
                "expected_runbook": scenario.expected_runbook,
                "selected_runbook": res1.selected_runbook,
                "runbook_match": res1.selected_runbook == scenario.expected_runbook,
                "runbook_confidence": res1.runbook_confidence,
                "required_tools": list(scenario.required_tools),
                "kept_tools": list(res1.kept_tools),
                "kept_count": len(res1.kept_tools),
                "total_tools": len(res1.kept_tools) + len(res1.pruned_tools),
                "missing_required_tools": list(missing),
                "tool_recall": recall,
                "tool_precision": precision,
                "decision_latency_ms": res1.decision_latency_ms,
                "step2_latency_ms": res2.decision_latency_ms,
                "step3_latency_ms": res3.decision_latency_ms,
                "total_rpcs_3step": total_rpcs_3step,
                "kv_cache_prefix_intact": kv_cache_intact,
                "prefix_hash": hash1[:16],
                "decision_input_tokens": res1.decision_input_tokens,
                "decision_output_tokens": res1.decision_output_tokens,
                "baseline_schema_bytes": res1.baseline_schema_bytes,
                "pruned_schema_bytes": res1.pruned_schema_bytes,
                "baseline_runbook_bytes": res1.baseline_runbook_bytes,
                "pruned_runbook_bytes": res1.pruned_runbook_bytes,
                "baseline_total_bytes": res1.baseline_total_bytes,
                "pruned_total_bytes": res1.pruned_total_bytes,
                "bytes_saved": res1.bytes_saved,
                "reduction_pct": res1.reduction_pct,
                "estimated_tokens_saved_per_step": res1.estimated_tokens_saved,
                "net_3step_tokens_saved": net_3step_tokens_saved,
                "fallback_triggered": res1.fallback_triggered,
                "error": res1.error,
            }
        )

    latencies = [r["decision_latency_ms"] for r in records]
    summary = {
        "mode": "dry_run" if dry_run else "live",
        "threshold": threshold,
        "base_catalog_tool_count": len(SOC_TOOL_CATALOG),
        "scenarios_evaluated": len(records),
        "runbook_accuracy": round(
            sum(1 for r in records if r["runbook_match"]) / len(records), 4
        ),
        "mean_tool_recall": round(
            statistics.mean(r["tool_recall"] for r in records), 4
        ),
        "mean_tool_precision": round(
            statistics.mean(r["tool_precision"] for r in records), 4
        ),
        "mean_kept_tools": round(statistics.mean(r["kept_count"] for r in records), 2),
        "mean_decision_latency_ms": round(statistics.mean(latencies), 2),
        "p50_decision_latency_ms": _percentile(latencies, 50),
        "p95_decision_latency_ms": _percentile(latencies, 95),
        "total_decision_output_tokens": sum(
            r["decision_output_tokens"] for r in records
        ),
        "kv_cache_intact_count": sum(1 for r in records if r["kv_cache_prefix_intact"]),
        "total_rpcs_across_30_steps": sum(r["total_rpcs_3step"] for r in records),
        "mean_bytes_saved": round(
            statistics.mean(r["bytes_saved"] for r in records), 1
        ),
        "mean_reduction_pct": round(
            statistics.mean(r["reduction_pct"] for r in records), 2
        ),
        "mean_estimated_tokens_saved_per_step": round(
            statistics.mean(r["estimated_tokens_saved_per_step"] for r in records), 1
        ),
        "mean_net_3step_tokens_saved": round(
            statistics.mean(r["net_3step_tokens_saved"] for r in records), 1
        ),
        "total_net_3step_tokens_saved": sum(
            r["net_3step_tokens_saved"] for r in records
        ),
    }

    payload = {"summary": summary, "scenarios": records}
    if json_out:
        out_path = pathlib.Path(json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def _print_report(payload: dict[str, Any]) -> None:
    s = payload["summary"]
    print(
        f"Workflow 2 Tool & Runbook Pruning ({s['mode']} | "
        f"scenarios={s['scenarios_evaluated']} | threshold={s['threshold']})"
    )
    print(
        f"  Decision 1 Step-1 latency: mean={s['mean_decision_latency_ms']} ms, "
        f"p50={s['p50_decision_latency_ms']} ms, p95={s['p95_decision_latency_ms']} ms, "
        f"output_tokens={s['total_decision_output_tokens']}"
    )
    print(
        f"  3-Step KV-Cache Pinning: intact={s['kv_cache_intact_count']}/{s['scenarios_evaluated']}, "
        f"total_rpcs={s['total_rpcs_across_30_steps']}/30 steps"
    )
    print(
        f"  Runbook accuracy={s['runbook_accuracy']:.2%} | "
        f"Tool recall={s['mean_tool_recall']:.2%}, "
        f"precision={s['mean_tool_precision']:.2%} | "
        f"Avg kept tools={s['mean_kept_tools']}/{s['base_catalog_tool_count']}"
    )
    print(
        f"  Prefill savings: mean={s['mean_bytes_saved']} B/step "
        f"({s['mean_reduction_pct']}% reduction, ~{s['mean_estimated_tokens_saved_per_step']} tok/step) | "
        f"Net 3-step savings: mean={s['mean_net_3step_tokens_saved']} tok/trajectory "
        f"(total={s['total_net_3step_tokens_saved']} tok)"
    )
    print("-" * 96)
    for r in payload["scenarios"]:
        print(
            f"  [{r['scenario_id']}] rb={r['selected_runbook']} "
            f"(match={r['runbook_match']}, conf={r['runbook_confidence']:.2f}) | "
            f"kept={r['kept_count']}/{r['total_tools']} | "
            f"rec={r['tool_recall']:.2f} prec={r['tool_precision']:.2f} | "
            f"kv={r['kv_cache_prefix_intact']} rpcs={r['total_rpcs_3step']} | "
            f"net3={r['net_3step_tokens_saved']}tok | lat={r['decision_latency_ms']}ms"
        )
        if r["missing_required_tools"]:
            print(f"    missing: {r['missing_required_tools']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--threshold", type=float, default=DEFAULT_PRUNE_THRESHOLD)
    parser.add_argument("--secret-name", default="gemini-api-key")
    parser.add_argument("--json-out", default=DEFAULT_JSON_OUT)
    args = parser.parse_args()

    payload = asyncio.run(
        run_workflow(
            dry_run=args.dry_run,
            threshold=args.threshold,
            secret_name=args.secret_name,
            json_out=args.json_out,
        )
    )
    _print_report(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
