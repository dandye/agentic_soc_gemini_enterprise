#!/usr/bin/env python3
"""Benchmark comparing standard generative Flash JSON vs Gemini Decision 1.

Evaluates both models across three governed SOC workloads:
  1. Orchestrator preflight routing (specialist selection, workflow mode, urgency)
  2. Chronicle SIEM alert / UDM rubric triage (severity, true positive, tactic, action)
  3. Chronicle SIEM YARA-L 2.0 rule grading (quality, FP risk, tactic, YARA-L 2.0 vs YARA)

Measures per-call and aggregate input tokens, output tokens (0 for Decision 1),
latency (mean, p50, p95 ms), cost ($0.10/1M input and $0 output for Decision 1),
label accuracy, and structured probability/confidence outputs.

Usage:
    .venv/bin/python scripts/governance/benchmark_decision1.py --dry-run
    .venv/bin/python scripts/governance/benchmark_decision1.py --json-out /tmp/bench.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

import httpx


DECISIONS_URL = "https://generativelanguage.googleapis.com/v1beta/decisions"
GENERATE_URL_TMPL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)

DEFAULT_GEN_MODEL = "gemini-2.5-flash"
DEFAULT_DECISION_MODEL = "gemini-decision-1"

# Pricing in USD per 1M tokens.
DECISION1_INPUT_PER_M = 0.10
DECISION1_OUTPUT_PER_M = 0.0
DEFAULT_GEN_INPUT_PER_M = 0.30
DEFAULT_GEN_OUTPUT_PER_M = 2.50


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    workload: str
    input_text: str
    questions: dict[str, dict[str, Any]]
    expected: dict[str, Any]


PREFLIGHT_QUESTIONS: dict[str, dict[str, Any]] = {
    "needs_cti": {
        "type": "noul",
        "instructions": (
            "Does the request ask to look up or enrich a file hash, domain, IP "
            "address, URL, or threat collection in threat intelligence?"
        ),
    },
    "needs_threat_hunt": {
        "type": "noul",
        "instructions": (
            "Does the request ask to search SIEM logs or UDM telemetry, list or "
            "triage security alerts, inspect entity context, or check SIEM feeds?"
        ),
    },
    "needs_detection_eng": {
        "type": "noul",
        "instructions": (
            "Does the request ask to author, validate, audit, or test a Chronicle "
            "SIEM YARA-L 2.0 detection rule or manage a SIEM parser?"
        ),
    },
    "needs_tier2_response": {
        "type": "noul",
        "instructions": (
            "Does the request ask to isolate an endpoint host, disable a user "
            "account, update an alert status, or modify a containment list?"
        ),
    },
    "has_change_ticket": {
        "type": "noul",
        "instructions": (
            "Does the request explicitly reference a change ticket identifier "
            "such as CHG-12345 or an approved emergency change ID?"
        ),
    },
    "workflow_mode": {
        "type": "choice",
        "instructions": "Select the most appropriate orchestration workflow mode.",
        "criteria": {
            "single_specialist": "Route directly to one matching specialist agent.",
            "multi_stage_investigation": "Coordinate two or more specialists.",
            "containment_action": "Execute or validate a containment action.",
            "other": "General security operations question or unclear scope.",
        },
    },
    "urgency": {
        "type": "score",
        "instructions": (
            "Rate operational urgency from level 0 (routine) to level 4 (critical)."
        ),
        "criteria": [
            "Level 0: Routine informational query or syntax check.",
            "Level 1: Low-priority enrichment or hygiene check.",
            "Level 2: Standard alert triage or suspicious indicator review.",
            "Level 3: High-priority active threat hunt or confirmed malicious IOC.",
            "Level 4: Critical active incident or immediate containment.",
        ],
    },
}

TRIAGE_QUESTIONS: dict[str, dict[str, Any]] = {
    "severity": {
        "type": "score",
        "instructions": (
            "Score the overall security severity of this Chronicle SIEM alert "
            "or UDM event batch from level 0 (benign) to level 4 (critical)."
        ),
        "criteria": [
            "Informational or benign activity with no security impact.",
            "Low severity anomaly or policy notice requiring routine review.",
            "Medium severity suspicious activity warranting investigation.",
            "High severity likely threat activity with host or account impact.",
            "Critical active compromise, lateral movement, or exfiltration.",
        ],
    },
    "true_positive": {
        "type": "noul",
        "instructions": (
            "Determine whether this alert or UDM event batch represents a true "
            "positive security threat rather than benign administrative activity."
        ),
    },
    "mitre_tactic": {
        "type": "choice",
        "instructions": "Select the primary MITRE ATT&CK tactic represented.",
        "criteria": {
            "initial_access": "Phishing, exploit public app, or remote entry.",
            "execution": "Command/scripting interpreter or malicious binary.",
            "persistence": "Scheduled tasks, run keys, or startup changes.",
            "privilege_escalation": "Token manipulation, sudo abuse, or UAC bypass.",
            "defense_evasion": "Log clearing, disabling security tools, obfuscation.",
            "credential_access": "LSASS dumping, brute force, or Kerberoasting.",
            "discovery": "Network scanning or host/account enumeration.",
            "lateral_movement": "SMB, WinRM, RDP, or SSH pivoting across hosts.",
            "collection_exfiltration": "Staging archives or DNS/HTTP exfiltration.",
            "command_and_control": "Beaconing, C2 callbacks, or covert channels.",
            "other_or_benign": "Other tactic or benign/inconclusive activity.",
        },
    },
    "next_action": {
        "type": "choice",
        "instructions": "Select the recommended next SOC triage action.",
        "criteria": {
            "dismiss": "Benign or clear false positive; close without escalation.",
            "enrich_cti": "Suspicious IOCs present; enrich via CTI first.",
            "escalate_tier2": "High-confidence threat; escalate to Tier 2.",
            "tune_yaral2": "Overly broad YARA-L 2.0 rule; send for tuning.",
        },
    },
}

YARAL2_QUESTIONS: dict[str, dict[str, Any]] = {
    "rule_quality_score": {
        "type": "score",
        "instructions": (
            "Rate the engineering quality of this Chronicle SIEM YARA-L 2.0 "
            "UDM rule from level 0 (broken/non-YARA-L 2.0) to level 4 (production)."
        ),
        "criteria": [
            "Broken or non-YARA-L 2.0 rule (e.g., standard file/payload YARA).",
            "Minimal YARA-L 2.0 draft with major structural gaps or broad filters.",
            "Functional YARA-L 2.0 UDM rule missing tuning or outcome enrichment.",
            "Well-structured YARA-L 2.0 UDM rule with specific event filters.",
            "Production-grade YARA-L 2.0 UDM rule with complete sections and tuning.",
        ],
    },
    "false_positive_risk": {
        "type": "choice",
        "instructions": "Classify expected false-positive risk in an enterprise SOC.",
        "criteria": {
            "low": "Specific UDM predicates and exclusions minimize benign noise.",
            "medium": "Moderate specificity; may match some benign admin activity.",
            "high": "Overly broad UDM matching likely to produce high noise.",
            "unknown": "Insufficient rule logic or context to assess risk.",
        },
    },
    "mitre_tactic": {
        "type": "choice",
        "instructions": "Select the primary MITRE ATT&CK tactic targeted.",
        "criteria": {
            "credential_access": "Credential dumping, brute force, Kerberoasting.",
            "defense_evasion": "Tampering with security tools or evading controls.",
            "exfiltration": "Data exfiltration over DNS or other channels.",
            "impact": "Shadow copy deletion, ransomware encryption, destruction.",
            "other_or_unknown": "Unclear or non-YARA-L 2.0 rule.",
        },
    },
    "has_required_yaral2_sections": {
        "type": "noul",
        "instructions": (
            "Does the rule use Chronicle SIEM YARA-L 2.0 structure (meta, events, "
            "condition with UDM predicates) rather than standard file/payload YARA?"
        ),
    },
    "ready_for_validation": {
        "type": "noul",
        "instructions": (
            "Is this YARA-L 2.0 UDM rule complete and coherent enough to submit "
            "to Chronicle validate_rule?"
        ),
    },
}


CASES: tuple[BenchmarkCase, ...] = (
    # --- Workload 1: Orchestrator preflight routing ---
    BenchmarkCase(
        case_id="preflight_multi_specialist",
        workload="preflight",
        input_text=(
            "Run a four-part governed SOC check: (1) ask Threat_Hunter to list "
            "Chronicle SIEM alerts; (2) ask CTI_Researcher to look up GTI domain "
            "reputation for evil-c2.example; (3) ask Detection_Engineer to validate "
            "a YARA-L 2.0 rule; and (4) ask Tier2_Responder to isolate WKSTN-FIN-042."
        ),
        questions=PREFLIGHT_QUESTIONS,
        expected={
            "needs_cti": True,
            "needs_threat_hunt": True,
            "needs_detection_eng": True,
            "needs_tier2_response": True,
            "has_change_ticket": False,
            "workflow_mode": "multi_stage_investigation",
        },
    ),
    BenchmarkCase(
        case_id="preflight_tier0_with_chg",
        workload="preflight",
        input_text=(
            "Direct Tier2_Responder to isolate host DC-PROD-01 immediately for "
            "confirmed Active Directory compromise under approved emergency "
            "change ticket CHG-20261105."
        ),
        questions=PREFLIGHT_QUESTIONS,
        expected={
            "needs_cti": False,
            "needs_threat_hunt": False,
            "needs_detection_eng": False,
            "needs_tier2_response": True,
            "has_change_ticket": True,
            "workflow_mode": "containment_action",
        },
    ),
    BenchmarkCase(
        case_id="preflight_cti_only",
        workload="preflight",
        input_text=(
            "Look up the VirusTotal GTI reputation and threat collections for "
            "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
        ),
        questions=PREFLIGHT_QUESTIONS,
        expected={
            "needs_cti": True,
            "needs_threat_hunt": False,
            "needs_detection_eng": False,
            "needs_tier2_response": False,
            "has_change_ticket": False,
            "workflow_mode": "single_specialist",
        },
    ),
    BenchmarkCase(
        case_id="preflight_yaral2_only",
        workload="preflight",
        input_text=(
            "Validate the syntax of this Chronicle SIEM YARA-L 2.0 rule and check "
            "rule coverage for WINDOWS_SYSMON PROCESS_LAUNCH events."
        ),
        questions=PREFLIGHT_QUESTIONS,
        expected={
            "needs_cti": False,
            "needs_threat_hunt": False,
            "needs_detection_eng": True,
            "needs_tier2_response": False,
            "has_change_ticket": False,
            "workflow_mode": "single_specialist",
        },
    ),
    # --- Workload 2: Alert / UDM rubric triage ---
    BenchmarkCase(
        case_id="triage_mimikatz_lsass",
        workload="triage",
        input_text=json.dumps(
            {
                "log_type": "WINDOWS_SYSMON",
                "event_type": "PROCESS_OPEN",
                "principal": {"hostname": "WKSTN-FIN-042", "user": "svc_backup"},
                "target": {
                    "process": {
                        "file": {"full_path": "C:\\Windows\\System32\\lsass.exe"}
                    }
                },
                "src_process": "C:\\Users\\Public\\m64.exe",
                "command_line": "m64.exe privilege::debug sekurlsa::logonpasswords exit",
                "granted_access": "0x1010",
            }
        ),
        questions=TRIAGE_QUESTIONS,
        expected={
            "true_positive": True,
            "mitre_tactic": "credential_access",
            "next_action": "escalate_tier2",
        },
    ),
    BenchmarkCase(
        case_id="triage_dns_tunneling",
        workload="triage",
        input_text=json.dumps(
            {
                "log_type": "GCP_DNS",
                "principal": {"resource_name": "gce-vm-prod-app-03"},
                "distinct_subdomains_10m": 47,
                "sample_queries": [
                    "7f9a4b1c8e2d0f3a6b5c4d2e1f0a9b8c.exfil.bad-actor.example",
                    "8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d.exfil.bad-actor.example",
                ],
                "record_type": "TXT",
            }
        ),
        questions=TRIAGE_QUESTIONS,
        expected={
            "true_positive": True,
            "mitre_tactic": "collection_exfiltration",
        },
    ),
    BenchmarkCase(
        case_id="triage_shadow_copy_delete",
        workload="triage",
        input_text=json.dumps(
            {
                "log_type": "WINDOWS_SYSMON",
                "event_type": "PROCESS_LAUNCH",
                "principal": {"hostname": "SRV-FILE-02", "user": "SYSTEM"},
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "parent_process": "powershell.exe -EncodedCommand JAB...",
            }
        ),
        questions=TRIAGE_QUESTIONS,
        expected={
            "true_positive": True,
            "next_action": "escalate_tier2",
        },
    ),
    BenchmarkCase(
        case_id="triage_benign_admin_scan",
        workload="triage",
        input_text=json.dumps(
            {
                "log_type": "WINEVTLOG",
                "event_id": 4624,
                "principal": {"user": "svc_qualys_scanner", "ip": "10.20.0.15"},
                "target": {"hostname": "WKSTN-HR-108"},
                "note": "Authorized weekly vulnerability scan window Tuesday 02:00 UTC.",
            }
        ),
        questions=TRIAGE_QUESTIONS,
        expected={
            "true_positive": False,
            "next_action": "dismiss",
        },
    ),
    # --- Workload 3: YARA-L 2.0 rule grading ---
    BenchmarkCase(
        case_id="yaral2_dns_tunneling",
        workload="yaral2",
        input_text=(
            "rule dns_tunneling_distinct_subdomains_T1048 {\n"
            "  meta:\n"
            '    author = "SOC Detection Team"\n'
            '    severity = "High"\n'
            '    mitre_attack_tactic = "Exfiltration"\n'
            "  events:\n"
            '    $e.metadata.log_type = "GCP_DNS"\n'
            "    $e.network.dns.questions.name = /^[a-f0-9]{24,}\\..+\\..+/ nocase\n"
            "    $e.principal.resource.name = $vm\n"
            "  match:\n"
            "    $vm over 10m\n"
            "  outcome:\n"
            "    $risk_score = 90\n"
            "    $distinct_subdomains = count_distinct($e.network.dns.questions.name)\n"
            "  condition:\n"
            "    $e and $distinct_subdomains > 8\n"
            "}"
        ),
        questions=YARAL2_QUESTIONS,
        expected={
            "has_required_yaral2_sections": True,
            "ready_for_validation": True,
            "mitre_tactic": "exfiltration",
        },
    ),
    BenchmarkCase(
        case_id="yaral2_shadow_copy",
        workload="yaral2",
        input_text=(
            "rule akira_shadow_copy_deletion_T1490 {\n"
            "  meta:\n"
            '    author = "SOC Detection Team"\n'
            '    severity = "High"\n'
            '    mitre_attack_tactic = "Impact"\n'
            "  events:\n"
            '    $e.metadata.log_type = "WINDOWS_SYSMON"\n'
            '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
            "    $e.target.process.command_line = /vssadmin(\\.exe)?\\s+delete\\s+shadows/ nocase\n"
            "    $e.principal.hostname = $host\n"
            "  match:\n"
            "    $host over 10m\n"
            "  outcome:\n"
            "    $risk_score = 85\n"
            "  condition:\n"
            "    $e\n"
            "}"
        ),
        questions=YARAL2_QUESTIONS,
        expected={
            "has_required_yaral2_sections": True,
            "ready_for_validation": True,
            "mitre_tactic": "impact",
        },
    ),
    BenchmarkCase(
        case_id="yaral2_overly_broad_draft",
        workload="yaral2",
        input_text=(
            "rule noisy_process_launch {\n"
            "  meta:\n"
            '    author = "draft"\n'
            "  events:\n"
            '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
            "  condition:\n"
            "    $e\n"
            "}"
        ),
        questions=YARAL2_QUESTIONS,
        expected={
            "has_required_yaral2_sections": True,
            "false_positive_risk": "high",
        },
    ),
    BenchmarkCase(
        case_id="yaral2_negative_control_standard_yara",
        workload="yaral2",
        input_text=(
            "rule Suspicious_PE_String {\n"
            "  strings:\n"
            '    $mz = "MZ"\n'
            '    $cmd = "vssadmin delete shadows"\n'
            "  condition:\n"
            "    $mz at 0 and $cmd\n"
            "}"
        ),
        questions=YARAL2_QUESTIONS,
        expected={
            "has_required_yaral2_sections": False,
            "ready_for_validation": False,
        },
    ),
)


def _resolve_api_key(secret_name: str) -> str:
    env_key = os.getenv("GEMINI_API_KEY", "").strip()
    if env_key:
        return env_key
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
        return proc.stdout.strip()
    raise RuntimeError(
        f"GEMINI_API_KEY not set and `gcloud secrets versions access latest --secret={secret_name}` failed"
    )


def _build_gen_prompt(input_text: str, questions: dict[str, dict[str, Any]]) -> str:
    schema_lines: list[str] = []
    for qid, q in questions.items():
        qtype = q["type"]
        if qtype == "noul":
            schema_lines.append(
                f'- "{qid}": boolean (true or false) — {q["instructions"]}'
            )
        elif qtype == "choice":
            opts = ", ".join(q["criteria"].keys())
            schema_lines.append(
                f'- "{qid}": one string from [{opts}] — {q["instructions"]}'
            )
        elif qtype == "score":
            max_idx = len(q["criteria"]) - 1
            schema_lines.append(
                f'- "{qid}": number from 1.0 to {max_idx + 1}.0 — {q["instructions"]}'
            )
    return (
        "Analyze the input and return ONLY a single JSON object with these exact keys:\n"
        + "\n".join(schema_lines)
        + "\n\nInput:\n"
        + input_text
    )


def _extract_decision1_labels(answers: dict[str, Any]) -> dict[str, Any]:
    labels: dict[str, Any] = {}
    for qid, ans in answers.items():
        qtype = ans.get("type")
        if qtype == "noul":
            labels[qid] = float(ans.get("noul", 0.0)) >= 0.5
        elif qtype == "choice":
            labels[qid] = str(ans.get("choice", ""))
        elif qtype == "score":
            labels[qid] = round(float(ans.get("score", 0.0)) + 1.0, 4)
    return labels


def _score_accuracy(
    predicted: dict[str, Any], expected: dict[str, Any]
) -> tuple[int, int]:
    matched = 0
    for key, exp_val in expected.items():
        if predicted.get(key) == exp_val:
            matched += 1
    return matched, len(expected)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return ordered[idx]


def _run_dry_call(mode: str, case: BenchmarkCase) -> dict[str, Any]:
    # Deterministic offline simulation reflecting observed token/latency profiles.
    labels = dict(case.expected)
    for qid, q in case.questions.items():
        if qid not in labels:
            if q["type"] == "noul":
                labels[qid] = False
            elif q["type"] == "choice":
                labels[qid] = next(iter(q["criteria"].keys()))
            elif q["type"] == "score":
                labels[qid] = 3.0
    if mode == "decision1":
        input_tokens = max(120, len(case.input_text) // 4 + 80)
        return {
            "latency_ms": 185.0,
            "input_tokens": input_tokens,
            "output_tokens": 0,
            "labels": labels,
            "has_probabilities": True,
            "sample_confidence": 0.96,
        }
    input_tokens = max(220, len(case.input_text) // 4 + 190)
    output_tokens = 65 + len(case.questions) * 10
    return {
        "latency_ms": 640.0,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "labels": labels,
        "has_probabilities": False,
        "sample_confidence": None,
    }


def _run_live_decision1(
    client: httpx.Client,
    api_key: str,
    model: str,
    case: BenchmarkCase,
) -> dict[str, Any]:
    started = time.perf_counter()
    resp = client.post(
        DECISIONS_URL,
        headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
        json={"model": model, "input": case.input_text, "questions": case.questions},
    )
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    resp.raise_for_status()
    payload = resp.json()
    answers = payload.get("answers") or {}
    usage = payload.get("usage") or {}
    confs = [
        float(ans["confidence"])
        for ans in answers.values()
        if isinstance(ans, dict) and "confidence" in ans
    ]
    return {
        "latency_ms": round(elapsed_ms, 2),
        "input_tokens": int(usage.get("total_input_tokens", 0)),
        "output_tokens": int(usage.get("total_output_tokens", 0)),
        "labels": _extract_decision1_labels(answers),
        "has_probabilities": True,
        "sample_confidence": round(statistics.mean(confs), 4) if confs else None,
        "raw_answers": answers,
    }


def _run_live_generative(
    client: httpx.Client,
    api_key: str,
    model: str,
    case: BenchmarkCase,
) -> dict[str, Any]:
    url = GENERATE_URL_TMPL.format(model=model)
    prompt = _build_gen_prompt(case.input_text, case.questions)
    started = time.perf_counter()
    resp = client.post(
        url,
        headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
        json={
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.0,
            },
        },
    )
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    resp.raise_for_status()
    payload = resp.json()
    usage = payload.get("usageMetadata") or {}
    candidates = payload.get("candidates") or []
    text = ""
    if candidates:
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(str(p.get("text", "")) for p in parts)
    try:
        labels = json.loads(text) if text else {}
    except json.JSONDecodeError:
        labels = {}
    out_tokens = int(usage.get("candidatesTokenCount", 0)) + int(
        usage.get("thoughtsTokenCount", 0)
    )
    return {
        "latency_ms": round(elapsed_ms, 2),
        "input_tokens": int(usage.get("promptTokenCount", 0)),
        "output_tokens": out_tokens,
        "labels": labels if isinstance(labels, dict) else {},
        "has_probabilities": False,
        "sample_confidence": None,
    }


def _summarize(
    records: list[dict[str, Any]],
    input_price_per_m: float,
    output_price_per_m: float,
) -> dict[str, Any]:
    latencies = [r["latency_ms"] for r in records]
    in_tok = sum(r["input_tokens"] for r in records)
    out_tok = sum(r["output_tokens"] for r in records)
    matched = sum(r["matched"] for r in records)
    total_exp = sum(r["expected_count"] for r in records)
    cost_usd = (in_tok / 1_000_000.0) * input_price_per_m + (
        out_tok / 1_000_000.0
    ) * output_price_per_m
    return {
        "calls": len(records),
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "mean_latency_ms": round(statistics.mean(latencies), 2) if latencies else 0.0,
        "p50_latency_ms": round(_percentile(latencies, 50), 2),
        "p95_latency_ms": round(_percentile(latencies, 95), 2),
        "cost_usd": round(cost_usd, 6),
        "accuracy_pct": round((matched / total_exp) * 100.0, 1) if total_exp else 0.0,
        "matched": matched,
        "expected_total": total_exp,
        "calibrated_probabilities": all(r["has_probabilities"] for r in records),
    }


def _format_markdown(
    gen_model: str,
    dec_model: str,
    gen_summary: dict[str, Any],
    dec_summary: dict[str, Any],
    dry_run: bool,
) -> str:
    mode_label = "DRY-RUN (offline simulated)" if dry_run else "LIVE"
    lines = [
        f"## Decision 1 Benchmark Summary ({mode_label})",
        "",
        f"| Metric | Generative ({gen_model}) | Decision 1 ({dec_model}) |",
        "| --- | ---: | ---: |",
        f"| Calls | {gen_summary['calls']} | {dec_summary['calls']} |",
        f"| Total Input Tokens | {gen_summary['input_tokens']} | {dec_summary['input_tokens']} |",
        f"| Total Output Tokens | {gen_summary['output_tokens']} | {dec_summary['output_tokens']} |",
        f"| Mean Latency (ms) | {gen_summary['mean_latency_ms']:.2f} | {dec_summary['mean_latency_ms']:.2f} |",
        f"| p50 Latency (ms) | {gen_summary['p50_latency_ms']:.2f} | {dec_summary['p50_latency_ms']:.2f} |",
        f"| p95 Latency (ms) | {gen_summary['p95_latency_ms']:.2f} | {dec_summary['p95_latency_ms']:.2f} |",
        f"| Estimated Cost (USD) | ${gen_summary['cost_usd']:.6f} | ${dec_summary['cost_usd']:.6f} |",
        f"| Label Accuracy | {gen_summary['accuracy_pct']}% ({gen_summary['matched']}/{gen_summary['expected_total']}) | {dec_summary['accuracy_pct']}% ({dec_summary['matched']}/{dec_summary['expected_total']}) |",
        f"| Calibrated Probabilities | {gen_summary['calibrated_probabilities']} | {dec_summary['calibrated_probabilities']} |",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true", help="Run offline mock benchmark"
    )
    parser.add_argument("--gen-model", default=DEFAULT_GEN_MODEL)
    parser.add_argument("--decision-model", default=DEFAULT_DECISION_MODEL)
    parser.add_argument("--secret-name", default="gemini-api-key")
    parser.add_argument(
        "--workload",
        choices=("all", "preflight", "triage", "yaral2"),
        default="all",
    )
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument(
        "--gen-input-price", type=float, default=DEFAULT_GEN_INPUT_PER_M
    )
    parser.add_argument(
        "--gen-output-price", type=float, default=DEFAULT_GEN_OUTPUT_PER_M
    )
    parser.add_argument("--json-out", help="Optional path for JSON results")
    parser.add_argument("--md-out", help="Optional path for Markdown summary")
    args = parser.parse_args()

    selected = [
        c for c in CASES if args.workload == "all" or c.workload == args.workload
    ]
    api_key = "" if args.dry_run else _resolve_api_key(args.secret_name)

    gen_records: list[dict[str, Any]] = []
    dec_records: list[dict[str, Any]] = []

    with httpx.Client(timeout=30.0) as client:
        for _ in range(max(1, args.iterations)):
            for case in selected:
                if args.dry_run:
                    g = _run_dry_call("generative", case)
                    d = _run_dry_call("decision1", case)
                else:
                    g = _run_live_generative(client, api_key, args.gen_model, case)
                    d = _run_live_decision1(client, api_key, args.decision_model, case)

                g_match, g_tot = _score_accuracy(g["labels"], case.expected)
                d_match, d_tot = _score_accuracy(d["labels"], case.expected)
                gen_records.append(
                    {
                        "case_id": case.case_id,
                        "workload": case.workload,
                        "matched": g_match,
                        "expected_count": g_tot,
                        **g,
                    }
                )
                dec_records.append(
                    {
                        "case_id": case.case_id,
                        "workload": case.workload,
                        "matched": d_match,
                        "expected_count": d_tot,
                        **d,
                    }
                )

    gen_summary = _summarize(gen_records, args.gen_input_price, args.gen_output_price)
    dec_summary = _summarize(dec_records, DECISION1_INPUT_PER_M, DECISION1_OUTPUT_PER_M)
    markdown = _format_markdown(
        args.gen_model, args.decision_model, gen_summary, dec_summary, args.dry_run
    )
    print(markdown)

    if args.md_out:
        pathlib.Path(args.md_out).write_text(markdown + "\n")
    if args.json_out:
        payload = {
            "dry_run": args.dry_run,
            "gen_model": args.gen_model,
            "decision_model": args.decision_model,
            "generative_summary": gen_summary,
            "decision1_summary": dec_summary,
            "generative_calls": gen_records,
            "decision1_calls": dec_records,
        }
        pathlib.Path(args.json_out).write_text(json.dumps(payload, indent=2) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
