#!/usr/bin/env python3
"""Benchmark comparing standard generative Flash JSON vs Gemini Decision 1.

Evaluates both models across three high-ROI governed SOC workloads:
  1. Orchestrator short-circuit routing (`preflight`): bypasses the outer
     Pro orchestrator when Decision 1 routes to a single specialist at >= 0.90.
  2. Pre-LLM UDM noise reduction (`udm_filter`): scores individual UDM events
     before `threat_hunter_llm` runs, dropping low-signal noise (< 0.30).
  3. Unstructured CTI artifact triage (`cti_artifact`): extracts structured
     actionability, category, and severity from unstructured threat prose.

Measures per-call and aggregate input tokens, output tokens (0 for Decision 1),
isolated API latency (mean, p50, p95 ms), cost ($0.10/1M input and $0 output
for Decision 1), label accuracy, per-question mismatches, calibrated
probabilities, and estimated end-to-end agent savings.

Usage:
    .venv/bin/python scripts/governance/benchmark_decision1.py --dry-run
    .venv/bin/python scripts/governance/benchmark_decision1.py --iterations 3 --json-out /tmp/bench.json
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

DEFAULT_GEN_MODEL = "gemini-3.8-flash"
DEFAULT_DECISION_MODEL = "gemini-decision-1"

# Pricing in USD per 1M tokens.
DECISION1_INPUT_PER_M = 0.10
DECISION1_OUTPUT_PER_M = 0.0
DEFAULT_GEN_INPUT_PER_M = 0.30
DEFAULT_GEN_OUTPUT_PER_M = 2.50

# Reference end-to-end savings constants for bypassed downstream LLM turns.
PRO_BYPASS_SAVED_INPUT_TOKENS = 1800
PRO_BYPASS_SAVED_OUTPUT_TOKENS = 220
PRO_BYPASS_SAVED_LATENCY_MS = 3200.0
FLASH_FILTER_SAVED_INPUT_TOKENS_PER_EVENT = 450
FLASH_FILTER_SAVED_LATENCY_MS_PER_BATCH = 650.0
SHORT_CIRCUIT_THRESHOLD = 0.90
UDM_DROP_THRESHOLD = 0.30
UDM_ESCALATE_THRESHOLD = 0.85


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    workload: str
    input_text: str
    questions: dict[str, dict[str, Any]]
    expected: dict[str, Any]
    metadata: dict[str, Any]


PREFLIGHT_QUESTIONS: dict[str, dict[str, Any]] = {
    "needs_cti": {
        "type": "noul",
        "instructions": (
            "Does the request ask to look up or enrich a file hash, domain, IP "
            "address, URL, or threat report in external threat intelligence?"
        ),
    },
    "needs_threat_hunt": {
        "type": "noul",
        "instructions": (
            "Does the request ask to search Chronicle SIEM logs or UDM "
            "telemetry, list or triage security alerts, or inspect SIEM feeds?"
        ),
    },
    "needs_detection_eng": {
        "type": "noul",
        "instructions": (
            "Does the request ask to author, validate, audit, or test a "
            "Chronicle SIEM YARA-L 2.0 detection rule or manage a SIEM parser?"
        ),
    },
    "needs_tier2_response": {
        "type": "noul",
        "instructions": (
            "Does the request ask to isolate an endpoint host, disable a user "
            "account, update an alert status, or modify a containment list?"
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

UDM_FILTER_QUESTIONS: dict[str, dict[str, Any]] = {
    "true_positive": {
        "type": "noul",
        "instructions": (
            "Determine whether this Chronicle SIEM alert or UDM event represents "
            "a true positive security threat rather than benign administrative "
            "or routine system activity."
        ),
    },
    "severity": {
        "type": "score",
        "instructions": (
            "Score the security severity of this Chronicle SIEM alert or UDM "
            "event from level 0 (benign) to level 4 (critical)."
        ),
        "criteria": [
            "Informational or benign activity with no security impact.",
            "Low severity anomaly or policy notice requiring routine review.",
            "Medium severity suspicious activity warranting investigation.",
            "High severity likely threat activity with host or account impact.",
            "Critical active compromise, lateral movement, or exfiltration.",
        ],
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
            "dismiss": "Benign or clear false positive; drop before LLM triage.",
            "enrich_cti": "Suspicious IOCs present; enrich via CTI first.",
            "escalate_tier2": "High-confidence threat; escalate to Tier 2.",
            "tune_yaral2": "Overly broad YARA-L 2.0 rule; send for tuning.",
        },
    },
}

CTI_ARTIFACT_QUESTIONS: dict[str, dict[str, Any]] = {
    "is_actionable_threat": {
        "type": "noul",
        "instructions": (
            "Does this unstructured threat intelligence artifact describe an "
            "actionable, active, or relevant security threat with concrete TTPs "
            "or indicators requiring SOC attention?"
        ),
    },
    "threat_category": {
        "type": "choice",
        "instructions": "Classify the primary threat category described.",
        "criteria": {
            "ransomware": "Ransomware deployment, extortion, or shadow copy deletion.",
            "apt_espionage": "Targeted intrusion, credential theft, or persistent C2.",
            "infostealer_malware": "Credential harvesting malware or commodity loader.",
            "phishing_social_eng": "Credential phishing, MFA fatigue, or BEC.",
            "vulnerability_advisory": "CVE/patch notice without active exploitation.",
            "benign_or_noise": "Marketing fluff, non-actionable, or benign notice.",
        },
    },
    "severity": {
        "type": "score",
        "instructions": (
            "Score the operational severity of this CTI artifact from level 0 "
            "(informational) to level 4 (critical immediate threat)."
        ),
        "criteria": [
            "Informational or non-actionable commentary.",
            "Low relevance advisory with no immediate enterprise exposure.",
            "Moderate threat requiring routine detection coverage check.",
            "High-severity active campaign targeting enterprise infrastructure.",
            "Critical zero-day or active ransomware/APT exploitation.",
        ],
    },
    "requires_immediate_hunt": {
        "type": "noul",
        "instructions": (
            "Does this artifact warrant an immediate retrospective Chronicle "
            "SIEM UDM hunt across enterprise endpoints or identities?"
        ),
    },
}


CASES: tuple[BenchmarkCase, ...] = (
    # --- Workload 1: Orchestrator short-circuit routing ---
    BenchmarkCase(
        case_id="preflight_cti_single",
        workload="preflight",
        input_text=(
            "Look up the VirusTotal GTI reputation for SHA256 "
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
        ),
        questions=PREFLIGHT_QUESTIONS,
        expected={
            "needs_cti": True,
            "needs_threat_hunt": False,
            "needs_detection_eng": False,
            "needs_tier2_response": False,
            "workflow_mode": "single_specialist",
            "urgency": {"min": 1.0, "max": 3.5},
        },
        metadata={"expect_short_circuit": True, "target": "CTI_Researcher"},
    ),
    BenchmarkCase(
        case_id="preflight_yaral2_single",
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
            "workflow_mode": "single_specialist",
            "urgency": {"min": 1.0, "max": 2.5},
        },
        metadata={"expect_short_circuit": True, "target": "Detection_Engineer"},
    ),
    BenchmarkCase(
        case_id="preflight_tier0_containment",
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
            "workflow_mode": "containment_action",
            "urgency": {"min": 4.0, "max": 5.0},
        },
        metadata={"expect_short_circuit": False, "target": "Tier2_Responder"},
    ),
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
            "workflow_mode": "multi_stage_investigation",
            "urgency": {"min": 3.0, "max": 5.0},
        },
        metadata={"expect_short_circuit": False, "target": "multi"},
    ),
    # --- Workload 2: Pre-LLM UDM noise reduction ---
    BenchmarkCase(
        case_id="udm_noise_osconfig_dns",
        workload="udm_filter",
        input_text=json.dumps(
            {
                "log_type": "WINDOWS_SYSMON",
                "event_type": "NETWORK_DNS",
                "principal": {"hostname": "gce-win-worker-01", "user": "SYSTEM"},
                "process": "C:\\Program Files\\Google\\OSConfig\\google_osconfig_agent.exe",
                "dns_query": "logging.googleapis.com",
            }
        ),
        questions=UDM_FILTER_QUESTIONS,
        expected={
            "true_positive": False,
            "severity": {"min": 1.0, "max": 2.0},
            "mitre_tactic": "other_or_benign",
            "next_action": "dismiss",
        },
        metadata={"is_noise": True},
    ),
    BenchmarkCase(
        case_id="udm_noise_defender_cdn",
        workload="udm_filter",
        input_text=json.dumps(
            {
                "log_type": "WINDOWS_SYSMON",
                "event_type": "NETWORK_DNS",
                "principal": {
                    "hostname": "WKSTN-FIN-019",
                    "user": "NT AUTHORITY\\NETWORK SERVICE",
                },
                "process": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
                "dns_query": "wdcp.microsoft.com",
            }
        ),
        questions=UDM_FILTER_QUESTIONS,
        expected={
            "true_positive": False,
            "severity": {"min": 1.0, "max": 2.0},
            "mitre_tactic": "other_or_benign",
            "next_action": "dismiss",
        },
        metadata={"is_noise": True},
    ),
    BenchmarkCase(
        case_id="udm_noise_qualys_scan",
        workload="udm_filter",
        input_text=json.dumps(
            {
                "log_type": "WINEVTLOG",
                "event_id": 4624,
                "principal": {"user": "svc_qualys_scanner", "ip": "10.20.0.15"},
                "target": {"hostname": "WKSTN-HR-108"},
                "note": "Authorized weekly vulnerability scan window Tuesday 02:00 UTC.",
            }
        ),
        questions=UDM_FILTER_QUESTIONS,
        expected={
            "true_positive": False,
            "severity": {"min": 1.0, "max": 2.5},
            "mitre_tactic": "other_or_benign",
            "next_action": "dismiss",
        },
        metadata={"is_noise": True},
    ),
    BenchmarkCase(
        case_id="udm_attack_ntdsutil_dump",
        workload="udm_filter",
        input_text=json.dumps(
            {
                "log_type": "WINDOWS_SYSMON",
                "event_type": "PROCESS_LAUNCH",
                "principal": {
                    "hostname": "activedir.stackedpads.local",
                    "user": "frank.kolzig",
                },
                "command_line": 'ntdsutil.exe "ac i ntds" "ifm" "create full c:\\temp\\ad_dump" q q',
            }
        ),
        questions=UDM_FILTER_QUESTIONS,
        expected={
            "true_positive": True,
            "severity": {"min": 3.5, "max": 5.0},
            "mitre_tactic": "credential_access",
            "next_action": "escalate_tier2",
        },
        metadata={"is_noise": False},
    ),
    BenchmarkCase(
        case_id="udm_attack_mimikatz_lsass",
        workload="udm_filter",
        input_text=json.dumps(
            {
                "log_type": "WINDOWS_SYSMON",
                "event_type": "PROCESS_OPEN",
                "principal": {"hostname": "WKSTN-FIN-042", "user": "svc_backup"},
                "target_process": "C:\\Windows\\System32\\lsass.exe",
                "command_line": "m64.exe privilege::debug sekurlsa::logonpasswords exit",
                "granted_access": "0x1010",
            }
        ),
        questions=UDM_FILTER_QUESTIONS,
        expected={
            "true_positive": True,
            "severity": {"min": 4.0, "max": 5.0},
            "mitre_tactic": "credential_access",
            "next_action": "escalate_tier2",
        },
        metadata={"is_noise": False},
    ),
    BenchmarkCase(
        case_id="udm_attack_shadow_copy_delete",
        workload="udm_filter",
        input_text=json.dumps(
            {
                "log_type": "WINDOWS_SYSMON",
                "event_type": "PROCESS_LAUNCH",
                "principal": {"hostname": "SRV-FILE-02", "user": "SYSTEM"},
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "parent_process": "powershell.exe -EncodedCommand JAB...",
            }
        ),
        questions=UDM_FILTER_QUESTIONS,
        expected={
            "true_positive": True,
            "severity": {"min": 3.5, "max": 5.0},
            "next_action": "escalate_tier2",
        },
        metadata={"is_noise": False},
    ),
    # --- Workload 3: Unstructured CTI artifact triage ---
    BenchmarkCase(
        case_id="cti_akira_ransomware_report",
        workload="cti_artifact",
        input_text=(
            "FLASH ADVISORY: Incident responders observed Akira ransomware "
            "affiliates exploiting unpatched VPN appliances without MFA to gain "
            "initial access, pivoting via AnyDesk and RDP, dumping LSASS with "
            "comsvcs.dll, deleting Volume Shadow Copies via PowerShell "
            "Win32_ShadowCopy, and exfiltrating archives over FileZilla before "
            "encrypting ESXi and Windows file servers."
        ),
        questions=CTI_ARTIFACT_QUESTIONS,
        expected={
            "is_actionable_threat": True,
            "threat_category": "ransomware",
            "severity": {"min": 3.5, "max": 5.0},
            "requires_immediate_hunt": True,
        },
        metadata={},
    ),
    BenchmarkCase(
        case_id="cti_apt_dns_tunnel_brief",
        workload="cti_artifact",
        input_text=(
            "THREAT BRIEF: Over the past 14 days, a financially motivated "
            "espionage cluster has used custom Go implants on Linux cloud VMs "
            "to exfiltrate staged secrets inside 32-byte hex-encoded TXT DNS "
            "queries under newly registered domains, evading outbound HTTP proxies."
        ),
        questions=CTI_ARTIFACT_QUESTIONS,
        expected={
            "is_actionable_threat": True,
            "threat_category": "apt_espionage",
            "severity": {"min": 3.0, "max": 5.0},
            "requires_immediate_hunt": True,
        },
        metadata={},
    ),
    BenchmarkCase(
        case_id="cti_vendor_marketing_noise",
        workload="cti_artifact",
        input_text=(
            "WEBINAR INVITE: Join our upcoming fireside chat on next-generation "
            "AI-powered zero-trust synergy! Register today for a free coffee "
            "gift card and learn how digital transformation elevates your brand."
        ),
        questions=CTI_ARTIFACT_QUESTIONS,
        expected={
            "is_actionable_threat": False,
            "threat_category": "benign_or_noise",
            "severity": {"min": 1.0, "max": 2.0},
            "requires_immediate_hunt": False,
        },
        metadata={},
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


def _extract_decision1_details(
    answers: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, float]]:
    labels: dict[str, Any] = {}
    confidences: dict[str, float] = {}
    raw_nouls: dict[str, float] = {}
    for qid, ans in answers.items():
        if not isinstance(ans, dict):
            continue
        qtype = ans.get("type")
        if "confidence" in ans:
            confidences[qid] = float(ans["confidence"])
        if qtype == "noul":
            val = float(ans.get("noul", 0.0))
            labels[qid] = val >= 0.5
            raw_nouls[qid] = val
        elif qtype == "choice":
            labels[qid] = str(ans.get("choice", ""))
        elif qtype == "score":
            labels[qid] = round(float(ans.get("score", 0.0)) + 1.0, 4)
    return labels, {"confidences": confidences, "raw_nouls": raw_nouls}


def _matches_expected(predicted_val: Any, expected_val: Any) -> bool:
    if (
        isinstance(expected_val, dict)
        and "min" in expected_val
        and "max" in expected_val
    ):
        if predicted_val is None:
            return False
        try:
            num = float(predicted_val)
        except (TypeError, ValueError):
            return False
        return float(expected_val["min"]) <= num <= float(expected_val["max"])
    return predicted_val == expected_val


def _score_case(
    case: BenchmarkCase,
    predicted: dict[str, Any],
    details: dict[str, Any],
) -> tuple[int, int, list[dict[str, Any]]]:
    matched = 0
    mismatches: list[dict[str, Any]] = []
    confidences = details.get("confidences") or {}
    raw_nouls = details.get("raw_nouls") or {}
    for key, exp_val in case.expected.items():
        pred_val = predicted.get(key)
        if _matches_expected(pred_val, exp_val):
            matched += 1
        else:
            mismatches.append(
                {
                    "case_id": case.case_id,
                    "workload": case.workload,
                    "question": key,
                    "expected": exp_val,
                    "predicted": pred_val,
                    "noul": raw_nouls.get(key),
                    "confidence": confidences.get(key),
                }
            )
    return matched, len(case.expected), mismatches


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return ordered[idx]


def _run_dry_call(mode: str, case: BenchmarkCase) -> dict[str, Any]:
    labels: dict[str, Any] = {}
    raw_nouls: dict[str, float] = {}
    confidences: dict[str, float] = {}
    for qid, exp_val in case.expected.items():
        if isinstance(exp_val, dict) and "min" in exp_val and "max" in exp_val:
            labels[qid] = round(
                (float(exp_val["min"]) + float(exp_val["max"])) / 2.0, 2
            )
        else:
            labels[qid] = exp_val
            if isinstance(exp_val, bool):
                raw_nouls[qid] = 0.96 if exp_val else 0.04
        confidences[qid] = 0.96
    if mode == "decision1":
        input_tokens = max(140, len(case.input_text) // 4 + 90)
        return {
            "latency_ms": 210.0,
            "input_tokens": input_tokens,
            "output_tokens": 0,
            "labels": labels,
            "details": {"confidences": confidences, "raw_nouls": raw_nouls},
            "has_probabilities": True,
        }
    input_tokens = max(220, len(case.input_text) // 4 + 190)
    output_tokens = 55 + len(case.questions) * 9
    return {
        "latency_ms": 580.0,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "labels": labels,
        "details": {"confidences": {}, "raw_nouls": {}},
        "has_probabilities": False,
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
    labels, details = _extract_decision1_details(answers)
    return {
        "latency_ms": round(elapsed_ms, 2),
        "input_tokens": int(usage.get("total_input_tokens", 0)),
        "output_tokens": int(usage.get("total_output_tokens", 0)),
        "labels": labels,
        "details": details,
        "has_probabilities": True,
        "raw_answers": answers,
    }


def _run_live_generative(
    client: httpx.Client,
    api_key: str,
    model: str,
    case: BenchmarkCase,
    *,
    no_thinking: bool,
) -> dict[str, Any]:
    url = GENERATE_URL_TMPL.format(model=model)
    prompt = _build_gen_prompt(case.input_text, case.questions)
    gen_config: dict[str, Any] = {
        "responseMimeType": "application/json",
        "temperature": 0.0,
    }
    if no_thinking:
        gen_config["thinkingConfig"] = {"thinkingBudget": 0}
    started = time.perf_counter()
    resp = client.post(
        url,
        headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
        json={
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": gen_config,
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
        "details": {"confidences": {}, "raw_nouls": {}},
        "has_probabilities": False,
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


def _compute_end_to_end_savings(dec_records: list[dict[str, Any]]) -> dict[str, Any]:
    preflight_recs = [r for r in dec_records if r["workload"] == "preflight"]
    short_circuited = 0
    for rec in preflight_recs:
        labels = rec["labels"]
        nouls = (rec.get("details") or {}).get("raw_nouls") or {}
        need_keys = (
            "needs_cti",
            "needs_threat_hunt",
            "needs_detection_eng",
            "needs_tier2_response",
        )
        high_conf_hits = [
            k for k in need_keys if float(nouls.get(k, 0.0)) >= SHORT_CIRCUIT_THRESHOLD
        ]
        active_hits = [k for k in need_keys if bool(labels.get(k))]
        if (
            labels.get("workflow_mode") == "single_specialist"
            and len(high_conf_hits) == 1
            and len(active_hits) == 1
        ):
            short_circuited += 1

    udm_recs = [r for r in dec_records if r["workload"] == "udm_filter"]
    udm_dropped = 0
    udm_escalated = 0
    for rec in udm_recs:
        nouls = (rec.get("details") or {}).get("raw_nouls") or {}
        tp = float(nouls.get("true_positive", 0.5))
        if tp < UDM_DROP_THRESHOLD:
            udm_dropped += 1
        elif tp >= UDM_ESCALATE_THRESHOLD:
            udm_escalated += 1

    return {
        "preflight_calls": len(preflight_recs),
        "preflight_short_circuited": short_circuited,
        "pro_tokens_saved": short_circuited
        * (PRO_BYPASS_SAVED_INPUT_TOKENS + PRO_BYPASS_SAVED_OUTPUT_TOKENS),
        "pro_latency_saved_ms": round(short_circuited * PRO_BYPASS_SAVED_LATENCY_MS, 2),
        "udm_events_scored": len(udm_recs),
        "udm_noise_dropped": udm_dropped,
        "udm_high_conf_escalated": udm_escalated,
        "flash_tokens_saved_from_noise_drop": udm_dropped
        * FLASH_FILTER_SAVED_INPUT_TOKENS_PER_EVENT,
        "flash_latency_saved_ms": round(
            (udm_dropped / max(1, len(udm_recs)))
            * FLASH_FILTER_SAVED_LATENCY_MS_PER_BATCH
            if udm_recs
            else 0.0,
            2,
        ),
    }


def _aggregate_mismatches(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for rec in records:
        for m in rec.get("mismatches") or []:
            key = (m["case_id"], m["question"], str(m["predicted"]))
            if key not in grouped:
                grouped[key] = {**m, "count": 1}
            else:
                grouped[key]["count"] += 1
    return list(grouped.values())


def _format_markdown(
    gen_model: str,
    dec_model: str,
    gen_summary: dict[str, Any],
    dec_summary: dict[str, Any],
    e2e_savings: dict[str, Any],
    gen_mismatches: list[dict[str, Any]],
    dec_mismatches: list[dict[str, Any]],
    *,
    dry_run: bool,
    no_thinking: bool,
) -> str:
    mode_label = "DRY-RUN (offline simulated)" if dry_run else "LIVE"
    thinking_label = "thinkingBudget=0" if no_thinking else "default thinking"
    lines = [
        f"## Decision 1 Benchmark Summary ({mode_label}, {thinking_label})",
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
        "",
        "### Estimated End-to-End Agent Savings (Decision 1 Fast Paths)",
        "",
        f"- **Orchestrator short-circuit (`preflight`)**: {e2e_savings['preflight_short_circuited']}/{e2e_savings['preflight_calls']} calls bypassed `gemini-4-hydrogen` (~{e2e_savings['pro_tokens_saved']} tokens and ~{e2e_savings['pro_latency_saved_ms']:.0f} ms saved).",
        f"- **Pre-LLM UDM noise drop (`udm_filter`)**: {e2e_savings['udm_noise_dropped']}/{e2e_savings['udm_events_scored']} events dropped (`P(tp) < 0.30`), {e2e_savings['udm_high_conf_escalated']} fast-escalated (`P(tp) >= 0.85`), saving ~{e2e_savings['flash_tokens_saved_from_noise_drop']} downstream Flash input tokens.",
        "",
        "### Per-Question Mismatches",
        "",
    ]
    if not gen_mismatches and not dec_mismatches:
        lines.append(
            "- None (100% agreement across all expected labels and score bands)."
        )
    else:
        for label, items in (
            ("Generative", gen_mismatches),
            ("Decision 1", dec_mismatches),
        ):
            for m in items:
                lines.append(
                    f"- [{label}] `{m['case_id']}.{m['question']}` x{m['count']}: "
                    f"expected={m['expected']!r}, predicted={m['predicted']!r}, "
                    f"noul={m.get('noul')}, confidence={m.get('confidence')}"
                )
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
        choices=("all", "preflight", "udm_filter", "cti_artifact"),
        default="all",
    )
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument(
        "--no-thinking",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Disable thinkingBudget on generative Flash baseline for apples-to-apples comparison.",
    )
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
                    g = _run_live_generative(
                        client,
                        api_key,
                        args.gen_model,
                        case,
                        no_thinking=args.no_thinking,
                    )
                    d = _run_live_decision1(client, api_key, args.decision_model, case)

                g_match, g_tot, g_mis = _score_case(case, g["labels"], g["details"])
                d_match, d_tot, d_mis = _score_case(case, d["labels"], d["details"])
                gen_records.append(
                    {
                        "case_id": case.case_id,
                        "workload": case.workload,
                        "matched": g_match,
                        "expected_count": g_tot,
                        "mismatches": g_mis,
                        **g,
                    }
                )
                dec_records.append(
                    {
                        "case_id": case.case_id,
                        "workload": case.workload,
                        "matched": d_match,
                        "expected_count": d_tot,
                        "mismatches": d_mis,
                        **d,
                    }
                )

    gen_summary = _summarize(gen_records, args.gen_input_price, args.gen_output_price)
    dec_summary = _summarize(dec_records, DECISION1_INPUT_PER_M, DECISION1_OUTPUT_PER_M)
    e2e_savings = _compute_end_to_end_savings(dec_records)
    gen_mismatches = _aggregate_mismatches(gen_records)
    dec_mismatches = _aggregate_mismatches(dec_records)

    markdown = _format_markdown(
        args.gen_model,
        args.decision_model,
        gen_summary,
        dec_summary,
        e2e_savings,
        gen_mismatches,
        dec_mismatches,
        dry_run=args.dry_run,
        no_thinking=args.no_thinking,
    )
    print(markdown)

    if args.md_out:
        pathlib.Path(args.md_out).write_text(markdown + "\n")
    if args.json_out:
        payload = {
            "dry_run": args.dry_run,
            "no_thinking": args.no_thinking,
            "gen_model": args.gen_model,
            "decision_model": args.decision_model,
            "generative_summary": gen_summary,
            "decision1_summary": dec_summary,
            "end_to_end_savings": e2e_savings,
            "generative_mismatches": gen_mismatches,
            "decision1_mismatches": dec_mismatches,
            "generative_calls": gen_records,
            "decision1_calls": dec_records,
        }
        pathlib.Path(args.json_out).write_text(json.dumps(payload, indent=2) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
