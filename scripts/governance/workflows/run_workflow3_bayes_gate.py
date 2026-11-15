#!/usr/bin/env python3
"""End-to-end runner for Workflow 3: Epistemic & Cost-Weighted Bayes Gate.

Evaluates eight realistic raw JSON tool-trace scenarios against live Gemini
Decision 1 (`v1beta/decisions`) and verifies deterministic branching across
all four governed actions:
  1. ``AUTO_CLOSE_BENIGN``
  2. ``FORCE_PROBE_MORE``
  3. ``AUTO_ISOLATE_CONTAIN``
  4. ``RECOMMEND_TIER0_CHG_ESCALATION``

Usage:
    .venv/bin/python scripts/governance/workflows/run_workflow3_bayes_gate.py
    .venv/bin/python scripts/governance/workflows/run_workflow3_bayes_gate.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from governed_agents.shared_decision_guards.bayes_containment_gate import (  # noqa: E402
    AssetTier,
    ContainmentAction,
    compute_udm_window_bucket,
    decide_containment_action,
    evaluate_bayes_containment_gate,
)


DEFAULT_JSON_OUT = (
    pathlib.Path(tempfile.gettempdir())
    / "decision1_v2_results"
    / "workflow3_bayes_gate.json"
)


def _format_tool_trace(
    *,
    cmdb_record: dict[str, Any],
    udm_start: str,
    udm_end: str,
    udm_result: dict[str, Any],
    edr_result: dict[str, Any] | None = None,
    extra_tools: list[tuple[str, dict[str, Any]]] | None = None,
) -> str:
    """Formats raw JSON tool calls and outputs with a pre-computed window bucket."""
    window_bucket = compute_udm_window_bucket(udm_start, udm_end)
    steps: list[str] = [
        f"TOOL_CALL cmdb_lookup({json.dumps({'hostname': cmdb_record.get('hostname')})})",
        f"TOOL_RESPONSE cmdb_lookup: {json.dumps(cmdb_record)}",
        (
            f"TOOL_CALL udm_search({json.dumps({'start_time': udm_start, 'end_time': udm_end})}) "
            f"{window_bucket}"
        ),
        f"TOOL_RESPONSE udm_search: {json.dumps(udm_result)}",
    ]
    if edr_result is not None:
        steps.append(
            f"TOOL_CALL edr_process_query({json.dumps({'hostname': cmdb_record.get('hostname')})})"
        )
        steps.append(f"TOOL_RESPONSE edr_process_query: {json.dumps(edr_result)}")
    for tool_name, payload in extra_tools or []:
        steps.append(f"TOOL_RESPONSE {tool_name}: {json.dumps(payload)}")
    return "\n".join(steps)


@dataclass(frozen=True)
class BayesScenario:
    """A single end-to-end Workflow 3 test scenario."""

    scenario_id: str
    asset_id: str
    asset_tier: AssetTier
    expected_action: ContainmentAction
    evidence_text: str


SCENARIOS: tuple[BayesScenario, ...] = (
    BayesScenario(
        scenario_id="qualys_widened_168h_clean_scanner",
        asset_id="SRV-WEB-04",
        asset_tier=AssetTier.STANDARD,
        expected_action=ContainmentAction.AUTO_CLOSE_BENIGN,
        evidence_text=_format_tool_trace(
            cmdb_record={
                "hostname": "SRV-WEB-04",
                "tier": "STANDARD",
                "role": "web_frontend",
                "found": True,
            },
            udm_start="2026-11-07T00:00:00Z",
            udm_end="2026-11-14T00:00:00Z",
            udm_result={
                "total_events": 14,
                "events": [
                    {
                        "src_ip": "10.20.30.40",
                        "dst_host": "SRV-WEB-04",
                        "dst_port": 443,
                        "action": "ALLOW",
                    }
                ],
            },
            edr_result={
                "hostname": "SRV-WEB-04",
                "suspicious_processes": [],
                "lolbin_executions": [],
            },
            extra_tools=[
                (
                    "scanner_schedule_lookup",
                    {
                        "scanner_ip": "10.20.30.40",
                        "vendor": "Qualys",
                        "chg_ticket": "CHG-44102",
                        "scheduled_window_active": True,
                    },
                )
            ],
        ),
    ),
    BayesScenario(
        scenario_id="incomplete_72h_empty_hunt",
        asset_id="WS-FIN-112",
        asset_tier=AssetTier.HIGH,
        expected_action=ContainmentAction.FORCE_PROBE_MORE,
        evidence_text=_format_tool_trace(
            cmdb_record={
                "hostname": "WS-FIN-112",
                "tier": "HIGH",
                "owner_dept": "Finance",
                "found": True,
            },
            udm_start="2026-11-11T00:00:00Z",
            udm_end="2026-11-14T00:00:00Z",
            udm_result={"total_events": 0, "events": []},
            edr_result=None,
            extra_tools=[
                (
                    "siem_alert",
                    {
                        "alert_id": "ALT-8812",
                        "process": "powershell.exe",
                        "command_line": "powershell.exe -NoP -NonI -Enc JABzAD0ATgBlAHcA",
                        "signer_verified": False,
                    },
                )
            ],
        ),
    ),
    BayesScenario(
        scenario_id="borderline_single_source_ambiguous",
        asset_id="SRV-APP-19",
        asset_tier=AssetTier.STANDARD,
        expected_action=ContainmentAction.FORCE_PROBE_MORE,
        evidence_text=_format_tool_trace(
            cmdb_record={
                "hostname": "SRV-APP-19",
                "tier": "STANDARD",
                "found": True,
            },
            udm_start="2026-11-07T00:00:00Z",
            udm_end="2026-11-14T00:00:00Z",
            udm_result={
                "total_events": 1,
                "events": [
                    {
                        "src_host": "SRV-APP-19",
                        "dst_ip": "198.51.100.44",
                        "dst_port": 8443,
                        "bytes_out": 2048,
                    }
                ],
            },
            edr_result=None,
        ),
    ),
    BayesScenario(
        scenario_id="unverified_cmdb_tier_lolbin",
        asset_id="HOST-9942",
        asset_tier=AssetTier.STANDARD,
        expected_action=ContainmentAction.FORCE_PROBE_MORE,
        evidence_text=_format_tool_trace(
            cmdb_record={
                "hostname": "HOST-9942",
                "found": False,
                "tier": None,
                "error": "CMDB record missing",
            },
            udm_start="2026-11-07T00:00:00Z",
            udm_end="2026-11-14T00:00:00Z",
            udm_result={
                "total_events": 2,
                "events": [{"dst_ip": "203.0.113.55", "dst_port": 443}],
            },
            edr_result={
                "hostname": "HOST-9942",
                "process": "rundll32.exe",
                "command_line": "rundll32.exe C:\\Temp\\helper.dll,DllRegisterServer",
                "signer_status": "UNVERIFIED",
            },
        ),
    ),
    BayesScenario(
        scenario_id="unsigned_lolbin_workstation_c2",
        asset_id="WS-ENG-089",
        asset_tier=AssetTier.STANDARD,
        expected_action=ContainmentAction.AUTO_ISOLATE_CONTAIN,
        evidence_text=_format_tool_trace(
            cmdb_record={
                "hostname": "WS-ENG-089",
                "tier": "STANDARD",
                "role": "engineering_workstation",
                "found": True,
            },
            udm_start="2026-11-07T00:00:00Z",
            udm_end="2026-11-14T00:00:00Z",
            udm_result={
                "total_events": 42,
                "events": [
                    {
                        "src_host": "WS-ENG-089",
                        "dst_ip": "198.51.100.77",
                        "dst_port": 443,
                        "beacon_interval_s": 60,
                    }
                ],
            },
            edr_result={
                "hostname": "WS-ENG-089",
                "process": "svchost_update.exe",
                "path": "C:\\Users\\Public\\svchost_update.exe",
                "parent": "winword.exe",
                "signer": "UNSIGNED",
                "signature_valid": False,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            extra_tools=[
                (
                    "gti_lookup",
                    {
                        "indicator": "198.51.100.77",
                        "verdict": "MALICIOUS",
                        "malware_family": "CobaltStrike",
                        "detections": 54,
                    },
                )
            ],
        ),
    ),
    BayesScenario(
        scenario_id="compromised_high_tier_db_server",
        asset_id="DB-PAY-02",
        asset_tier=AssetTier.HIGH,
        expected_action=ContainmentAction.AUTO_ISOLATE_CONTAIN,
        evidence_text=_format_tool_trace(
            cmdb_record={
                "hostname": "DB-PAY-02",
                "tier": "HIGH",
                "role": "payments_database",
                "found": True,
            },
            udm_start="2026-11-07T00:00:00Z",
            udm_end="2026-11-14T00:00:00Z",
            udm_result={
                "total_events": 18,
                "events": [
                    {
                        "src_host": "DB-PAY-02",
                        "dst_ip": "203.0.113.99",
                        "dst_port": 4444,
                        "action": "ALLOW",
                    }
                ],
            },
            edr_result={
                "hostname": "DB-PAY-02",
                "process": "vssadmin.exe",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "signer": "Microsoft Windows",
                "parent": "C:\\ProgramData\\crypt_svc.exe",
                "parent_signer": "UNSIGNED",
                "signature_valid": False,
            },
            extra_tools=[
                (
                    "gti_lookup",
                    {
                        "indicator": "203.0.113.99",
                        "verdict": "MALICIOUS",
                        "malware_family": "LockBit",
                        "detections": 48,
                    },
                )
            ],
        ),
    ),
    BayesScenario(
        scenario_id="signed_benign_backup_admin",
        asset_id="SRV-BKUP-03",
        asset_tier=AssetTier.STANDARD,
        expected_action=ContainmentAction.AUTO_CLOSE_BENIGN,
        evidence_text=_format_tool_trace(
            cmdb_record={
                "hostname": "SRV-BKUP-03",
                "tier": "STANDARD",
                "role": "backup_server",
                "found": True,
            },
            udm_start="2026-11-07T00:00:00Z",
            udm_end="2026-11-14T00:00:00Z",
            udm_result={
                "total_events": 4,
                "events": [
                    {
                        "hostname": "SRV-BKUP-03",
                        "user": "CORP\\svc_backup_prod",
                        "event_type": "SCHEDULED_BACKUP",
                        "dst_ip": "10.50.0.10",
                    }
                ],
            },
            edr_result={
                "hostname": "SRV-BKUP-03",
                "process": "wbadmin.exe",
                "path": "C:\\Windows\\System32\\wbadmin.exe",
                "command_line": "wbadmin.exe start systemstatebackup -backupTarget:E:",
                "parent": "taskeng.exe",
                "signer": "Microsoft Windows",
                "signature_valid": True,
                "user": "CORP\\svc_backup_prod",
            },
            extra_tools=[
                (
                    "change_ticket_lookup",
                    {
                        "ticket": "CHG-44990",
                        "status": "APPROVED",
                        "service_account": "CORP\\svc_backup_prod",
                    },
                )
            ],
        ),
    ),
    BayesScenario(
        scenario_id="dc_prod_ntdsutil",
        asset_id="DC-PROD-01",
        asset_tier=AssetTier.CRITICAL,
        expected_action=ContainmentAction.RECOMMEND_TIER0_CHG_ESCALATION,
        evidence_text=_format_tool_trace(
            cmdb_record={
                "hostname": "DC-PROD-01",
                "tier": "CRITICAL",
                "tier_label": "Tier-0 Domain Controller",
                "found": True,
            },
            udm_start="2026-11-07T00:00:00Z",
            udm_end="2026-11-14T00:00:00Z",
            udm_result={
                "total_events": 9,
                "events": [
                    {
                        "hostname": "DC-PROD-01",
                        "event_id": 4688,
                        "file_write": "C:\\temp\\ntds_dump\\Active Directory\\ntds.dit",
                        "smb_out_ip": "10.99.4.12",
                    }
                ],
            },
            edr_result={
                "hostname": "DC-PROD-01",
                "process": "ntdsutil.exe",
                "command_line": 'ntdsutil.exe "ac i ntds" "ifm" "create full C:\\temp\\ntds_dump"',
                "parent": "cmd.exe",
                "signer": "Microsoft Windows",
                "signature_valid": True,
                "user": "CORP\\svc_legacy_app",
            },
            extra_tools=[
                (
                    "change_ticket_lookup",
                    {
                        "user": "CORP\\svc_legacy_app",
                        "active_chg_ticket": None,
                        "authorized_for_ntds_ifm": False,
                    },
                )
            ],
        ),
    ),
)

_DRY_RUN_ANSWERS: dict[str, dict[str, Any]] = {
    "qualys_widened_168h_clean_scanner": {
        "enabled": True,
        "answers": {
            "compromise_detected": {"type": "noul", "noul": 0.02, "confidence": 0.98},
            "corroborated_two_sources": {
                "type": "noul",
                "noul": 0.96,
                "confidence": 0.96,
            },
            "widened_72h_to_168h_on_empty_hunt": {
                "type": "noul",
                "noul": 0.95,
                "confidence": 0.95,
            },
            "checked_lolbin_signer": {"type": "noul", "noul": 0.93, "confidence": 0.93},
            "verified_asset_tier": {"type": "noul", "noul": 0.98, "confidence": 0.98},
        },
    },
    "incomplete_72h_empty_hunt": {
        "enabled": True,
        "answers": {
            "compromise_detected": {"type": "noul", "noul": 0.42, "confidence": 0.58},
            "corroborated_two_sources": {
                "type": "noul",
                "noul": 0.12,
                "confidence": 0.88,
            },
            "widened_72h_to_168h_on_empty_hunt": {
                "type": "noul",
                "noul": 0.08,
                "confidence": 0.92,
            },
            "checked_lolbin_signer": {"type": "noul", "noul": 0.15, "confidence": 0.85},
            "verified_asset_tier": {"type": "noul", "noul": 0.92, "confidence": 0.92},
        },
    },
    "borderline_single_source_ambiguous": {
        "enabled": True,
        "answers": {
            "compromise_detected": {"type": "noul", "noul": 0.30, "confidence": 0.70},
            "corroborated_two_sources": {
                "type": "noul",
                "noul": 0.18,
                "confidence": 0.82,
            },
            "widened_72h_to_168h_on_empty_hunt": {
                "type": "noul",
                "noul": 0.90,
                "confidence": 0.90,
            },
            "checked_lolbin_signer": {"type": "noul", "noul": 0.85, "confidence": 0.85},
            "verified_asset_tier": {"type": "noul", "noul": 0.95, "confidence": 0.95},
        },
    },
    "unverified_cmdb_tier_lolbin": {
        "enabled": True,
        "answers": {
            "compromise_detected": {"type": "noul", "noul": 0.65, "confidence": 0.65},
            "corroborated_two_sources": {
                "type": "noul",
                "noul": 0.88,
                "confidence": 0.88,
            },
            "widened_72h_to_168h_on_empty_hunt": {
                "type": "noul",
                "noul": 0.91,
                "confidence": 0.91,
            },
            "checked_lolbin_signer": {"type": "noul", "noul": 0.22, "confidence": 0.78},
            "verified_asset_tier": {"type": "noul", "noul": 0.09, "confidence": 0.91},
        },
    },
    "unsigned_lolbin_workstation_c2": {
        "enabled": True,
        "answers": {
            "compromise_detected": {"type": "noul", "noul": 0.97, "confidence": 0.97},
            "corroborated_two_sources": {
                "type": "noul",
                "noul": 0.98,
                "confidence": 0.98,
            },
            "widened_72h_to_168h_on_empty_hunt": {
                "type": "noul",
                "noul": 0.95,
                "confidence": 0.95,
            },
            "checked_lolbin_signer": {"type": "noul", "noul": 0.96, "confidence": 0.96},
            "verified_asset_tier": {"type": "noul", "noul": 0.97, "confidence": 0.97},
        },
    },
    "compromised_high_tier_db_server": {
        "enabled": True,
        "answers": {
            "compromise_detected": {"type": "noul", "noul": 0.96, "confidence": 0.96},
            "corroborated_two_sources": {
                "type": "noul",
                "noul": 0.97,
                "confidence": 0.97,
            },
            "widened_72h_to_168h_on_empty_hunt": {
                "type": "noul",
                "noul": 0.94,
                "confidence": 0.94,
            },
            "checked_lolbin_signer": {"type": "noul", "noul": 0.95, "confidence": 0.95},
            "verified_asset_tier": {"type": "noul", "noul": 0.96, "confidence": 0.96},
        },
    },
    "signed_benign_backup_admin": {
        "enabled": True,
        "answers": {
            "compromise_detected": {"type": "noul", "noul": 0.03, "confidence": 0.97},
            "corroborated_two_sources": {
                "type": "noul",
                "noul": 0.95,
                "confidence": 0.95,
            },
            "widened_72h_to_168h_on_empty_hunt": {
                "type": "noul",
                "noul": 0.93,
                "confidence": 0.93,
            },
            "checked_lolbin_signer": {"type": "noul", "noul": 0.97, "confidence": 0.97},
            "verified_asset_tier": {"type": "noul", "noul": 0.96, "confidence": 0.96},
        },
    },
    "dc_prod_ntdsutil": {
        "enabled": True,
        "answers": {
            "compromise_detected": {"type": "noul", "noul": 0.96, "confidence": 0.96},
            "corroborated_two_sources": {
                "type": "noul",
                "noul": 0.97,
                "confidence": 0.97,
            },
            "widened_72h_to_168h_on_empty_hunt": {
                "type": "noul",
                "noul": 0.95,
                "confidence": 0.95,
            },
            "checked_lolbin_signer": {"type": "noul", "noul": 0.94, "confidence": 0.94},
            "verified_asset_tier": {"type": "noul", "noul": 0.98, "confidence": 0.98},
        },
    },
}


def _ensure_decision_credentials(secret_name: str) -> None:
    """Populates GEMINI_API_KEY from Secret Manager if no Decision 1 creds exist."""
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


def run_scenarios(*, dry_run: bool = False) -> list[dict[str, Any]]:
    """Executes all 8 Workflow 3 scenarios and returns serialized results."""
    results: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        if dry_run:
            decision = decide_containment_action(
                asset_id=scenario.asset_id,
                asset_tier=scenario.asset_tier,
                decision1_response=_DRY_RUN_ANSWERS[scenario.scenario_id],
                latency_ms=0.0,
            )
        else:
            decision = evaluate_bayes_containment_gate(
                scenario.evidence_text,
                asset_id=scenario.asset_id,
                asset_tier=scenario.asset_tier,
            )
        record = decision.to_dict()
        record["scenario_id"] = scenario.scenario_id
        record["expected_action"] = scenario.expected_action.value
        record["matched"] = decision.action == scenario.expected_action
        results.append(record)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run Workflow 3 Cost-Weighted Bayes Containment Gate scenarios."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use deterministic synthetic Decision 1 responses instead of live API calls.",
    )
    parser.add_argument(
        "--secret-name",
        default="gemini-api-key",
        help="GCP Secret Manager secret name fallback when GEMINI_API_KEY is unset.",
    )
    parser.add_argument(
        "--json-out",
        type=pathlib.Path,
        default=DEFAULT_JSON_OUT,
        help="Path to write JSON results.",
    )
    args = parser.parse_args(argv)

    if not args.dry_run:
        _ensure_decision_credentials(args.secret_name)

    results = run_scenarios(dry_run=args.dry_run)

    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(results, indent=2) + "\n")

    print(
        f"{'SCENARIO':<36} {'ASSET':<12} {'TIER':<9} {'P':>6} {'CONF':>6} "
        f"{'E[CLOSE]':>10} {'E[ISOL]':>10} {'LAT(ms)':>8} {'ACTION':<30} {'OK'}"
    )
    print("-" * 142)
    all_ok = True
    for r in results:
        ok = bool(r["matched"]) and not bool(r["fallback"])
        if not ok:
            all_ok = False
        print(
            f"{r['scenario_id']:<36} {r['asset_id']:<12} {r['asset_tier']:<9} "
            f"{r['p_compromise']:>6.3f} {r['confidence']:>6.3f} "
            f"${r['expected_loss_close_usd']:>9,.0f} "
            f"${r['expected_loss_isolate_usd']:>9,.0f} "
            f"{r['latency_ms']:>8.1f} {r['action']:<30} {'PASS' if ok else 'FAIL'}"
        )

    print(f"\nResults written to {args.json_out}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
