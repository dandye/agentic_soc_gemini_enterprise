import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


# Paths
#
# PROJECT_ROOT is derived from this file's location so the audit runs from any
# checkout, any machine, and CI. Override with PARITY_PROJECT_ROOT if you are
# auditing a checkout other than the one this script lives in.
PROJECT_ROOT = Path(
    os.environ.get("PARITY_PROJECT_ROOT", Path(__file__).resolve().parent.parent)
)

# Where audit artifacts are written. Defaults to evalsets/parity/ inside the
# repo so results are versioned alongside the eval ledgers; point
# PARITY_ARTIFACT_DIR at an external vault to keep them out of git.
ART_DIR = Path(
    os.environ.get("PARITY_ARTIFACT_DIR", PROJECT_ROOT / "evalsets" / "parity")
)
EXPERIMENTS_DIR = ART_DIR / "experiments"
PARITY_LEDGER_PATH = ART_DIR / "parity_ledger.md"

# Ensure directories exist
EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)


def parse_dimension_score(dimension_name, content):
    """
    Bulletproof parser for dimension scores in the markdown table.
    """
    pattern = rf"{re.escape(dimension_name)}\*\*\s*\|\s*\*?\*?([\d\.]+)\%"
    match = re.search(pattern, content, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return 0.0


def parse_report_score(content):
    """
    Parses a report to find the overall grade.
    """
    overall = parse_dimension_score("OVERALL INVESTIGATION GRADE", content)
    if overall == 0.0:
        overall = parse_dimension_score("OVERALL QUALITY GRADE", content)
    return overall


def parse_benchmark_report(report_path):
    """
    Parses a benchmark report to extract scores and tool trajectory.
    """
    if not report_path.exists():
        return None

    content = report_path.read_text()

    # Parse scores
    telemetry = parse_dimension_score("Telemetry Coverage", content)
    timeline = parse_dimension_score("Timeline Accuracy", content)
    containment = parse_dimension_score("Containment Precision", content)
    overall = parse_report_score(content)

    # Parse trajectory
    trajectory = []
    traj_m = re.search(
        r"### AI Tool Trajectory\s*\n+```json\n(.*?)\n```", content, re.DOTALL
    )
    if traj_m:
        try:
            trajectory = json.loads(traj_m.group(1))
        except Exception:
            trajectory = []

    # Check for common error signatures
    errors = []
    if "401" in content or "Unauthorized" in content:
        errors.append("401 Unauthorized (Credential/OAuth issue)")
    if "PermissionDenied" in content or "permission" in content.lower():
        errors.append("Permission Denied (IAM role issue)")
    if "timeout" in content.lower() or "deadline" in content.lower():
        errors.append("Timeout (Network/gRPC hang)")
    if "ConnectionError" in content or "connection failed" in content.lower():
        errors.append("Connection Failure (API host unreachable)")

    return {
        "telemetry": telemetry,
        "timeline": timeline,
        "containment": containment,
        "overall": overall,
        "trajectory": trajectory,
        "errors": errors,
        "raw_content": content,
    }


def run_benchmark(uuid, local=False):
    """
    Runs the benchmark script for a specific campaign.
    """
    cmd = [
        "python",
        str(PROJECT_ROOT / "installation_scripts/benchmark_human_vs_ai.py"),
        "--uuid",
        uuid,
    ]
    if local:
        cmd.append("--local")

    print(
        f"[EXEC] Running {'Local' if local else 'Cloud'} benchmark for campaign {uuid}..."
    )
    subprocess.run(cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT))

    report_path = ART_DIR / f"benchmark_{uuid}_report.md"
    return parse_benchmark_report(report_path)


def audit_parity(uuid):
    """
    Runs local and remote benchmarks, performs differential analysis, and logs results.
    """
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    file_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # Resolve campaign name from telemetry file if possible
    campaign_name = "Unknown Threat"
    json_path = PROJECT_ROOT / f"investigations/{uuid}.json"
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text())
            campaign_name = data.get("displayName", campaign_name)
        except Exception:
            campaign_name = "Unknown Threat"

    print(
        "\n================================================================================"
    )
    print(f"[START] Beginning Parity Audit for Campaign: {campaign_name} ({uuid})")
    print(
        "================================================================================"
    )

    # 1. Run Local
    local_data = run_benchmark(uuid, local=True)
    if not local_data:
        print("[ERROR] Local benchmark execution failed to produce a report.")
        return

    # 2. Run Remote
    remote_data = run_benchmark(uuid, local=False)
    if not remote_data:
        print(
            "[WARNING] Remote benchmark execution failed to produce a report or crashed. Logging default failure metrics."
        )
        remote_data = {
            "telemetry": 0.0,
            "timeline": 0.0,
            "containment": 0.0,
            "overall": 0.0,
            "trajectory": [],
            "errors": ["Cloud Execution Crash or Timeout"],
            "raw_content": "",
        }

    # 3. Differential Analysis
    variance = remote_data["overall"] - local_data["overall"]

    # Determine Status
    if (
        len(remote_data["errors"]) > 0
        and remote_data["overall"] < local_data["overall"] - 5.0
    ):
        status = "DEGRADED"
        primary_drift = ", ".join(remote_data["errors"])
    elif variance < -5.0:
        status = "DEGRADED"
        primary_drift = "Cognitive/behavioral discrepancy (Check tool logs)"
    elif abs(variance) <= 5.0:
        status = "PASSED"
        primary_drift = "None (Within LLM non-determinism limit)"
    else:
        status = "STABLE"
        primary_drift = f"Cloud scored higher by +{variance}%"

    # Write Parity Audit Report
    report_filename = f"parity_audit_{uuid}_{file_timestamp}.md"
    latest_report_filename = f"parity_audit_{uuid}.md"
    report_path = EXPERIMENTS_DIR / report_filename
    latest_report_path = EXPERIMENTS_DIR / latest_report_filename

    audit_md = f"""---
type: "Evaluation Report"
title: "Environment Parity Audit: {campaign_name}"
description: "Differential parity analysis between local in-process and deployed cloud agent execution trajectories."
resource: "file://{report_path}"
timestamp: "{datetime.utcnow().isoformat()}Z"
provenance:
  source_type: "generative_ai"
  source_tool: "audit_environment_parity"
  timestamp: "{datetime.utcnow().isoformat()}Z"
---

# Environment Parity Audit: {campaign_name}

*   **Campaign UUID:** `{uuid}`
*   **Audit Timestamp:** {timestamp}
*   **Parity Status:** **{status}**

## Score Comparison

| Metric | Local Runtime | Cloud Deployed | Variance |
| :--- | :---: | :---: | :---: |
| Telemetry Coverage | {local_data['telemetry']}% | {remote_data['telemetry']}% | {remote_data['telemetry'] - local_data['telemetry']:+.1f}% |
| Timeline Accuracy | {local_data['timeline']}% | {remote_data['timeline']}% | {remote_data['timeline'] - local_data['timeline']:+.1f}% |
| Containment Precision | {local_data['containment']}% | {remote_data['containment']}% | {remote_data['containment'] - local_data['containment']:+.1f}% |
| **OVERALL GRADE** | **{local_data['overall']}%** | **{remote_data['overall']}%** | **{variance:+.1f}%** |

## Trajectory Comparison

*   **Local Tool Sequence (In-Process):**
    `{ " -> ".join(local_data['trajectory']) if local_data['trajectory'] else 'No tools executed' }`

*   **Cloud Tool Sequence (Deployed):**
    `{ " -> ".join(remote_data['trajectory']) if remote_data['trajectory'] else 'No tools executed' }`

## Differential Diagnosis & Findings

*   **Audit Status:** {status}
*   **Primary Drift Cause:** {primary_drift}

### Error Signatures Detected
{chr(10).join([f'- {e}' for e in remote_data['errors']]) if remote_data['errors'] else '- None detected in remote execution.'}

### Trajectory Analysis
Local and remote runs were compared for tool-routing alignment. A large discrepancy in scores or tool paths usually points to container configuration differences, regional gRPC routing issues, or expired OAuth credentials in the deployed cloud environment.
"""

    # Save the reports (both timestamped and the latest constant pointer)
    report_path.write_text(audit_md)
    latest_report_path.write_text(audit_md)
    print(f"[SUCCESS] Parity Audit Report saved to: file://{latest_report_path}")

    # 4. Update the Master Parity Ledger
    update_parity_ledger(
        uuid,
        campaign_name,
        local_data["overall"],
        remote_data["overall"],
        status,
        primary_drift,
        timestamp,
    )


def update_parity_ledger(
    uuid, campaign_name, local_score, remote_score, status, primary_drift, timestamp
):
    """
    Updates the central parity_ledger.md file, adding or replacing the row for this campaign.
    """
    ledger_uri = PARITY_LEDGER_PATH.resolve().as_uri()
    header = f"""---
type: "Documentation"
title: "Multi-Agent SOC Network: Master Parity Ledger"
description: "Aggregated registry of local vs. cloud environment parity audits and production regression tracking."
resource: "{ledger_uri}"
timestamp: "2026-06-22T12:00:00Z"
provenance:
  source_type: "manual"
  source_tool: "audit_environment_parity"
  timestamp: "2026-06-22T12:00:00Z"
---

# Multi-Agent SOC Network: Master Parity Ledger

This ledger tracks the results of all environment parity audits run between the local in-process runtime and the deployed cloud Agent Engine.

## Master Parity Scorecard

| Last Audit Date | Campaign Name | Campaign UUID | Local Score | Cloud Score | Status | Primary Drift Cause / Notes |
| :--- | :--- | :--- | :---: | :---: | :--- | :--- |
"""

    new_row = f"| {timestamp[:10]} | {campaign_name} | `{uuid[:8]}` | {local_score}% | {remote_score}% | **{status}** | {primary_drift} |\n"

    rows = {}
    if PARITY_LEDGER_PATH.exists():
        content = PARITY_LEDGER_PATH.read_text()
        # Parse existing rows to prevent duplicates and keep latest results
        for line in content.splitlines():
            if (
                line.startswith("|")
                and not line.startswith("| Last Audit Date")
                and not line.startswith("| :---")
            ):
                parts = line.split("|")
                if len(parts) >= 8:
                    existing_uuid_part = parts[3].strip().replace("`", "")
                    rows[existing_uuid_part] = line

    # Insert or update this campaign's row
    short_uuid = uuid[:8]
    rows[short_uuid] = new_row.strip()

    # Rebuild ledger
    ledger_content = header
    for r_uuid in sorted(rows.keys()):
        ledger_content += rows[r_uuid] + "\n"

    PARITY_LEDGER_PATH.write_text(ledger_content)
    print(f"[SUCCESS] Master Parity Ledger updated: file://{PARITY_LEDGER_PATH}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python audit_environment_parity.py <CAMPAIGN_UUID>")
        sys.exit(1)

    campaign_uuid = sys.argv[1]
    audit_parity(campaign_uuid)
