import os
import re
import subprocess
import time
from pathlib import Path


# Configured list of all 15 campaigns, their paths, and their UUIDs
FLEET_CAMPAIGNS = [
    # Stage 1: Initial 5 campaigns
    {
        "name": "MSBuild Bypass (FP)",
        "uuid": "0355946c-a580-4593-b9b1-e69e162d57e9",
        "path": "worktrees/campaign_msbuild_bypass",
    },
    {
        "name": "SharpNoPSExec (TP)",
        "uuid": "084efd15-d572-4f95-8878-e540f82ab864",
        "path": "worktrees/campaign_sharpnopsexec",
    },
    {
        "name": "WMI & Mimikatz (TP)",
        "uuid": "e907f501-13d6-49a7-b003-c8534b263c2b",
        "path": "worktrees/campaign_wmi_mimikatz",
    },
    {
        "name": "Defender Abuse (TP)",
        "uuid": "8ff94964-c022-43e6-882e-c1da42470262",
        "path": "worktrees/campaign_defender_abuse",
    },
    {
        "name": "ntdsutil AD Theft (TP)",
        "uuid": "0a96ea4c-aab1-49f1-9136-17a8af63c161",
        "path": "worktrees/campaign_ntdsutil_theft",
    },
    # Stage 2: 10 new campaigns
    {
        "name": "Backup Script (FP)",
        "uuid": "c06477e1-4e4d-4ee1-934d-6b2e5b5c3167",
        "path": "worktrees/campaign_backup_fp",
    },
    {
        "name": "Admin Tool (FP)",
        "uuid": "bf77d315-4707-47fc-b200-83352f5b4203",
        "path": "worktrees/campaign_admin_tool_fp",
    },
    {
        "name": "Shadow Maint (FP)",
        "uuid": "5a2d8f97-0a46-4355-b992-11e796d95c71",
        "path": "worktrees/campaign_shadow_maintenance_fp",
    },
    {
        "name": "Remote Mgmt (FP)",
        "uuid": "03cbf404-9914-4d40-be82-f97c15a676be",
        "path": "worktrees/campaign_remote_mgmt_fp",
    },
    {
        "name": "Service Migr (FP)",
        "uuid": "b32516a5-ea42-47f3-9424-eb0c2c8dd75f",
        "path": "worktrees/campaign_service_migration_fp",
    },
    {
        "name": "Password Spray (TP)",
        "uuid": "10fbb728-6739-420f-91a3-4f5fcdad1cbc",
        "path": "worktrees/campaign_password_spray_tp",
    },
    {
        "name": "LSASS Memory Dump (TP)",
        "uuid": "5dbc3c30-d7a2-4fa1-913e-23e7bc2c87c3",
        "path": "worktrees/campaign_lsass_dump_tp",
    },
    {
        "name": "ADFS DC Intrusion (TP)",
        "uuid": "1f2fb800-9e3b-419c-a03f-b747c6882566",
        "path": "worktrees/campaign_adfs_intrusion_tp",
    },
    {
        "name": "Broad Admin Spray (TP)",
        "uuid": "1b6bf948-0e8c-4977-9f3f-f8b085a76d2a",
        "path": "worktrees/campaign_broad_spray_tp",
    },
    {
        "name": "Lateral Payload (TP)",
        "uuid": "21294d36-8bc8-4242-99eb-98b532779138",
        "path": "worktrees/campaign_lateral_payload_tp",
    },
]


def run_fleet(concurrency: int = 1):
    project_root = Path.cwd()
    log_dir = project_root / "scratch" / "fleet_logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # Resolve environment variables
    env = os.environ.copy()
    env["GOOGLE_GENAI_USE_VERTEXAI"] = "True"
    # Ensure standard GCP credentials path if present
    sa_path = project_root / "secops-demo-env-391e3b623e0a.json"
    if sa_path.exists():
        env["GOOGLE_APPLICATION_CREDENTIALS"] = str(sa_path)

    print("=" * 80)
    print(
        f"[LAUNCH] LAUNCHING BENCHMARKING FLEET (15 CAMPAIGNS, CONCURRENCY: {concurrency})"
    )
    print("=" * 80)
    print(f"Project Root: {project_root}")
    print(f"Fleet Logs:   {log_dir}")
    print("-" * 80)

    # Bounded Worker Pool Queue
    queue = list(FLEET_CAMPAIGNS)
    active_processes = []

    while queue or active_processes:
        # Fill active slots up to concurrency limit
        while queue and len(active_processes) < concurrency:
            comp = queue.pop(0)
            name = comp["name"]
            uuid = comp["uuid"]
            worktree_path = project_root / comp["path"]

            log_file_path = log_dir / f"{uuid}.log"
            log_file = open(log_file_path, "w", buffering=1)

            cmd = [
                "python",
                "installation_scripts/benchmark_human_vs_ai.py",
                "--uuid",
                uuid,
            ]

            print(
                f"[SPAWN] Spawning: {name:<25} | Worktree: {comp['path']} -> {uuid[:8]}..."
            )
            proc = subprocess.Popen(
                cmd,
                cwd=str(worktree_path),
                env=env,
                stdout=log_file,
                stderr=log_file,
                text=True,
            )
            active_processes.append(
                {
                    "name": name,
                    "uuid": uuid,
                    "proc": proc,
                    "log_file": log_file,
                    "log_path": log_file_path,
                    "start_time": time.time(),
                }
            )

            # Stagger spawning within the pool slightly to prevent network handshake collisions
            if queue and len(active_processes) < concurrency:
                time.sleep(5)

        # Check on active processes
        still_active = []
        for p in active_processes:
            ret = p["proc"].poll()
            if ret is not None:
                p["log_file"].close()
                elapsed = time.time() - p["start_time"]
                if ret == 0:
                    print(
                        f"[SUCCESS] Finished: {p['name']:<25} | Elapsed: {elapsed:.1f}s | Active Slots: {len(active_processes)-1}/{concurrency}"
                    )
                else:
                    print(
                        f"[FAILED] Failed:   {p['name']:<25} | Elapsed: {elapsed:.1f}s | Status: Exit Code {ret} (See log: {p['log_path']})"
                    )
            else:
                still_active.append(p)
        active_processes = still_active

        # Sleep briefly before the next poll to minimize CPU usage
        if queue or active_processes:
            time.sleep(5)


def compile_results():
    print("=" * 80)
    print("[SUMMARY] CONCURRENT FLEET INVESTIGATIONS COMPLETE! COMPILING RESULTS...")
    print("=" * 80)

    # Compile Markdown table
    report_artifacts_dir = Path(
        "/Users/dandye/.gemini/jetski/brain/39525e8a-aae4-4a3e-8010-e6cbe24b229d"
    )

    table_lines = [
        "| Campaign / Threat Triage | Telemetry | Timeline | Containment | OVERALL GRADE | QA Verdict / Rating |",
        "| :--- | :---: | :---: | :---: | :---: | :--- |",
    ]

    for comp in FLEET_CAMPAIGNS:
        name = comp["name"]
        uuid = comp["uuid"]

        # Parse scorecard from the generated artifact
        artifact_path = report_artifacts_dir / f"benchmark_{uuid}_report.md"
        if not artifact_path.exists():
            table_lines.append(
                f"| {name} ({uuid[:8]}) | - | - | - | **NO REPORT** | [WARNING] Evaluation report not found |"
            )
            continue

        content = artifact_path.read_text()

        # Extract scores
        telemetry = "0.0%"
        timeline = "0.0%"
        containment = "0.0%"
        overall = "0.0%"

        telemetry_match = re.search(
            r"Telemetry Coverage\*\*\s*\|\s*([\d\.]+\%)", content
        )
        if telemetry_match:
            telemetry = telemetry_match.group(1)

        timeline_match = re.search(r"Timeline Accuracy\*\*\s*\|\s*([\d\.]+\%)", content)
        if timeline_match:
            timeline = timeline_match.group(1)

        containment_match = re.search(
            r"Containment Precision\*\*\s*\|\s*([\d\.]+\%)", content
        )
        if containment_match:
            containment = containment_match.group(1)

        overall_match = re.search(
            r"OVERALL (?:INVESTIGATION|QUALITY) GRADE\*\*\s*\|\s*\*\*([\d\.]+\%)\*\*",
            content,
        )
        if overall_match:
            overall = overall_match.group(1)

        # Extract the QA Rating/Verdict
        rating = "Passed"
        rating_match = re.search(
            r"OVERALL (?:INVESTIGATION|QUALITY) GRADE\*\*\s*\|\s*\*\*[\d\.]+\%\*\*\s*\|\s*(.*?)\s*\|",
            content,
        )
        if rating_match:
            rating = rating_match.group(1).strip()
            # Strip any emojis or non-ASCII badges from parsed rating to maintain professional formatting
            rating = re.sub(r"[^\x00-\x7F]+", "", rating).strip()

        table_lines.append(
            f"| {name} ({uuid[:8]}) | {telemetry} | {timeline} | {containment} | **{overall}** | {rating} |"
        )

    master_report = "\n".join(table_lines)
    print("\n" + master_report + "\n")

    # Save master report
    master_report_path = report_artifacts_dir / "fleet_benchmarking_summary.md"

    # Compute average score
    scores = []
    for line in table_lines[2:]:
        parts = line.split("|")
        if len(parts) >= 6:
            score_str = parts[5].replace("**", "").replace("%", "").strip()
            try:
                scores.append(float(score_str))
            except ValueError:
                pass
    avg_score = sum(scores) / len(scores) if scores else 0.0

    master_report_path.write_text(
        "---\n"
        'type: "Evaluation Report"\n'
        'title: "Multi-Agent SOC Network: Master Fleet Benchmarking Report"\n'
        'description: "Aggregated concurrent evaluation of the RAG-decoupled multi-agent SOC network across 15 parallel production threat campaigns."\n'
        f'resource: "file://{master_report_path}"\n'
        'timestamp: "2026-06-21T13:21:00Z"\n'
        "provenance:\n"
        '  source_type: "generative_ai"\n'
        '  source_tool: "run_fleet_benchmarks"\n'
        '  timestamp: "2026-06-21T13:21:00Z"\n'
        "---\n\n"
        "# Multi-Agent SOC Network: Master Fleet Benchmarking Report\n\n"
        f"### Fleet Summary: **{len(scores)}** Campaigns Evaluated | Average Grade: **{avg_score:.1f}%**\n\n"
        "This report aggregates the concurrent evaluation of our RAG-decoupled multi-agent SOC network "
        "across 15 parallel production threat campaigns.\n\n" + master_report
    )
    print(f"[SUCCESS] Master summary report saved to: file://{master_report_path}")
    print("=" * 80)


if __name__ == "__main__":
    import sys

    concurrency = 1
    if len(sys.argv) > 1 and sys.argv[1] == "--summary-only":
        compile_results()
        sys.exit(0)
    elif len(sys.argv) > 1 and sys.argv[1] == "--parallel":
        concurrency = len(FLEET_CAMPAIGNS)
    elif len(sys.argv) > 1 and sys.argv[1] in ("--concurrency", "-c"):
        try:
            concurrency = int(sys.argv[2])
        except (ValueError, IndexError):
            print("Error: --concurrency requires an integer value.")
            sys.exit(1)

    run_fleet(concurrency=concurrency)
    compile_results()
