#!/usr/bin/env python3
"""
Migration script to retroactively add provenance metadata blocks
to all existing Markdown files in harvested_investigations, merging
multiple YAML blocks into a single block.
"""

from datetime import UTC, datetime
from pathlib import Path


def merge_provenance_and_telemetry(content: str, description: str) -> str:
    """
    Parse a file's content, detect if there are 0, 1, or 2 YAML blocks,
    extract the telemetry metadata, and output a single merged YAML block
    with the new provenance fields.
    """
    parts = content.split("---")

    # Check if there are 2 blocks (at least 5 parts when split by '---')
    if len(parts) >= 5:
        telemetry_yaml = parts[3].strip()
        body = "---".join(parts[4:])
    elif len(parts) >= 3:
        # 1 block (3 parts)
        yaml_content = parts[1].strip()
        body = "---".join(parts[2:])
        # Check if the block has provenance or telemetry
        if "provenance:" in yaml_content:
            # It only has provenance, strip it to start fresh
            # Find any non-provenance keys in the block if present
            lines = yaml_content.splitlines()
            telemetry_lines = []
            in_provenance = False
            for line in lines:
                if line.strip().startswith("provenance:"):
                    in_provenance = True
                    continue
                if in_provenance and line.startswith("  "):
                    continue
                in_provenance = False
                telemetry_lines.append(line)
            telemetry_yaml = "\n".join(telemetry_lines).strip()
        else:
            telemetry_yaml = yaml_content
    else:
        # No frontmatter block
        telemetry_yaml = ""
        body = content

    # Build the new provenance lines
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    prov_lines = [
        "provenance:",
        "  source_type: api_response",
        "  source_tool: harvest_investigations.py",
        f"  timestamp: {timestamp}",
    ]
    if description:
        clean_desc = description.replace('"', '\\"')
        prov_lines.append(f'  description: "{clean_desc}"')

    # Merge provenance and telemetry into a single YAML block
    yaml_lines = prov_lines
    if telemetry_yaml:
        yaml_lines.append(telemetry_yaml)

    return "---\n" + "\n".join(yaml_lines).strip() + "\n---\n" + body.lstrip("\r\n")


def main():
    investigations_dir = Path(
        "/Users/dandye/Projects/agentic_soc_agentspace__worktrees/elastic_v0001/harvested_investigations"
    )
    if not investigations_dir.exists():
        print(f"Error: Directory {investigations_dir} does not exist.")
        return

    md_files = list(investigations_dir.glob("*.md"))
    print(f"Found {len(md_files)} markdown files in {investigations_dir}.")

    updated_count = 0

    for file_path in md_files:
        filename = file_path.name

        # Read current content
        content = file_path.read_text(encoding="utf-8")

        # Determine target details based on filename pattern
        if filename.startswith("case_"):
            case_id = filename.replace("case_", "").replace(".md", "")
            description = f"Harvested report summary for SOAR case {case_id}"
        elif filename.startswith("alert_"):
            alert_id = filename.replace("alert_", "").replace(".md", "")
            description = f"Harvested details for Chronicle alert {alert_id}"
        else:
            inv_id = filename.replace(".md", "")
            description = f"Harvested details for Chronicle investigation {inv_id}"

        # Merge YAML block and write updated content
        new_content = merge_provenance_and_telemetry(content, description)
        file_path.write_text(new_content, encoding="utf-8")
        updated_count += 1

    print("\n==================================================")
    print("PROVENANCE RETROFIT MIGRATION COMPLETE")
    print("==================================================")
    print(f"Total markdown files found & merged: {len(md_files)}")
    print(f"Successfully processed:              {updated_count}")
    print("==================================================")


if __name__ == "__main__":
    main()
