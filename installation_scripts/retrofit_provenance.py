#!/usr/bin/env python3
"""
Migration script to retroactively add provenance metadata blocks
to all existing Markdown files in harvested_investigations.
"""

from pathlib import Path

from provenance_helper import format_provenance, has_provenance


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
    skipped_count = 0

    for file_path in md_files:
        filename = file_path.name

        # Read current content
        content = file_path.read_text(encoding="utf-8")

        # Check if it already has frontmatter
        if has_provenance(content):
            skipped_count += 1
            continue

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

        # Generate provenance header
        provenance_header = format_provenance(
            source_type="api_response",
            source_tool="harvest_investigations.py",
            is_fine_tune_safe=True,
            description=description,
        )

        # Write updated content
        new_content = provenance_header + content
        file_path.write_text(new_content, encoding="utf-8")
        updated_count += 1

    print("\n==================================================")
    print("PROVENANCE RETROFIT MIGRATION COMPLETE")
    print("==================================================")
    print(f"Total markdown files found: {len(md_files)}")
    print(f"Successfully updated:       {updated_count}")
    print(f"Already had provenance:     {skipped_count}")
    print("==================================================")


if __name__ == "__main__":
    main()
