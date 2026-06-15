#!/usr/bin/env python3
"""
Provenance helper utility for formatting and validating YAML frontmatter
metadata in Markdown files.
"""

from datetime import UTC, datetime


def format_provenance(
    source_type: str,
    source_tool: str,
    description: str = "",
) -> str:
    """
    Format a standard YAML frontmatter block for markdown files.

    Args:
        source_type: 'api_response', 'mcp_tool', 'generative_ai', 'manual', or 'python_generated'
        source_tool: Name of the script, model, or tool generating the data
        description: Brief details about the context

    Returns:
        The formatted YAML frontmatter string block, including delimiters
    """
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    frontmatter = [
        "---",
        "provenance:",
        f"  source_type: {source_type}",
        f"  source_tool: {source_tool}",
        f"  timestamp: {timestamp}",
    ]

    if description:
        # Escape quotes if present
        clean_desc = description.replace('"', '\\"')
        frontmatter.append(f'  description: "{clean_desc}"')

    frontmatter.append("---")
    return "\n".join(frontmatter) + "\n"


def has_provenance(content: str) -> bool:
    """Check if the content already starts with a YAML frontmatter block containing provenance."""
    stripped = content.lstrip()
    if not stripped.startswith("---"):
        return False

    # Find the next occurrence of ---
    end_idx = stripped.find("---", 3)
    if end_idx == -1:
        return False

    yaml_block = stripped[3:end_idx]
    return "provenance:" in yaml_block


def inject_provenance(
    content: str,
    source_type: str,
    source_tool: str,
    description: str = "",
) -> str:
    """
    Inject provenance metadata into markdown content.
    If the content already starts with a YAML frontmatter block, the provenance fields
    are merged directly into that existing block. Otherwise, a new block is prepended.
    """
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Format the provenance YAML lines (without delimiters)
    prov_lines = [
        "provenance:",
        f"  source_type: {source_type}",
        f"  source_tool: {source_tool}",
        f"  timestamp: {timestamp}",
    ]
    if description:
        clean_desc = description.replace('"', '\\"')
        prov_lines.append(f'  description: "{clean_desc}"')

    # Check if there is an existing frontmatter block at the very start
    stripped = content.lstrip()
    if stripped.startswith("---"):
        end_idx = stripped.find("---", 3)
        if end_idx != -1:
            # We have an existing frontmatter block
            yaml_content = stripped[3:end_idx]
            body_content = stripped[end_idx + 3 :]

            # If it already has provenance, strip it first to avoid duplicates
            if "provenance:" in yaml_content:
                # Find where provenance starts and end of it (until next unindented key or end of block)
                lines = yaml_content.splitlines()
                new_yaml_lines = []
                in_provenance = False
                for line in lines:
                    if line.strip().startswith("provenance:"):
                        in_provenance = True
                        continue
                    if in_provenance and line.startswith("  "):
                        # Keep skipping indented lines under provenance
                        continue
                    # Any other line ends the skipping
                    in_provenance = False
                    new_yaml_lines.append(line)
                yaml_content = "\n".join(new_yaml_lines)

            # Build merged block
            merged_yaml = (
                "provenance:\n"
                + "\n".join("  " + line for line in prov_lines[1:])
                + "\n"
                + yaml_content.lstrip("\n")
            )
            return (
                "---\n" + merged_yaml.rstrip() + "\n---\n" + body_content.lstrip("\n")
            )

    # If no existing frontmatter, format as a standalone block
    header = format_provenance(source_type, source_tool, description)
    return header + content
