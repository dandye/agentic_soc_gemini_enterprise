#!/usr/bin/env python3
"""
Provenance helper utility for formatting and validating YAML frontmatter
metadata in Markdown files.
"""

from datetime import datetime


def format_provenance(
    source_type: str,
    source_tool: str,
    is_fine_tune_safe: bool,
    description: str = "",
) -> str:
    """
    Format a standard YAML frontmatter block for markdown files.

    Args:
        source_type: 'api_response', 'mcp_tool', 'generative_ai', 'manual', or 'python_generated'
        source_tool: Name of the script, model, or tool generating the data
        is_fine_tune_safe: Boolean indicating if this is safe for model fine-tuning
        description: Brief details about the context

    Returns:
        The formatted YAML frontmatter string block, including delimiters
    """
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    safe_str = "true" if is_fine_tune_safe else "false"

    frontmatter = [
        "---",
        "provenance:",
        f"  source_type: {source_type}",
        f"  source_tool: {source_tool}",
        f"  timestamp: {timestamp}",
        f"  is_fine_tune_safe: {safe_str}",
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
