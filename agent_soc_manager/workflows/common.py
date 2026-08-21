"""
Common utilities, shared Pydantic models, and helper functions for ADK Graph Workflows.

Provides reusable components across SecOps runbook graph workflows.
"""

import os
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# -----------------------------------------------------------------------------
# Safe Google ADK Imports with fallback for isolated test environments
# -----------------------------------------------------------------------------
try:
    from google.adk.agents import Agent
    from google.adk.events import Event
    from google.adk.workflow import START, Edge, FunctionNode, Workflow
except ImportError:
    class Agent:
        def __init__(self, *args, **kwargs):
            pass

    class Workflow:
        def __init__(self, *args, **kwargs):
            pass

    class Event:
        def __init__(self, route="", output=None, actions=None, **kwargs):
            self.route = route
            self.output = output
            self.actions = actions

    START = "START"

    class Edge:
        def __init__(self, *args, **kwargs):
            pass

    class FunctionNode:
        def __init__(self, *args, **kwargs):
            pass


# -----------------------------------------------------------------------------
# Shared Pydantic Input/Output Schemas
# -----------------------------------------------------------------------------

class BaseWorkflowInput(BaseModel):
    """Base input contract for SOAR workflows."""
    case_id: str | None = Field(default=None, description="SOAR Case ID for correlation and documentation")


class CommonSOAROutcome(BaseModel):
    """Base outcome model containing standardized SOAR documentation payload."""
    case_id: str | None = Field(default=None, description="SOAR Case ID")
    action_status: str = Field(description="Workflow status code or disposition string")
    soar_comment_text: str = Field(description="Formatted comment string posted to SOAR case")
    report_markdown: str | None = Field(default=None, description="Generated Markdown report content")


# -----------------------------------------------------------------------------
# Common Utility Functions
# -----------------------------------------------------------------------------

def sanitize_entity_value(val: str) -> str:
    """Strips leading/trailing whitespace and normalizes entity strings."""
    return val.strip() if val else ""


def format_soar_comment(title: str, metrics: dict[str, Any], recommendation: str) -> str:
    """Formats standardized SOAR case comment block."""
    lines = [f"### {title}"]
    for key, value in metrics.items():
        lines.append(f"- **{key}:** {value}")
    lines.append(f"- **Recommendation:** {recommendation}")
    return "\n".join(lines)


def generate_markdown_summary(
    title: str,
    target_name: str,
    target_value: str,
    case_id: str | None,
    status: str,
    details: str,
    soar_comment: str,
) -> str:
    """Generates a standard Markdown investigation summary artifact."""
    return f"""# {title}

## Target Context
- **{target_name}:** `{target_value}`
- **Case ID:** `{case_id or 'N/A'}`
- **Workflow Status:** `{status}`

## Details
{details}

## SOAR Case Comment
```text
{soar_comment}
```
"""


def save_workflow_report_to_disk(report_name: str, report_markdown: str) -> str:
    """Writes workflow generated markdown reports to the reports directory."""
    reports_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "reports")
    )
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name, ext = os.path.splitext(report_name)
    if not ext:
        ext = ".md"
    file_name = f"{base_name}_{timestamp}{ext}"
    file_path = os.path.join(reports_dir, file_name)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(report_markdown)
    return file_path
