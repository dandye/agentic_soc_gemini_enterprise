"""Progressive MCP Discovery and Dynamic Execution Meta-Tools.

Provides runtime meta-tools for discovery, schema inspection, and dynamic execution
without upfront JSON schema context bloat.
"""

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

from .mcp_registry import MCPToolRegistry


logger = logging.getLogger(__name__)

# Global singleton MCP registry
global_mcp_registry = MCPToolRegistry()


def search_mcp_tools(query: str = "", server: str = "") -> str:
    """Discovers available MCP security tools by keyword or server without loading full schemas.

    Use this tool to find relevant MCP tools for SIEM (Chronicle), SOAR (SecOps SOAR),
    GTI (VirusTotal / Threat Intelligence), or SCC (Security Command Center) before requesting
    their schema or executing them.

    Args:
        query: Optional search keyword to filter tool names, descriptions, or servers.
        server: Optional server filter ('siem', 'soar', 'gti', 'scc', etc.).

    Returns:
        str: Formatted list of matching tools with concise descriptions.
    """
    tools = global_mcp_registry.search_tools(query=query, server=server)
    if not tools:
        msg = "No MCP tools found"
        if query and server:
            msg += f" matching query '{query}' and server '{server}'."
        elif query:
            msg += f" matching query '{query}'."
        elif server:
            msg += f" for server '{server}'."
        else:
            msg += " in registry."
        return msg

    lines = ["### Discovered MCP Security Tools\n"]
    current_server = ""
    for t in tools:
        if t["server"] != current_server:
            current_server = t["server"]
            lines.append(f"\n#### Server: {current_server.upper()}")
        lines.append(f"- **`{t["name"]}`**: {t["description"]}")

    return "\n".join(lines)


def get_mcp_tool_schema(tool_name: str) -> str:
    """Retrieves the JSON Schema, argument definitions, and requirements for a specific MCP tool.

    Use this tool before executing an MCP tool to inspect its required and optional parameters.

    Args:
        tool_name: The exact name of the MCP tool (e.g. 'soar_get_case', 'gti_get_file_report').

    Returns:
        str: JSON-formatted schema documentation including required fields and property descriptions.
    """
    schema_info = global_mcp_registry.get_tool_schema(tool_name)
    if not schema_info:
        return f"Error: MCP tool '{tool_name}' not found in registry. Use 'search_mcp_tools' to discover available tools."

    return json.dumps(schema_info, indent=2)


def execute_mcp_tool(tool_name: str, arguments: Any = None) -> str:
    """Dynamically executes an MCP security tool with provided arguments.

    Use this tool after obtaining the tool's parameter schema via `get_mcp_tool_schema`.

    Args:
        tool_name: Name of the MCP tool to execute (e.g. 'soar_get_case', 'gti_get_ip_report').
        arguments: Key-value parameters matching the tool's JSON Schema (as dict or JSON string).

    Returns:
        str: JSON string containing the tool's execution results or error details.
    """
    parsed_args: dict[str, Any] = {}
    if arguments:
        if isinstance(arguments, str):
            try:
                parsed_args = json.loads(arguments)
            except Exception as e:
                return f"Error parsing arguments JSON: {e}"
        elif isinstance(arguments, dict):
            parsed_args = arguments
        else:
            return f"Error: arguments must be a JSON string or dict, got {type(arguments).__name__}"

    try:
        res = global_mcp_registry.execute_tool(tool_name, parsed_args)
        if asyncio.iscoroutine(res):
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If in running loop, run in separate thread runner
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        res = pool.submit(asyncio.run, res).result()
                else:
                    res = loop.run_until_complete(res)
            except RuntimeError:
                res = asyncio.run(res)

        if isinstance(res, (dict, list)):
            return json.dumps(res, default=str)
        return str(res)
    except Exception as e:
        logger.error(f"Error executing MCP tool '{tool_name}': {e}")
        return f"Error executing tool '{tool_name}': {e}"


def get_progressive_mcp_meta_tools() -> list[Callable]:
    """Returns the list of 3 progressive discovery meta-tools for agent registration."""
    return [search_mcp_tools, get_mcp_tool_schema, execute_mcp_tool]
