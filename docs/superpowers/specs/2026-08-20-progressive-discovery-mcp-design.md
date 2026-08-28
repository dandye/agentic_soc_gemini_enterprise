---
type: "Architecture"
title: "Progressive MCP Tool Discovery & Dynamic Execution Design Specification"
description: "Architecture and design specification for client-side progressive discovery, on-demand schema expansion, and dynamic MCP execution"
resource: "docs/superpowers/specs/2026-08-20-progressive-discovery-mcp-design.md"
timestamp: "2026-08-21T20:20:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-08-21T20:20:00Z"
---

# Design Specification: Progressive MCP Tool Discovery & Dispatcher

## 1. Executive Summary

This specification defines the **Progressive MCP Tool Discovery & Dispatcher Framework** for the Google ADK Multi-Agent Cybersecurity Operations platform.

Static registration of dozens of Model Context Protocol (MCP) security tools (`siem-mcp`, `soar-mcp`, `gti-mcp`, `scc-mcp`) injects full JSON schemas upfront, leading to prompt context bloat, token exhaustion, increased latency, and tool-selection degradation.

This architecture introduces:
1. **`MCPToolRegistry`**: Discovers, indexes, normalizes, and manages tool schemas across connected MCP security servers.
2. **Progressive MCP Meta-Tools (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`)**: Enables LLM agents to maintain ultra-lean tool definitions while retaining full capability to discover parameters and dynamically dispatch calls to any connected MCP tool at runtime.

## 2. Architectural Overview

```
                                  +--------------------------------------------------+
                                  |                LLM Agent Context                 |
                                  |                                                  |
                                  |  * System Prompt: Progressive Tool Instructions  |
                                  |  * Active Tools:                                 |
                                  |      - search_mcp_tools(query, server)           |
                                  |      - get_mcp_tool_schema(tool_name)            |
                                  |      - execute_mcp_tool(tool_name, arguments)    |
                                  +------------------------+-------------------------+
                                                           |
                        +----------------------------------+----------------------------------+
                        |                                                                     |
                        v (Discovery / Schema Lookup)                                         v (Execution)
        +--------------------------------+                                    +---------------------------------+
        |        MCPToolRegistry         |                                    |      MCP Execution Engine       |
        |  * Discovers & indexes tools   |                                    |  * Validates parameters         |
        |    from all connected servers  |                                    |  * Resolves target MCP client   |
        |  * Generates concise catalogs  |                                    |  * Routes call via async client |
        |  * Serves full JSON schemas    |                                    |  * Returns structured outcome   |
        +---------------+----------------+                                    +----------------+----------------+
                        |                                                                      |
                        +-------------------------------+--------------------------------------+
                                                        |
                                                        v
                        +-------------------------------------------------------------+
                        |                 Connected MCP Security Servers              |
                        |                                                             |
                        |   +----------------+   +---------------+   +------------+   |
                        |   |   Chronicle    |   |  SecOps SOAR  |   | VirusTotal |   |
                        |   |   SIEM MCP     |   |     MCP       |   |  GTI MCP   |   |
                        |   +----------------+   +---------------+   +------------+   |
                        +-------------------------------------------------------------+
```

## 3. Detailed Component Architecture

### 3.1 Data Structures & MCPToolRegistry (`agent_soc_manager/tools/mcp_registry.py`)

#### `MCPToolMetadata`
Dataclass capturing indexed MCP tool attributes:
- `name: str` - Standard tool identifier (e.g. `soar_get_case` or `siem_search_events`).
- `server: str` - Server namespace (`siem`, `soar`, `gti`, `scc`).
- `description: str` - Concise one-sentence summary for routing (< 200 chars).
- `input_schema: dict[str, Any]` - Full JSON Schema defining required/optional properties and types.
- `executor: Callable | None` - Optional direct async/sync execution callable.

#### `MCPToolRegistry`
Core registry providing:
- `register_tool(metadata: MCPToolMetadata) -> None`: Indexes tool under normalized dual keys (kebab-case and snake_case).
- `register_mcp_toolset(toolset: McpToolset | Any, server_name: str) -> int`: Auto-extracts tool definitions from Google ADK `McpToolset` instances.
- `search_tools(query: str = "", server: str = "") -> list[dict[str, str]]`: Keyword search across tool names, server tags, and descriptions.
- `get_tool_schema(tool_name: str) -> dict[str, Any] | None`: Returns formatted parameter documentation and JSON Schema.
- `get_compact_catalog(server: str = "") -> str`: Generates a compact Markdown list for prompt injection.
- `execute_tool(tool_name: str, arguments: dict[str, Any]) -> Any`: Validates inputs and routes execution to the registered tool executor.

### 3.2 Progressive Discovery Meta-Tools (`agent_soc_manager/tools/progressive_mcp_tools.py`)

1. **`search_mcp_tools(query: str = "", server: str = "") -> str`**
   - Discovers available MCP security tools by keyword or server without loading parameter schemas into context.

2. **`get_mcp_tool_schema(tool_name: str) -> str`**
   - Retrieves full parameter definitions, required fields, data types, and descriptions for a specific tool on demand.

3. **`execute_mcp_tool(tool_name: str, arguments: Any) -> str`**
   - Executes the selected MCP tool dynamically with the supplied arguments.
   - Includes execution error boundaries and JSON serialization handling.
