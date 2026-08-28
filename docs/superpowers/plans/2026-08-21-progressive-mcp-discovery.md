---
type: "Documentation"
title: "Progressive MCP Tool Discovery & Dynamic Execution Implementation Plan"
description: "Implementation plan for integrating progressive MCP discovery and dynamic execution across the SOC multi-agent architecture"
resource: "docs/superpowers/plans/2026-08-21-progressive-mcp-discovery.md"
timestamp: "2026-08-21T20:20:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-08-21T20:20:00Z"
---

# Progressive MCP Tool Discovery & Dynamic Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate client-side progressive discovery, on-demand schema expansion, and dynamic tool execution for connected MCP security tools (Chronicle SIEM, SecOps SOAR, Google Threat Intelligence, and Security Command Center) to eliminate context bloat and schema size limits.

**Architecture:** Build and integrate a centralized `MCPToolRegistry` that indexes tools from connected MCP servers and provides 3 lightweight meta-tools (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`) to the Orchestrator and Tier 1 analyst sub-agent.

**Tech Stack:** Python 3.10+, Google ADK (`google-adk`, `McpToolset`), Vertex AI Reasoning Engine, pytest.

**Spec:** `docs/superpowers/specs/2026-08-20-progressive-discovery-mcp-design.md`

## Global Constraints
- Never use emojis anywhere in code, comments, commit messages, or documentation.
- Maintain full backwards compatibility for existing custom functions, A2A delegation stubs, and grounding tools (AlloyDB, Neo4j, Elasticsearch, RAG).
- All MCP tools must be normalized with dual keys (supporting both snake_case and kebab-case).
- All unit and integration tests must pass cleanly.
- No hardcoded API secrets or credentials.

---

### Task 1: Centralized MCP Tool Registry Engine (`MCPToolRegistry`)

**Files:**
- Create/Verify: `agent_soc_manager/tools/mcp_registry.py`
- Test: `tests/test_mcp_registry.py`

**Interfaces:**
- Produces: `MCPToolMetadata`, `MCPToolRegistry`, `register_tool`, `register_mcp_toolset`, `get_tool`, `search_tools`, `get_tool_schema`, `get_compact_catalog`, `execute_tool`.

- [ ] **Step 1: Verify test suite for MCPToolRegistry**
  - Verify `tests/test_mcp_registry.py` covers registration, dual-key casing normalization, server filtering, keyword searching, schema retrieval, sync/async tool execution, and error handling.
- [ ] **Step 2: Run test suite to verify registry unit tests**
  - Run tests with pytest
- [ ] **Step 3: Commit Task 1**
  - `git add agent_soc_manager/tools/mcp_registry.py tests/test_mcp_registry.py && git commit -m "feat(mcp): implement centralized MCPToolRegistry engine"`

---

### Task 2: Progressive MCP Meta-Tools (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`)

**Files:**
- Create/Verify: `agent_soc_manager/tools/progressive_mcp_tools.py`
- Test: `tests/test_progressive_mcp_tools.py`

**Interfaces:**
- Consumes: `MCPToolMetadata`, `MCPToolRegistry` from `agent_soc_manager/tools/mcp_registry.py`
- Produces: `global_mcp_registry`, `search_mcp_tools(query, server)`, `get_mcp_tool_schema(tool_name)`, `execute_mcp_tool(tool_name, arguments)`, `get_progressive_mcp_meta_tools()`.

- [ ] **Step 1: Verify test suite for progressive MCP meta-tools**
  - Verify `tests/test_progressive_mcp_tools.py` covers discovery output formatting, schema serialization, JSON argument parsing, sync and async tool execution dispatching, and fallback error handling.
- [ ] **Step 2: Run unit tests to verify meta-tools**
  - Run tests with pytest
- [ ] **Step 3: Commit Task 2**
  - `git add agent_soc_manager/tools/progressive_mcp_tools.py tests/test_progressive_mcp_tools.py && git commit -m "feat(tools): add progressive MCP discovery meta-tools"`

---

### Task 3: Agent Integration & System Instruction Directives

**Files:**
- Modify: `agent_soc_manager/agent.py`
- Modify: `agent_soc_manager/prompts/orchestrator_instructions.md`
- Modify: `agent_soc_manager/prompts/tier1_analyst_instructions.md`

**Interfaces:**
- Consumes: `get_progressive_mcp_meta_tools()`, `global_mcp_registry`
- Produces: Updated `orchestrator_tools` and `tier1_tools` with progressive MCP discovery meta-tools and MCP server registration into `global_mcp_registry`.

- [ ] **Step 1: Update MCP server toolset initialization in `agent.py`**
  - Register connected toolsets (Chronicle SIEM, SecOps SOAR, GTI, SCC) into `global_mcp_registry`.
  - Pass `--with mcp<2.0.0` to uv-based MCP server invocations where applicable.
- [ ] **Step 2: Bind progressive discovery meta-tools to Orchestrator and Tier 1 Analyst**
  - Append `get_progressive_mcp_meta_tools()` to `tier1_tools` and `orchestrator_tools`.
- [ ] **Step 3: Update system prompts in `orchestrator_instructions.md` and `tier1_analyst_instructions.md`**
  - Add explicit instructions for the 3-step progressive MCP pattern:
    1. Use `search_mcp_tools` to find relevant tools.
    2. Use `get_mcp_tool_schema` to inspect parameter requirements.
    3. Use `execute_mcp_tool` to dynamically dispatch execution.
- [ ] **Step 4: Verify agent initialization**
  - Run verification script
- [ ] **Step 5: Commit Task 3**
  - `git add agent_soc_manager/agent.py agent_soc_manager/prompts/ && git commit -m "feat(agent): integrate progressive MCP discovery into orchestrator and tier 1 analyst"`

---

### Task 4: Full Verification and Testing

**Files:**
- Test: All tests under `tests/`
- Documentation: `docs/superpowers/specs/2026-08-20-progressive-discovery-mcp-design.md`

- [ ] **Step 1: Run complete test suite**
- [ ] **Step 2: Document design specification with OKF frontmatter**
  - Save `docs/superpowers/specs/2026-08-20-progressive-discovery-mcp-design.md`
- [ ] **Step 3: Commit Task 4**
  - `git add docs/ tests/ && git commit -m "docs(specs): add progressive discovery design specification and verification suite"`
