---
type: "Documentation"
title: "36 Executable ADK Graph Workflows Implementation Plan"
description: "Implementation plan for integrating the 36 deterministic ADK Graph Workflows, Pydantic IO schemas, and tool wrappers into agent_soc_manager"
resource: "docs/superpowers/plans/2026-08-21-adk-graph-workflows.md"
timestamp: "2026-08-21T21:10:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-08-21T21:10:00Z"
---

# 36 Executable ADK Graph Workflows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate the 36 deterministic ADK Graph Workflows and tool wrapper functions into `agent_soc_manager` with safe environment fallback imports, comprehensive unit test coverage, and documentation.

**Architecture:**
- `agent_soc_manager/workflows/`: Contains all 36 workflow modules with Pydantic contracts and decision branch routers.
- `agent_soc_manager/workflows/common.py`: Shared models, reporting helpers, and safe fallback classes for `google.adk`.
- `agent_soc_manager/tools/workflow_tools.py`: Wraps and exports all 36 workflow execution functions and `get_all_workflow_tools()`.

**Tech Stack:** Python 3.10+, Pydantic v2, Google ADK 2.x Graph Workflows.

**Spec:** `docs/superpowers/specs/2026-08-21-adk-graph-workflows-design.md`

## Global Constraints
- Never use emojis anywhere in code, comments, commit messages, or documentation.
- Maintain isolated unit test compatibility without requiring live GCP credentials.
- All Markdown files must have OKF YAML frontmatter.

---

### Task 1: Integrate 36 Graph Workflows into `agent_soc_manager`
- [x] **Step 1: Port all 36 workflow modules to `agent_soc_manager/workflows/`**
- [x] **Step 2: Add safe ADK fallback imports in `agent_soc_manager/workflows/common.py`**
- [x] **Step 3: Update workflow modules to import from `.common`**

---

### Task 2: Create Workflow Tool Wrappers & Test Suite
- [x] **Step 1: Create `agent_soc_manager/tools/workflow_tools.py` exporting 36 tools**
- [x] **Step 2: Create unit test suite in `tests/test_workflow_tools.py`**
- [x] **Step 3: Run pytest across full test suite (31/31 tests passing)**
- [x] **Step 4: Commit changes to `feat/progressive-mcp-discovery`**
