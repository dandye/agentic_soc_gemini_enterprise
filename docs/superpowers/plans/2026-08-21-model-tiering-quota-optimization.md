---
type: "Documentation"
title: "Model Tiering & Quota Optimization Implementation Plan"
description: "Execution plan for configuring tiered LLM models across SOC orchestrator, specialist agents, and procedural sub-agents to optimize throughput and quota allocation"
resource: "docs/superpowers/plans/2026-08-21-model-tiering-quota-optimization.md"
timestamp: "2026-08-21T20:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-08-21T20:50:00Z"
---

# Model Tiering & Quota Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Configure optimized multi-tier model defaults across all SOC agents to balance critical reasoning against high-throughput procedural tasks, preventing 429 quota exhaustion while minimizing latency.

**Architecture:**
- Orchestrator: `gemini-3.7-flash` (or `gemini-3.1-pro-preview` via env)
- Domain Specialists (CTI, Detection Engineer, Threat Hunter, Tier 2 Responder): `gemini-3.7-flash`
- Tier 1 Analyst: `gemini-2.5-flash-lite`

**Tech Stack:** Python 3.10+, Google ADK, Vertex AI Reasoning Engine.

**Spec:** `docs/superpowers/specs/2026-08-21-model-tiering-quota-optimization.md`

## Global Constraints
- Never use emojis anywhere in code, comments, commit messages, or documentation.
- Maintain environment variable override compatibility for all model variables.
- Ensure all 22 existing unit tests continue to pass.

---

### Task 1: Update Model Tier Defaults Across Agent Modules

**Files:**
- Modify: `agent_soc_manager/agent.py`
- Modify: `agent_a2a_cti_researcher/agent.py`
- Modify: `agent_a2a_detection_engineer/agent.py`
- Modify: `agent_a2a_threat_hunter/agent.py`
- Modify: `agent_a2a_tier2/agent.py`

- [ ] **Step 1: Update `agent_soc_manager/agent.py` model defaults**
  - Set `ORCHESTRATOR_MODEL = os.environ.get("ORCHESTRATOR_MODEL", "gemini-3.7-flash")`
  - Set `TIER1_ANALYST_MODEL = os.environ.get("TIER1_ANALYST_MODEL", "gemini-2.5-flash-lite")`
  - Set `CTI_RESEARCHER_MODEL = os.environ.get("CTI_RESEARCHER_MODEL", "gemini-3.7-flash")`
- [ ] **Step 2: Update remote specialist model defaults**
  - In `agent_a2a_cti_researcher/agent.py`: `CTI_RESEARCHER_MODEL = os.environ.get("CTI_RESEARCHER_MODEL", "gemini-3.7-flash")`
  - In `agent_a2a_detection_engineer/agent.py`: `DETECTION_ENGINEER_MODEL = os.environ.get("DETECTION_ENGINEER_MODEL", "gemini-3.7-flash")`
  - In `agent_a2a_threat_hunter/agent.py`: `THREAT_HUNTER_MODEL = os.environ.get("THREAT_HUNTER_MODEL", "gemini-3.7-flash")`
  - In `agent_a2a_tier2/agent.py`: `TIER2_RESPONDER_MODEL = os.environ.get("TIER2_RESPONDER_MODEL", "gemini-3.7-flash")`
- [ ] **Step 3: Run pytest to verify no regression**
  - Run: `pytest tests/ -v`
- [ ] **Step 4: Commit Task 1**
  - `git commit -m "feat(models): configure tiered model distribution across orchestrator and specialists"`

---

### Task 2: Environment Configuration & Documentation

**Files:**
- Modify: `.env.example`
- Create: `tests/test_model_tiering.py`

- [ ] **Step 1: Update `.env.example` documentation**
  - Clearly document Tier 1 (Critical Reasoning), Tier 2 (Specialists), and Tier 3 (Procedural Triage) model settings.
- [ ] **Step 2: Add unit tests in `tests/test_model_tiering.py`**
  - Verify model environment variable resolution and defaults across agent modules.
- [ ] **Step 3: Run full test suite**
  - Run `pytest tests/ -v`
- [ ] **Step 4: Commit Task 2**
  - `git commit -m "docs(env): update model tiering environment documentation and verification tests"`
