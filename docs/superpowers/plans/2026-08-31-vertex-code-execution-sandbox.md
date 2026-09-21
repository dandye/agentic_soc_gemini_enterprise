# Vertex AI Code Execution & Threat Hunter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate Vertex AI Code Execution Sandboxes (`AgentEngineSandboxCodeExecutor` / `VertexAiCodeExecutor`) into the Agentic SOC repository and empower the Threat Hunter specialist (`agent_a2a_threat_hunter`) with sandboxed Python data analytics for large-scale telemetry processing.

**Architecture:** A unified `CodeExecutorFactory` configures the appropriate ADK `BaseCodeExecutor` implementation based on deployment runtime (Agent Engine Sandbox in cloud, BuiltIn for API mode, UnsafeLocal for unit tests). The Threat Hunter agent binds this executor alongside existing MCP security toolsets and incorporates pre-built statistical analysis routines (entropy, beaconing jitter, timeline alignment).

**Tech Stack:** Google Agent Development Kit (ADK), Vertex AI Agent Engine (`vertexai.Client.agent_engines.sandboxes`), Python 3.11+, pytest, pandas, numpy, Google GenAI SDK.

**Spec:** [docs/superpowers/specs/2026-08-31-vertex-code-execution-sandbox-design.md](file:///usr/local/google/home/dandye/Projects/agentic_soc_agentspace__worktrees/feat-vertex-code-execution-sandbox/docs/superpowers/specs/2026-08-31-vertex-code-execution-sandbox-design.md)

## Global Constraints
- Target workspace: `Projects/agentic_soc_agentspace__worktrees/feat-vertex-code-execution-sandbox/`
- Target branch: `feat/vertex-code-execution-sandbox`
- Python version floor: 3.11+
- Follow project architectural convention of self-contained agent files while leveraging clean shared factory patterns where appropriate.
- Strict Test-Driven Development (TDD): Write failing test, verify RED, implement minimal code, verify GREEN.

---

### Task 1: Code Executor Factory & Standalone Test Agent (Phase 1 Foundation)

**Files:**
- Create: `installation_scripts/code_executor_factory.py`
- Create: `test_agents/soc_code_analysis_agent/agent.py`
- Test: `tests/test_code_execution_unit.py`

**Interfaces:**
- Produces: `get_code_executor(executor_type: str = "auto", ...) -> BaseCodeExecutor` in `installation_scripts/code_executor_factory.py`
- Produces: `root_agent: Agent` in `test_agents/soc_code_analysis_agent/agent.py`

- [ ] **Step 1: Write failing unit test for CodeExecutorFactory and test agent**
- [ ] **Step 2: Run test to verify it fails (RED)**
- [ ] **Step 3: Implement CodeExecutorFactory supporting `AgentEngineSandboxCodeExecutor`, `VertexAiCodeExecutor`, and `BuiltInCodeExecutor`**
- [ ] **Step 4: Implement standalone `soc_code_analysis_agent` with attached code executor**
- [ ] **Step 5: Run tests and verify all pass (GREEN)**
- [ ] **Step 6: Commit changes**

---

### Task 2: Threat Hunter Sandbox Integration & Analytics Prompting

**Files:**
- Modify: `agent_a2a_threat_hunter/agent.py`
- Test: `tests/test_threat_hunter_code_exec.py`

**Interfaces:**
- Consumes: `get_code_executor` from `installation_scripts.code_executor_factory`
- Produces: `threat_hunter_agent` with bound `code_executor` and enhanced hunting system instructions.

- [ ] **Step 1: Write failing test for Threat Hunter Code Execution integration**
- [ ] **Step 2: Run test to verify it fails (RED)**
- [ ] **Step 3: Update `agent_a2a_threat_hunter/agent.py` to bind code executor and include hunting Python recipes in instructions**
- [ ] **Step 4: Run tests and verify all pass (GREEN)**
- [ ] **Step 5: Commit changes**

---

### Task 3: Threat Hunting Evaluation Scenarios & Baseline Verification

**Files:**
- Create: `evalsets/threat_hunter_code_analytics.evalset.json`
- Test: Verification via `python manage.py eval run` or ADK eval runner

- [ ] **Step 1: Create evaluation dataset containing DGA entropy and C2 beaconing analysis cases**
- [ ] **Step 2: Run evaluation test and verify results**
- [ ] **Step 3: Document benchmark metrics**
- [ ] **Step 4: Commit changes**
