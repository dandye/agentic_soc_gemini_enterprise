# Implementation Plan: Configurable Gemini Model Versions

This plan outlines the changes required to make all Gemini model versions fully configurable via the `.env` file, with sensible defaults documented in `.env.example`.

## 1. Environment Variables Design

We will introduce the following environment variables to configuration:

| Environment Variable | Default Value | Target Files / Roles |
|----------------------|---------------|----------------------|
| `ORCHESTRATOR_MODEL` | `gemini-2.5-pro` | Main orchestrator in `soc_agent/agent.py` and `soc_agent_flash/agent.py` |
| `CTI_RESEARCHER_MODEL` | `gemini-2.5-flash` | CTI sub-agent/persona in `soc_agent/agent.py` and `soc_agent_cti/agent.py` |
| `TIER1_ANALYST_MODEL` | `gemini-2.5-flash` | Tier 1 sub-agent/persona in `soc_agent/agent.py` and `soc_agent_tier1/agent.py` |
| `A2UI_RENDERER_MODEL` | `gemini-2.5-flash` | GenAI client in `soc_agent/tools/a2ui_renderer.py` |

## 2. Planned Changes

### 2.1. `.env.example`
- Add a new section `Model Version Configuration` documenting these variables, their purposes, and defaults.

### 2.2. `soc_agent/agent.py`
- Load `ORCHESTRATOR_MODEL`, `CTI_RESEARCHER_MODEL`, and `TIER1_ANALYST_MODEL` from environment variables.
- Fallback to their respective default values if not defined.
- Replace inline model strings with the loaded variables:
  - Line 1054 (cti subagent): `model=CTI_RESEARCHER_MODEL`
  - Line 1181 (tier1 subagent): `model=TIER1_ANALYST_MODEL`
  - Line 1505 (orchestrator): `model=ORCHESTRATOR_MODEL`

### 2.3. `soc_agent_flash/agent.py`
- Load `ORCHESTRATOR_MODEL` from environment variables.
- Fallback to `gemini-3.0-flash` (retaining current default configuration).
- Replace model assignment on line 299.

### 2.4. `soc_agent_cti/agent.py`
- Load `CTI_RESEARCHER_MODEL` from environment variables.
- Fallback to `gemini-2.5-flash`.
- Replace model assignment on line 609.

### 2.5. `soc_agent_tier1/agent.py`
- Load `TIER1_ANALYST_MODEL` from environment variables.
- Fallback to `gemini-2.5-flash`.
- Replace model assignment on line 576.

### 2.6. `soc_agent/tools/a2ui_renderer.py`
- Load `A2UI_RENDERER_MODEL` from environment variables.
- Fallback to `gemini-3-flash-preview` (retaining current default configuration).
- Replace model assignment on line 49.

## 3. Verification Plan

To ensure no syntax errors or regressions are introduced, we will:
1. Run a Python dry run script to import `create_agent` from each modified module.
2. Programmatically assert that setting env vars (e.g., `ORCHESTRATOR_MODEL="gemini-2.5-flash"`) changes the instantiated Agent's model name correctly.
