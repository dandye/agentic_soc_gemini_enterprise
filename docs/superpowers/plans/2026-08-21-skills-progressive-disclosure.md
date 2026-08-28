---
type: "Documentation"
title: "Skills Progressive Disclosure Implementation Plan"
description: "Implementation plan for integrating SkillRegistry, procedural skill retrieval tools, and progressive disclosure catalogs across the SOC multi-agent architecture"
resource: "docs/superpowers/plans/2026-08-21-skills-progressive-disclosure.md"
timestamp: "2026-08-21T20:45:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-08-21T20:45:00Z"
---

# Skills Progressive Disclosure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Skills Progressive Disclosure in the Agentic SOC repository, providing centralized indexing, on-demand procedure loading (`load_skill`), category discovery (`list_available_skills`), and dynamic persona prompt enrichment (`load_persona_with_skills_catalog`).

**Architecture:** Build a centralized `SkillRegistry` engine that indexes `SKILL.md` files from both local package skills (`agent_soc_manager/skills/`) and submodule skills (`external/adk_runbooks/skills/`), and expose lightweight procedural meta-tools to the Orchestrator and Tier 1 analyst sub-agent.

**Tech Stack:** Python 3.10+, PyYAML, Google ADK, pytest.

**Spec:** `docs/superpowers/specs/2026-08-21-skills-progressive-disclosure-design.md`

## Global Constraints
- Never use emojis anywhere in code, comments, commit messages, or documentation.
- All skills must support dual-key normalization (`kebab-case` and `snake_case`).
- Preserve 100% backwards compatibility for existing ADK SkillToolset and custom tools.
- All unit and integration tests must pass cleanly.
- No hardcoded API secrets or credentials.

---

### Task 1: Centralized Skill Registry Engine (`SkillRegistry`)

**Files:**
- Create: `agent_soc_manager/tools/skill_registry.py`
- Test: `tests/test_skill_registry.py`

**Interfaces:**
- Produces: `SkillMetadata`, `SkillRegistry`, `scan_skills`, `reload`, `get_skill`, `get_skill_content`, `get_skill_catalog`, `list_skills_by_category`.

- [ ] **Step 1: Write unit tests for `SkillRegistry`**
  - Create `tests/test_skill_registry.py` covering skill scanning, YAML frontmatter extraction, fallback parsing, casing normalization, category filtering, catalog generation, and missing skill handling.
- [ ] **Step 2: Implement `SkillRegistry` in `agent_soc_manager/tools/skill_registry.py`**
  - Define `SkillMetadata` dataclass (`name`, `description`, `category`, `path`, `version`).
  - Implement recursive directory scanning, YAML parsing, normalization, content retrieval, and markdown catalog generation.
- [ ] **Step 3: Run pytest to verify pass**
  - Run: `pytest tests/test_skill_registry.py -v`
- [ ] **Step 4: Commit Task 1**
  - `git add agent_soc_manager/tools/skill_registry.py tests/test_skill_registry.py && git commit -m "feat(skills): implement centralized SkillRegistry engine"`

---

### Task 2: Progressive Skill Meta-Tools (`load_skill`, `list_available_skills`, `load_persona_with_skills_catalog`)

**Files:**
- Create: `agent_soc_manager/tools/skill_tools.py`
- Test: `tests/test_skill_tools.py`

**Interfaces:**
- Consumes: `SkillRegistry` from `agent_soc_manager/tools/skill_registry.py`
- Produces: `global_skill_registry`, `load_skill(skill_name)`, `list_available_skills(category)`, `load_persona_with_skills_catalog(persona_file_path, skill_names, default_persona_description)`, `get_progressive_skill_tools()`.

- [ ] **Step 1: Write unit tests for skill meta-tools**
  - Create `tests/test_skill_tools.py` testing `load_skill`, `list_available_skills`, `load_persona_with_skills_catalog`, and error boundaries.
- [ ] **Step 2: Implement meta-tools in `agent_soc_manager/tools/skill_tools.py`**
  - Implement `load_skill(skill_name: str) -> str`.
  - Implement `list_available_skills(category: str = "") -> str`.
  - Implement `load_persona_with_skills_catalog(persona_file_path, skill_names, default_description) -> str`.
  - Implement `get_progressive_skill_tools() -> list[Callable]`.
- [ ] **Step 3: Run pytest to verify pass**
  - Run: `pytest tests/test_skill_tools.py -v`
- [ ] **Step 4: Commit Task 2**
  - `git add agent_soc_manager/tools/skill_tools.py tests/test_skill_tools.py && git commit -m "feat(tools): add progressive skill disclosure meta-tools"`

---

### Task 3: Agent Integration & System Instruction Directives

**Files:**
- Modify: `agent_soc_manager/agent.py`
- Modify: `agent_soc_manager/prompts/orchestrator_instructions.md`
- Modify: `agent_soc_manager/prompts/tier1_analyst_instructions.md`

**Interfaces:**
- Consumes: `get_progressive_skill_tools()`, `load_persona_with_skills_catalog`
- Produces: Updated `tier1_tools` and `orchestrator_tools` with progressive skill loading tools and dynamic persona descriptions.

- [ ] **Step 1: Wire skill meta-tools in `agent_soc_manager/agent.py`**
  - Import `get_progressive_skill_tools` and `load_persona_with_skills_catalog`.
  - Extend `tier1_tools` and `orchestrator_tools` with `get_progressive_skill_tools()`.
- [ ] **Step 2: Update agent persona descriptions & prompts**
  - Enrich `TIER1_PERSONA` and orchestrator descriptions with relevant skill catalogs.
  - Update `orchestrator_instructions.md` and `tier1_analyst_instructions.md` with explicit `load_skill(skill_name)` guidance.
- [ ] **Step 3: Run full pytest suite**
  - Run: `pytest tests/ -v`
- [ ] **Step 4: Commit Task 3**
  - `git add agent_soc_manager/agent.py agent_soc_manager/prompts/ && git commit -m "feat(agent): integrate progressive skill disclosure into orchestrator and tier 1 analyst"`

---

### Task 4: Design Documentation & Verification

**Files:**
- Create: `docs/superpowers/specs/2026-08-21-skills-progressive-disclosure-design.md`
- Test: All tests under `tests/`

- [ ] **Step 1: Document architectural design specification**
  - Save `docs/superpowers/specs/2026-08-21-skills-progressive-disclosure-design.md` with OKF frontmatter.
- [ ] **Step 2: Run all unit tests and linter checks**
  - Run `pytest tests/ -v` and `ruff check`
- [ ] **Step 3: Commit Task 4**
  - `git add docs/ && git commit -m "docs(specs): add skills progressive disclosure design specification"`
