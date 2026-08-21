---
type: "Architecture"
title: "Skills Progressive Disclosure Design Specification"
description: "Architecture and design specification for procedural knowledge progressive disclosure, on-demand skill loading, and dynamic persona catalog enrichment"
resource: "docs/superpowers/specs/2026-08-21-skills-progressive-disclosure-design.md"
timestamp: "2026-08-21T20:45:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-08-21T20:45:00Z"
---

# Design Specification: Skills Progressive Disclosure

## 1. Executive Summary

This specification defines the **Skills Progressive Disclosure Framework** for the Google ADK Multi-Agent Cybersecurity Operations platform.

Static inlining of dozens of complex procedural runbooks into LLM system instructions consumes valuable context window space, increases inference latency, and degrades procedural adherence.

This architecture introduces:
1. **`SkillRegistry`**: Discovers, indexes, normalizes, and manages procedural knowledge parsed from `SKILL.md` frontmatter across `agent_soc_manager/skills/` and `external/adk_runbooks/skills/`.
2. **Procedural Meta-Tools (`load_skill`, `list_available_skills`)**: Allows agents to load full step-by-step procedures, rubrics, and checklists on demand.
3. **Dynamic Persona Enrichment (`load_persona_with_skills_catalog`)**: Automatically appends a compact catalog of relevant skills to the agent prompt.

## 2. Architectural Overview

```
                                  +--------------------------------------------------+
                                  |                LLM Agent Context                 |
                                  |                                                  |
                                  |  * System Prompt: Compact Available Skills List  |
                                  |  * Active Tools:                                 |
                                  |      - load_skill(skill_name)                    |
                                  |      - list_available_skills(category)           |
                                  +------------------------+-------------------------+
                                                           |
                        +----------------------------------+----------------------------------+
                        | (Category Query / Catalog)                                          | (Procedure Lookup)
                        v                                                                     v
        +--------------------------------+                                    +---------------------------------+
        |         SkillRegistry          |                                    |       Skill Content Engine      |
        |  * Discovers & indexes skills  |                                    |  * Reads complete SKILL.md      |
        |    from package and submodules |                                    |  * Serves procedures & rubrics  |
        |  * Dual-key name normalization |                                    |  * Zero upfront context bloat   |
        +---------------+----------------+                                    +----------------+----------------+
                        |                                                                      |
                        +-------------------------------+--------------------------------------+
                                                        |
                                                        v
                        +-------------------------------------------------------------+
                        |                      Indexed Skills                         |
                        |   - Atomic Lookups (Domain, IP, Hash, URL, User)            |
                        |   - Common Operations (Enrichment, Duplicates, SOAR)        |
                        |   - Incident Response Plans (Malware, Phishing, Account)    |
                        |   - Triage, Threat Hunting, Detection Engineering           |
                        +-------------------------------------------------------------+
```

## 3. Detailed Component Architecture

### 3.1 Data Structures & SkillRegistry (`agent_soc_manager/tools/skill_registry.py`)

#### `SkillMetadata`
Dataclass capturing indexed skill attributes:
- `name: str` - Standard skill identifier (e.g. `malware-triage` or `compromised-user-account-response`).
- `description: str` - Concise one-sentence summary for routing (< 200 chars).
- `category: str` - Domain category (`atomic`, `common`, `triage`, `hunting`, `investigation`, `irps`, `detection`, `reporting`).
- `path: Path` - Absolute path to `SKILL.md` on disk.
- `version: str` - Semantic version string.

#### `SkillRegistry`
Core registry providing:
- `scan_skills() -> dict[str, SkillMetadata]`: Recursively scans skills directories and indexes metadata.
- `reload() -> dict[str, SkillMetadata]`: Dynamically re-scans disk for updated skills.
- `get_skill(name: str) -> SkillMetadata | None`: Retrieves metadata with `kebab-case` and `snake_case` normalization.
- `get_skill_content(name: str) -> str`: Reads and returns the complete markdown content.
- `get_skill_catalog(skill_names: list[str] | None) -> str`: Generates a compact Markdown list for system prompt injection.
- `list_skills_by_category(category: str) -> list[SkillMetadata]`: Filters skills by category.

### 3.2 Progressive Skill Meta-Tools (`agent_soc_manager/tools/skill_tools.py`)

1. **`load_skill(skill_name: str) -> str`**
   - Retrieves the complete markdown instructions, procedures, and rubrics for a specified skill.

2. **`list_available_skills(category: str = "") -> str`**
   - Lists available progressive disclosure skills, optionally filtered by category.

3. **`load_persona_with_skills_catalog(...) -> str`**
   - Reads persona description and appends the catalog of available skills for the agent.
