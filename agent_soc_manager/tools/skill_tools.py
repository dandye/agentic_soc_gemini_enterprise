"""Progressive Skill Disclosure and Procedure Loading Meta-Tools.

Provides runtime tools for on-demand procedure loading, skill catalog querying,
and persona prompt enrichment without upfront prompt context bloat.
"""

import logging
from collections.abc import Callable
from pathlib import Path

from .skill_registry import SkillRegistry


logger = logging.getLogger(__name__)

# Global singleton Skill registry
global_skill_registry = SkillRegistry()


def load_skill(skill_name: str) -> str:
    """Loads the complete markdown instructions, procedures, and rubrics for a specified skill.

    Use this tool when you need step-by-step procedures, execution checklists,
    or validation rubrics to perform a security investigation, threat hunt, alert triage,
    or incident response task.

    Args:
        skill_name: The name or identifier of the skill to load (e.g. 'malware-triage',
                    'compromised-user-account-response', 'basic-ioc-enrichment').

    Returns:
        str: The complete markdown content of the requested skill, or an error message if not found.
    """
    return global_skill_registry.get_skill_content(skill_name)


def list_available_skills(category: str = "") -> str:
    """Lists available progressive disclosure skills, optionally filtered by category.

    Use this tool to discover available security skills and capabilities that you can load
    on-demand using `load_skill`.

    Args:
        category: Optional category name to filter skills (e.g. 'triage', 'hunting',
                  'investigation', 'irps', 'detection', 'common', 'atomic'). If empty,
                  all available skills are listed.

    Returns:
        str: Formatted list of matching skills with their descriptions.
    """
    if category:
        skills = global_skill_registry.list_skills_by_category(category)
        if not skills:
            return f"No skills found in category '{category}'."
        lines = [f"### Available Skills in '{category}' (Progressive Disclosure)\n"]
        for s in skills:
            lines.append(f"- **`{s.name}`**: {s.description}")
        return "\n".join(lines)
    else:
        catalog = global_skill_registry.get_skill_catalog()
        return catalog if catalog else "No skills registered."


def load_persona_with_skills_catalog(
    persona_file_path: str,
    skill_names: list[str] | None = None,
    default_persona_description: str = "Default persona description.",
) -> str:
    """Loads persona description and appends progressive disclosure skill catalog.

    Reads the persona markdown file and appends the catalog of available skills
    so the agent is aware of what skills it can dynamically load during execution.

    Args:
        persona_file_path: Path to the persona markdown file.
        skill_names: Optional list of skill names allowed/relevant for this agent.
                     If None, includes all registered skills.
        default_persona_description: Fallback text if persona file is not found.

    Returns:
        str: The combined persona description with appended skills catalog.
    """
    persona_description = ""
    try:
        p_path = Path(persona_file_path)
        if p_path.exists():
            persona_description = p_path.read_text(encoding="utf-8")
        else:
            persona_description = default_persona_description
    except Exception:
        persona_description = default_persona_description

    catalog = global_skill_registry.get_skill_catalog(skill_names)
    if catalog:
        persona_description += "\n\n" + catalog

    return persona_description


def get_progressive_skill_tools() -> list[Callable]:
    """Returns the list of progressive skill meta-tools for agent registration."""
    return [load_skill, list_available_skills]
