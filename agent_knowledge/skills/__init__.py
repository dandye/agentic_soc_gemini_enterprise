"""Domain-specific skills for the KnowledgeAgent subsystem."""

import os
from pathlib import Path
from typing import Dict, List

from google.adk.features import FeatureName, override_feature_enabled
from google.adk.skills import Skill, load_skill_from_dir

# Enable snake_case skill names support in ADK
override_feature_enabled(FeatureName.SNAKE_CASE_SKILL_NAME, True)

SKILLS_DIR = Path(__file__).parent.resolve()

SKILL_NAMES: List[str] = [
    "cypher_graph_navigation",
    "asset_criticality_evaluation",
    "incident_memory_correlation",
    "mitre_ttp_mapping",
]


def load_domain_skill(skill_name: str) -> Skill:
    """Load a specific domain skill by name."""
    skill_path = SKILLS_DIR / skill_name
    if not skill_path.is_dir():
        raise FileNotFoundError(f"Skill '{skill_name}' not found in {SKILLS_DIR}")
    return load_skill_from_dir(skill_path)


def load_all_domain_skills() -> Dict[str, Skill]:
    """Load all domain-specific skills for the knowledge agent."""
    return {name: load_domain_skill(name) for name in SKILL_NAMES}


__all__ = [
    "SKILLS_DIR",
    "SKILL_NAMES",
    "load_all_domain_skills",
    "load_domain_skill",
]
