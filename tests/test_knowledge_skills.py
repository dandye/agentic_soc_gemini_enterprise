"""Unit tests for domain-specific skills in the KnowledgeAgent subsystem."""

import os
import pathlib
import pytest
import yaml

from google.adk.features import FeatureName, override_feature_enabled
from google.adk.skills import Skill, load_skill_from_dir

from agent_knowledge.skills import (
    SKILLS_DIR,
    SKILL_NAMES,
    load_all_domain_skills,
    load_domain_skill,
)

# Ensure snake_case skill naming is active for test execution
override_feature_enabled(FeatureName.SNAKE_CASE_SKILL_NAME, True)


EXPECTED_SKILLS = [
    "cypher_graph_navigation",
    "asset_criticality_evaluation",
    "incident_memory_correlation",
    "mitre_ttp_mapping",
]


@pytest.mark.parametrize("skill_name", EXPECTED_SKILLS)
def test_skill_directory_and_skill_md_exist(skill_name: str):
    """Verify that each domain skill directory exists and contains a readable SKILL.md file."""
    skill_dir = SKILLS_DIR / skill_name
    assert skill_dir.is_dir(), f"Skill directory {skill_dir} does not exist."
    skill_md = skill_dir / "SKILL.md"
    assert skill_md.is_file(), f"SKILL.md does not exist in {skill_dir}."


@pytest.mark.parametrize("skill_name", EXPECTED_SKILLS)
def test_skill_yaml_frontmatter_validity(skill_name: str):
    """Verify that SKILL.md contains valid YAML frontmatter with matching name and non-empty description."""
    skill_md = SKILLS_DIR / skill_name / "SKILL.md"
    content = skill_md.read_text(encoding="utf-8")

    assert content.startswith("---"), f"{skill_md} must start with '---'"
    parts = content.split("---", 2)
    assert len(parts) >= 3, f"{skill_md} frontmatter is not closed with '---'"

    frontmatter = yaml.safe_load(parts[1])
    assert isinstance(frontmatter, dict), "Frontmatter must be a YAML mapping"
    assert "name" in frontmatter, "Frontmatter must contain 'name'"
    assert "description" in frontmatter, "Frontmatter must contain 'description'"
    assert frontmatter["name"] == skill_name, (
        f"Frontmatter name '{frontmatter['name']}' must match directory name '{skill_name}'"
    )
    assert len(frontmatter["description"].strip()) > 10, "Description must be substantive"
    assert len(parts[2].strip()) > 100, "Skill instructions body must not be empty"


@pytest.mark.parametrize("skill_name", EXPECTED_SKILLS)
def test_load_skill_from_dir_direct(skill_name: str):
    """Verify that ADK load_skill_from_dir loads each skill into a Skill object."""
    skill_dir = SKILLS_DIR / skill_name
    skill = load_skill_from_dir(skill_dir)

    assert isinstance(skill, Skill)
    assert skill.frontmatter.name == skill_name
    assert skill.frontmatter.description is not None
    assert len(skill.instructions) > 0
    assert skill_name in skill.frontmatter.name


def test_load_all_domain_skills():
    """Verify load_all_domain_skills returns all 4 domain skills properly loaded."""
    skills = load_all_domain_skills()
    assert len(skills) == 4
    for expected in EXPECTED_SKILLS:
        assert expected in skills
        skill = skills[expected]
        assert isinstance(skill, Skill)
        assert skill.frontmatter.name == expected


def test_load_domain_skill_by_name():
    """Verify load_domain_skill loads individual skill by name."""
    skill = load_domain_skill("cypher_graph_navigation")
    assert skill.frontmatter.name == "cypher_graph_navigation"
    assert "Cypher Graph Navigation" in skill.instructions


def test_load_domain_skill_not_found():
    """Verify load_domain_skill raises FileNotFoundError for non-existent skill."""
    with pytest.raises(FileNotFoundError):
        load_domain_skill("non_existent_skill_xyz")


def test_cypher_graph_navigation_content():
    """Verify cypher_graph_navigation skill covers required graph heuristics, templates, and safety."""
    skill = load_domain_skill("cypher_graph_navigation")
    instructions = skill.instructions

    # Traversal heuristics
    assert "Entity Neighborhood" in instructions or "entity_neighborhood" in instructions
    assert "Lateral Movement" in instructions or "lateral_movement" in instructions
    assert "Credential Blast Radius" in instructions or "credential_blast_radius" in instructions
    assert "DomainController" in instructions or "Tier 0" in instructions

    # Safe Cypher patterns and constraints
    assert "shortestPath" in instructions
    assert "LIMIT" in instructions
    assert "Read-Only" in instructions or "read-only" in instructions.lower()
    assert "CREATE" in instructions and "DELETE" in instructions and "DROP" in instructions
    assert "Hop Limit" in instructions or "hop_count" in instructions or "max_hops" in instructions


def test_asset_criticality_evaluation_content():
    """Verify asset_criticality_evaluation skill covers Tier 0, 1, 2 classifications and blast radius."""
    skill = load_domain_skill("asset_criticality_evaluation")
    instructions = skill.instructions

    # Criticality tiers
    assert "Tier 0" in instructions
    assert "Tier 1" in instructions
    assert "Tier 2" in instructions
    assert "Crown Jewels" in instructions or "Domain Controllers" in instructions
    assert "CI/CD" in instructions or "Core Infrastructure" in instructions
    assert "Workstations" in instructions or "End-User" in instructions

    # Blast radius assessment
    assert "Blast Radius" in instructions or "blast radius" in instructions.lower()
    assert "Privilege" in instructions or "Cached Credentials" in instructions
    assert "query_asset_catalog" in instructions


def test_incident_memory_correlation_content():
    """Verify incident_memory_correlation skill covers tagging taxonomy, memory correlation, and tools."""
    skill = load_domain_skill("incident_memory_correlation")
    instructions = skill.instructions

    # Tag taxonomy
    expected_tags = [
        "credential_spray",
        "lateral_movement",
        "persistence",
        "data_exfiltration",
        "c2",
        "containment",
        "general",
    ]
    for tag in expected_tags:
        assert tag in instructions, f"Tag '{tag}' should be present in memory correlation skill"

    # Tool integration & correlation loop
    assert "add_investigation_note" in instructions
    assert "query_investigation_memory" in instructions
    assert "Hypothesis" in instructions or "hypothesis" in instructions.lower()


def test_mitre_ttp_mapping_content():
    """Verify mitre_ttp_mapping skill covers Enterprise ATT&CK matrix tactics, techniques, and CTI RAG."""
    skill = load_domain_skill("mitre_ttp_mapping")
    instructions = skill.instructions

    # Tactics coverage
    assert "Initial Access" in instructions or "TA0001" in instructions
    assert "Execution" in instructions or "TA0002" in instructions
    assert "Persistence" in instructions or "TA0003" in instructions
    assert "Privilege Escalation" in instructions or "TA0004" in instructions
    assert "Defense Evasion" in instructions or "TA0005" in instructions
    assert "Credential Access" in instructions or "TA0006" in instructions
    assert "Discovery" in instructions or "TA0007" in instructions
    assert "Lateral Movement" in instructions or "TA0008" in instructions
    assert "Collection" in instructions or "TA0009" in instructions
    assert "Command and Control" in instructions or "TA0011" in instructions
    assert "Exfiltration" in instructions or "TA0010" in instructions
    assert "Impact" in instructions or "TA0040" in instructions

    # Common technique references
    assert "T1078" in instructions
    assert "T1021" in instructions
    assert "T1003" in instructions

    # RAG / Playbook integration
    assert "retrieve_enterprise_docs" in instructions or "Playbook" in instructions
