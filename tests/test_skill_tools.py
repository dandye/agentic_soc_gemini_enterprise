import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_soc_manager.tools.skill_registry import SkillRegistry
from agent_soc_manager.tools.skill_tools import (
    get_progressive_skill_tools,
    global_skill_registry,
    list_available_skills,
    load_persona_with_skills_catalog,
    load_skill,
)


@pytest.fixture
def mock_registry():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        triage_dir = root / "triage" / "malware-triage"
        triage_dir.mkdir(parents=True, exist_ok=True)
        (triage_dir / "SKILL.md").write_text(
            """---
name: malware-triage
description: Rapid assessment of malware alerts.
category: triage
---
# Malware Triage Procedure
Step 1: Check hash.
""",
            encoding="utf-8",
        )

        irps_dir = root / "irps" / "phishing-response"
        irps_dir.mkdir(parents=True, exist_ok=True)
        (irps_dir / "SKILL.md").write_text(
            """---
name: phishing-response
description: End-to-end phishing incident response.
category: irps
---
# Phishing Response
Step 1: Quarantine email.
""",
            encoding="utf-8",
        )

        registry = SkillRegistry(skills_dir=root)
        yield registry


def test_global_skill_registry_instance():
    assert global_skill_registry is not None
    assert isinstance(global_skill_registry, SkillRegistry)


def test_load_skill(mock_registry):
    with patch("agent_soc_manager.tools.skill_tools.global_skill_registry", mock_registry):
        content = load_skill("malware-triage")
        assert "# Malware Triage Procedure" in content
        assert "Step 1: Check hash." in content

        # Normalization lookup
        content_snake = load_skill("malware_triage")
        assert "# Malware Triage Procedure" in content_snake

        missing = load_skill("nonexistent_skill")
        assert "Error: Skill 'nonexistent_skill' not found" in missing


def test_list_available_skills(mock_registry):
    with patch("agent_soc_manager.tools.skill_tools.global_skill_registry", mock_registry):
        # List all skills
        all_skills = list_available_skills()
        assert "### Available Skills (Progressive Disclosure)" in all_skills
        assert "malware-triage" in all_skills
        assert "phishing-response" in all_skills

        # List by category
        triage_skills = list_available_skills("triage")
        assert "malware-triage" in triage_skills
        assert "phishing-response" not in triage_skills

        empty_category = list_available_skills("unknown_cat")
        assert "No skills found in category 'unknown_cat'" in empty_category


def test_load_persona_with_skills_catalog(mock_registry):
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as f:
        f.write("You are a SOC Analyst Tier 1.")
        persona_path = f.name

    try:
        with patch("agent_soc_manager.tools.skill_tools.global_skill_registry", mock_registry):
            combined = load_persona_with_skills_catalog(
                persona_path,
                skill_names=["malware-triage"],
                default_persona_description="Default Analyst",
            )
            assert "You are a SOC Analyst Tier 1." in combined
            assert "### Available Skills (Progressive Disclosure)" in combined
            assert "malware-triage" in combined
            assert "phishing-response" not in combined

            fallback = load_persona_with_skills_catalog(
                "/nonexistent/path/persona.md",
                skill_names=["malware-triage"],
                default_persona_description="Default Analyst Fallback",
            )
            assert "Default Analyst Fallback" in fallback
            assert "malware-triage" in fallback
    finally:
        Path(persona_path).unlink(missing_ok=True)


def test_get_progressive_skill_tools():
    tools = get_progressive_skill_tools()
    tool_names = [t.__name__ for t in tools]
    assert "load_skill" in tool_names
    assert "list_available_skills" in tool_names
