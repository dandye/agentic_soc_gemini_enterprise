import tempfile
from pathlib import Path

import pytest

from agent_soc_manager.tools.skill_registry import SkillRegistry


@pytest.fixture
def temp_skills_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        # Create category 1: triage
        triage_dir = root / "triage" / "malware-triage"
        triage_dir.mkdir(parents=True, exist_ok=True)
        (triage_dir / "SKILL.md").write_text(
            """---
name: malware-triage
description: Rapid assessment of malware alerts.
category: triage
version: 1.0.0
---
# Malware Triage Procedure
1. Identify infected host.
2. Quarantine host.
""",
            encoding="utf-8",
        )

        # Create category 2: investigation
        invest_dir = root / "investigation" / "ioc_enrichment"
        invest_dir.mkdir(parents=True, exist_ok=True)
        (invest_dir / "SKILL.md").write_text(
            """---
name: ioc_enrichment
description: Enrich indicators with threat intel.
category: investigation
version: 1.0.0
---
# IOC Enrichment Procedure
1. Lookup IP/Domain in GTI.
""",
            encoding="utf-8",
        )

        # Create skill without frontmatter (fallback)
        fallback_dir = root / "common" / "simple-report"
        fallback_dir.mkdir(parents=True, exist_ok=True)
        (fallback_dir / "SKILL.md").write_text(
            """# Simple Report
Generates a markdown report.
""",
            encoding="utf-8",
        )

        yield root


def test_skill_registry_scanning_and_normalization(temp_skills_dir):
    registry = SkillRegistry(skills_dir=temp_skills_dir)

    # Exact name lookup
    skill = registry.get_skill("malware-triage")
    assert skill is not None
    assert skill.name == "malware-triage"
    assert skill.category == "triage"
    assert skill.description == "Rapid assessment of malware alerts."

    # Normalization lookup (snake_case from kebab-case)
    skill_snake = registry.get_skill("malware_triage")
    assert skill_snake is not None
    assert skill_snake.name == "malware-triage"

    # Normalization lookup (kebab-case from snake_case)
    skill_kebab = registry.get_skill("ioc-enrichment")
    assert skill_kebab is not None
    assert skill_kebab.name == "ioc_enrichment"

    # Non-existent skill
    assert registry.get_skill("nonexistent") is None
    assert registry.get_skill("") is None


def test_skill_registry_fallback_frontmatter(temp_skills_dir):
    registry = SkillRegistry(skills_dir=temp_skills_dir)
    skill = registry.get_skill("simple-report")
    assert skill is not None
    assert skill.name == "simple-report"
    assert skill.category == "common"


def test_skill_registry_get_content(temp_skills_dir):
    registry = SkillRegistry(skills_dir=temp_skills_dir)
    content = registry.get_skill_content("malware-triage")
    assert "# Malware Triage Procedure" in content
    assert "Quarantine host." in content

    missing = registry.get_skill_content("missing_skill")
    assert "Error: Skill 'missing_skill' not found" in missing


def test_skill_registry_catalog_generation(temp_skills_dir):
    registry = SkillRegistry(skills_dir=temp_skills_dir)
    catalog = registry.get_skill_catalog()
    assert "### Available Skills (Progressive Disclosure)" in catalog
    assert "malware-triage" in catalog
    assert "ioc_enrichment" in catalog

    filtered_catalog = registry.get_skill_catalog(skill_names=["malware-triage"])
    assert "malware-triage" in filtered_catalog
    assert "ioc_enrichment" not in filtered_catalog

    empty_registry = SkillRegistry(skills_dir=Path(tempfile.mkdtemp()))
    assert empty_registry.get_skill_catalog() == ""


def test_skill_registry_list_by_category(temp_skills_dir):
    registry = SkillRegistry(skills_dir=temp_skills_dir)
    triage_skills = registry.list_skills_by_category("triage")
    assert len(triage_skills) == 1
    assert triage_skills[0].name == "malware-triage"

    investigation_skills = registry.list_skills_by_category("investigation")
    assert len(investigation_skills) == 1
    assert investigation_skills[0].name == "ioc_enrichment"

    empty_category = registry.list_skills_by_category("nonexistent_category")
    assert empty_category == []
