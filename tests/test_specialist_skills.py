from pathlib import Path


def test_specialist_agents_skill_integration():
    repo_root = Path(__file__).resolve().parent.parent

    # 1. CTI Researcher
    cti_agent = (repo_root / "agent_a2a_cti_researcher" / "agent.py").read_text(encoding="utf-8")
    assert "from agent_soc_manager.tools.skill_tools import" in cti_agent
    assert "get_progressive_skill_tools" in cti_agent
    assert "load_persona_with_skills_catalog" in cti_agent
    assert "tools.extend(get_progressive_skill_tools())" in cti_agent
    assert "description=cti_persona" in cti_agent
    assert "load_skill(skill_name)" in cti_agent

    # 2. Detection Engineer
    det_agent = (repo_root / "agent_a2a_detection_engineer" / "agent.py").read_text(encoding="utf-8")
    assert "from agent_soc_manager.tools.skill_tools import" in det_agent
    assert "get_progressive_skill_tools" in det_agent
    assert "load_persona_with_skills_catalog" in det_agent
    assert "tools.extend(get_progressive_skill_tools())" in det_agent
    assert "description=det_persona" in det_agent
    assert "load_skill(skill_name)" in det_agent

    # 3. Threat Hunter
    hunter_agent = (repo_root / "agent_a2a_threat_hunter" / "agent.py").read_text(encoding="utf-8")
    assert "from agent_soc_manager.tools.skill_tools import" in hunter_agent
    assert "get_progressive_skill_tools" in hunter_agent
    assert "load_persona_with_skills_catalog" in hunter_agent
    assert "tools.extend(get_progressive_skill_tools())" in hunter_agent
    assert "description=hunter_persona" in hunter_agent
    assert "load_skill(skill_name)" in hunter_agent

    # 4. Tier 2 Responder
    tier2_agent = (repo_root / "agent_a2a_tier2" / "agent.py").read_text(encoding="utf-8")
    assert "from agent_soc_manager.tools.skill_tools import" in tier2_agent
    assert "get_progressive_skill_tools" in tier2_agent
    assert "load_persona_with_skills_catalog" in tier2_agent
    assert "tools.extend(get_progressive_skill_tools())" in tier2_agent
    assert "description=tier2_persona" in tier2_agent
    assert "load_skill(skill_name)" in tier2_agent
