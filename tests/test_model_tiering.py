import os
import re
from pathlib import Path
from unittest.mock import patch
import pytest


def test_agent_model_defaults_in_source_code():
    # Verify that code defaults in each agent.py match the Model Tiering specification
    repo_root = Path(__file__).resolve().parent.parent

    # 1. agent_soc_manager/agent.py
    mgr_agent = (repo_root / "agent_soc_manager" / "agent.py").read_text(encoding="utf-8")
    assert 'ORCHESTRATOR_MODEL = os.environ.get("ORCHESTRATOR_MODEL", "gemini-3.7-flash")' in mgr_agent
    assert 'TIER1_ANALYST_MODEL = os.environ.get("TIER1_ANALYST_MODEL", "gemini-2.5-flash-lite")' in mgr_agent
    assert 'CTI_RESEARCHER_MODEL = os.environ.get("CTI_RESEARCHER_MODEL", "gemini-3.7-flash")' in mgr_agent

    # 2. agent_a2a_cti_researcher/agent.py
    cti_agent = (repo_root / "agent_a2a_cti_researcher" / "agent.py").read_text(encoding="utf-8")
    assert 'CTI_RESEARCHER_MODEL = os.environ.get("CTI_RESEARCHER_MODEL", "gemini-3.7-flash")' in cti_agent

    # 3. agent_a2a_detection_engineer/agent.py
    det_agent = (repo_root / "agent_a2a_detection_engineer" / "agent.py").read_text(encoding="utf-8")
    assert 'DETECTION_ENGINEER_MODEL = os.environ.get(\n        "DETECTION_ENGINEER_MODEL", "gemini-3.7-flash"\n    )' in det_agent or 'DETECTION_ENGINEER_MODEL = os.environ.get("DETECTION_ENGINEER_MODEL", "gemini-3.7-flash")' in det_agent

    # 4. agent_a2a_threat_hunter/agent.py
    hunter_agent = (repo_root / "agent_a2a_threat_hunter" / "agent.py").read_text(encoding="utf-8")
    assert 'THREAT_HUNTER_MODEL = os.environ.get("THREAT_HUNTER_MODEL", "gemini-3.7-flash")' in hunter_agent

    # 5. agent_a2a_tier2/agent.py
    tier2_agent = (repo_root / "agent_a2a_tier2" / "agent.py").read_text(encoding="utf-8")
    assert 'TIER2_RESPONDER_MODEL = os.environ.get("TIER2_RESPONDER_MODEL", "gemini-3.7-flash")' in tier2_agent


def test_model_environment_overrides():
    custom_env = {
        "ORCHESTRATOR_MODEL": "gemini-3.1-pro-preview",
        "TIER1_ANALYST_MODEL": "gemini-2.5-flash",
        "CTI_RESEARCHER_MODEL": "gemini-2.5-flash",
        "DETECTION_ENGINEER_MODEL": "gemini-2.5-pro",
        "THREAT_HUNTER_MODEL": "gemini-2.5-pro",
        "TIER2_RESPONDER_MODEL": "gemini-2.5-pro",
    }
    with patch.dict(os.environ, custom_env, clear=True):
        assert os.environ.get("ORCHESTRATOR_MODEL") == "gemini-3.1-pro-preview"
        assert os.environ.get("TIER1_ANALYST_MODEL") == "gemini-2.5-flash"
        assert os.environ.get("CTI_RESEARCHER_MODEL") == "gemini-2.5-flash"
        assert os.environ.get("DETECTION_ENGINEER_MODEL") == "gemini-2.5-pro"
        assert os.environ.get("THREAT_HUNTER_MODEL") == "gemini-2.5-pro"
        assert os.environ.get("TIER2_RESPONDER_MODEL") == "gemini-2.5-pro"
