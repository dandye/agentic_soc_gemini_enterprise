"""Unit tests for the KnowledgeAgent ADK evaluation harness, agent, and evalset."""

import json
from pathlib import Path
import sys
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from google.adk.agents import Agent
from google.adk.evaluation.eval_config import EvalConfig
from google.adk.evaluation.eval_set import EvalSet
from google.adk.tools.skill_toolset import SkillToolset

import test_adk_evals
from test_agents.soc_knowledge_agent import root_agent

REPO_ROOT = Path(__file__).resolve().parent.parent
EVALSETS_DIR = REPO_ROOT / "evalsets"
TEST_AGENTS_DIR = REPO_ROOT / "test_agents" / "soc_knowledge_agent"


def test_soc_knowledge_agent_loading():
    """Verify that the test agent package loads and root_agent is properly configured."""
    assert isinstance(root_agent, Agent)
    assert root_agent.name == "knowledge_agent"
    assert root_agent.model == "gemini-2.5-flash"

    # Sub-agent hierarchy
    assert len(root_agent.sub_agents) == 1
    sub_agent = root_agent.sub_agents[0]
    assert sub_agent.name == "rag_knowledge_specialist"

    # Instruction coverage
    instruction = root_agent.instruction
    assert "rag_knowledge_specialist" in instruction or "Unstructured RAG" in instruction
    assert "query_knowledge_graph" in instruction or "Operational Graph" in instruction
    assert "query_asset_catalog" in instruction or "Asset" in instruction
    assert "query_investigation_memory" in instruction or "Working Memory" in instruction


def test_eval_config_schema_validation():
    """Verify that eval_config.json complies with ADK EvalConfig schema."""
    config_path = TEST_AGENTS_DIR / "eval_config.json"
    assert config_path.is_file(), f"Config file missing at {config_path}"

    config_data = json.loads(config_path.read_text(encoding="utf-8"))
    eval_config = EvalConfig.model_validate(config_data)

    criteria = eval_config.criteria
    assert "tool_trajectory_avg_score" in criteria
    assert "response_match_score" in criteria
    assert "rubric_based_final_response_quality_v1" in criteria
    assert "rubric_based_tool_use_quality_v1" in criteria

    # Validate response quality rubrics
    final_quality = criteria["rubric_based_final_response_quality_v1"]
    assert final_quality.threshold == 0.8
    rubric_ids = [
        r["rubric_id"] if isinstance(r, dict) else r.rubric_id
        for r in final_quality.rubrics
    ]
    assert "rubric_multi_modal_knowledge_grounding" in rubric_ids
    assert "rubric_actionable_soc_synthesis" in rubric_ids

    # Validate tool use quality rubrics
    tool_quality = criteria["rubric_based_tool_use_quality_v1"]
    assert tool_quality.threshold == 0.8
    tool_rubric_ids = [
        r["rubric_id"] if isinstance(r, dict) else r.rubric_id
        for r in tool_quality.rubrics
    ]
    assert "rubric_knowledge_plane_routing" in tool_rubric_ids


def test_soc_knowledge_evalset_schema_validation():
    """Verify that soc_knowledge_evalset.json complies with ADK EvalSet schema and benchmark cases."""
    evalset_path = EVALSETS_DIR / "soc_knowledge_evalset.json"
    assert evalset_path.is_file(), f"EvalSet file missing at {evalset_path}"

    evalset_data = json.loads(evalset_path.read_text(encoding="utf-8"))
    eval_set = EvalSet.model_validate(evalset_data)

    assert eval_set.eval_set_id == "soc_knowledge_evalset"
    assert len(eval_set.eval_cases) == 4

    eval_ids = [case.eval_id for case in eval_set.eval_cases]
    assert "case_01_lateral_movement_graph" in eval_ids
    assert "case_02_asset_criticality_lookup" in eval_ids
    assert "case_03_investigation_memory_context" in eval_ids
    assert "case_04_composite_rag_and_asset_investigation" in eval_ids

    # Check each invocation contains user prompt, tool expectation, and model reference
    for case in eval_set.eval_cases:
        assert len(case.conversation) >= 1
        invocation = case.conversation[0]
        user_parts = invocation.user_content.parts
        assert len(user_parts) >= 1
        assert user_parts[0].text is not None and len(user_parts[0].text) > 10

        final_parts = invocation.final_response.parts
        assert len(final_parts) >= 1
        assert final_parts[0].text is not None and len(final_parts[0].text) > 10

        assert invocation.intermediate_data is not None
        assert len(invocation.intermediate_data.tool_uses) >= 1


def test_evalset_tool_mapping_to_root_agent():
    """Verify that every tool call specified in the evalset maps to a valid tool on root_agent."""
    evalset_path = EVALSETS_DIR / "soc_knowledge_evalset.json"
    evalset_data = json.loads(evalset_path.read_text(encoding="utf-8"))
    eval_set = EvalSet.model_validate(evalset_data)

    # Collect agent callable tool names
    agent_tool_names = set()
    for t in root_agent.tools:
        if callable(t):
            agent_tool_names.add(getattr(t, "__name__", str(t)))
        elif hasattr(t, "name"):
            agent_tool_names.add(t.name)
        elif isinstance(t, SkillToolset):
            agent_tool_names.update(t._skills.keys())

    # Collect tool calls from evalset
    evalset_tool_names = set()
    for case in eval_set.eval_cases:
        for inv in case.conversation:
            for tool_use in inv.intermediate_data.tool_uses:
                evalset_tool_names.add(tool_use.name)

    # All tools expected in evalset must exist on the root agent
    assert "query_knowledge_graph" in agent_tool_names
    assert "query_asset_catalog" in agent_tool_names
    assert "query_investigation_memory" in agent_tool_names

    for tool_name in evalset_tool_names:
        assert tool_name in agent_tool_names, (
            f"Evalset tool '{tool_name}' is not registered on root_agent tools: {agent_tool_names}"
        )


def test_local_and_evalsets_dir_parity():
    """Verify that local test_agents evalset copy matches the root evalsets/ copy."""
    evalsets_file = EVALSETS_DIR / "soc_knowledge_evalset.json"
    local_file = TEST_AGENTS_DIR / "soc_knowledge_evalset.json"

    assert evalsets_file.is_file()
    assert local_file.is_file()

    evalsets_obj = EvalSet.model_validate_json(evalsets_file.read_text(encoding="utf-8"))
    local_obj = EvalSet.model_validate_json(local_file.read_text(encoding="utf-8"))

    assert evalsets_obj.eval_set_id == local_obj.eval_set_id
    assert len(evalsets_obj.eval_cases) == len(local_obj.eval_cases)


def test_adk_evals_runner_presets():
    """Verify test_adk_evals runner presets for triage and knowledge agents."""
    presets = test_adk_evals.AGENT_PRESETS
    assert "triage" in presets
    assert "knowledge" in presets

    knowledge_preset = presets["knowledge"]
    assert knowledge_preset["agent_module"] == "test_agents.soc_knowledge_agent"
    assert knowledge_preset["evalset"].is_file()
    assert knowledge_preset["config"].is_file()
