"""Unit tests for KnowledgeAgent router and AgentTool packaging."""

import pytest
from google.adk.agents import Agent
from google.adk.tools.agent_tool import AgentTool
from google.adk.tools.skill_toolset import SkillToolset

from agent_knowledge import (
    create_knowledge_agent,
    knowledge_agent,
    knowledge_agent_tool,
)
from agent_knowledge.tools.alloydb_tool import query_asset_catalog
from agent_knowledge.tools.graph_tool import query_knowledge_graph
from agent_knowledge.tools.memory_tool import query_investigation_memory


def test_knowledge_agent_structure():
    """Verify knowledge_agent structure, sub-agents, tools, and instructions."""
    assert isinstance(knowledge_agent, Agent)
    assert knowledge_agent.name == "knowledge_agent"
    assert knowledge_agent.model == "gemini-2.5-flash"

    # Sub-agents check
    assert len(knowledge_agent.sub_agents) == 1
    sub_agent = knowledge_agent.sub_agents[0]
    assert sub_agent.name == "rag_knowledge_specialist"

    # Instruction check covering 4 knowledge planes
    instruction = knowledge_agent.instruction
    assert "rag_knowledge_specialist" in instruction or "Unstructured RAG" in instruction
    assert "query_knowledge_graph" in instruction or "Operational Graph" in instruction
    assert "query_asset_catalog" in instruction or "Asset" in instruction
    assert "query_investigation_memory" in instruction or "Working Memory" in instruction

    # Core tools check
    tool_callables = [
        t for t in knowledge_agent.tools if callable(t)
    ]
    assert query_knowledge_graph in tool_callables
    assert query_asset_catalog in tool_callables
    assert query_investigation_memory in tool_callables

    # Skills toolset check
    skill_toolsets = [
        t for t in knowledge_agent.tools if isinstance(t, SkillToolset)
    ]
    assert len(skill_toolsets) == 1
    loaded_skills = skill_toolsets[0]._skills
    assert "cypher_graph_navigation" in loaded_skills
    assert "asset_criticality_evaluation" in loaded_skills
    assert "incident_memory_correlation" in loaded_skills
    assert "mitre_ttp_mapping" in loaded_skills


def test_knowledge_agent_tool_packaging():
    """Verify knowledge_agent_tool wraps knowledge_agent with expected name and description."""
    assert isinstance(knowledge_agent_tool, AgentTool)
    assert knowledge_agent_tool.name == "query_enterprise_knowledge"
    assert knowledge_agent_tool.agent is knowledge_agent
    assert knowledge_agent_tool.agent.name == "knowledge_agent"
    assert "Unstructured RAG" in knowledge_agent_tool.description
    assert "Neo4j" in knowledge_agent_tool.description
    assert "AlloyDB" in knowledge_agent_tool.description
    assert "Working Memory" in knowledge_agent_tool.description


@pytest.mark.asyncio
async def test_knowledge_agent_tools_callable():
    """Verify that core query tools attached to the agent are executable."""
    # Test query_knowledge_graph callable
    graph_res = await query_knowledge_graph(
        query_type="entity_neighborhood",
        entity_value="test_host",
    )
    assert isinstance(graph_res, str)

    # Test query_asset_catalog callable
    catalog_res = await query_asset_catalog(
        query="test_host",
        search_mode="exact_asset",
    )
    assert isinstance(catalog_res, str)

    # Test query_investigation_memory callable
    memory_res = await query_investigation_memory(
        entity="test_host",
    )
    assert isinstance(memory_res, str)


def test_create_knowledge_agent_custom_model():
    """Verify create_knowledge_agent propagates custom model to router and sub-agents."""
    custom_agent = create_knowledge_agent(model="gemini-3.1-pro-preview")
    assert custom_agent.model == "gemini-3.1-pro-preview"
    assert len(custom_agent.sub_agents) == 1
    assert custom_agent.sub_agents[0].model == "gemini-3.1-pro-preview"
