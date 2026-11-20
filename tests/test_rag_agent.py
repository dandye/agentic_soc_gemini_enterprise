import os
from unittest.mock import patch
import pytest
from google.adk.agents import Agent
from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval

from agent_knowledge.sub_agents import create_rag_knowledge_agent
from agent_knowledge.sub_agents.rag_agent import RAG_AGENT_INSTRUCTION


def test_create_rag_knowledge_agent_single_tool_isolation():
    """Verify single-tool isolation invariant: exactly 1 tool of type VertexAiRagRetrieval."""
    with patch.dict(
        "os.environ",
        {"RAG_CORPUS_ID": "projects/123/locations/us-central1/ragCorpora/456"},
    ):
        agent = create_rag_knowledge_agent()
        assert isinstance(agent, Agent)
        assert agent.name == "rag_knowledge_specialist"
        assert len(agent.tools) == 1
        assert isinstance(agent.tools[0], VertexAiRagRetrieval)
        assert agent.tools[0].name == "retrieve_enterprise_docs"
        assert agent.tools[0].vertex_rag_store.rag_corpora == [
            "projects/123/locations/us-central1/ragCorpora/456"
        ]


def test_create_rag_knowledge_agent_handles_missing_corpus():
    """Verify handling when RAG_CORPUS_ID is unset or empty."""
    with patch.dict("os.environ", {}, clear=True):
        agent = create_rag_knowledge_agent()
        assert agent.name == "rag_knowledge_specialist"
        assert len(agent.tools) == 1
        assert isinstance(agent.tools[0], VertexAiRagRetrieval)
        assert agent.tools[0].vertex_rag_store.rag_corpora == []


def test_create_rag_knowledge_agent_empty_corpus_string():
    """Verify handling when RAG_CORPUS_ID is an empty string or whitespace."""
    with patch.dict("os.environ", {"RAG_CORPUS_ID": "   "}):
        agent = create_rag_knowledge_agent()
        assert len(agent.tools) == 1
        assert agent.tools[0].vertex_rag_store.rag_corpora == []


def test_create_rag_knowledge_agent_model_and_instruction():
    """Verify agent model, name, and instruction content covering all required knowledge domains."""
    agent = create_rag_knowledge_agent(model="gemini-2.5-pro")
    assert agent.model == "gemini-2.5-pro"
    assert agent.name == "rag_knowledge_specialist"
    assert "Enterprise RAG Knowledge Specialist" in agent.instruction
    assert "Incident Response Playbooks" in agent.instruction or "IRP" in agent.instruction
    assert "Cyber Threat Intelligence" in agent.instruction or "CTI" in agent.instruction
    assert "Security & Compliance Policies" in agent.instruction or "compliance" in agent.instruction.lower()
    assert "Post-Mortems" in agent.instruction or "RCAs" in agent.instruction


def test_create_rag_knowledge_agent_custom_env_configs():
    """Verify custom similarity_top_k and vector_distance_threshold from environment."""
    with patch.dict(
        "os.environ",
        {
            "RAG_CORPUS_ID": "projects/my-proj/locations/us-central1/ragCorpora/corp-999",
            "RAG_SIMILARITY_TOP_K": "10",
            "RAG_DISTANCE_THRESHOLD": "0.45",
        },
    ):
        agent = create_rag_knowledge_agent()
        tool = agent.tools[0]
        assert tool.vertex_rag_store.rag_corpora == [
            "projects/my-proj/locations/us-central1/ragCorpora/corp-999"
        ]
        assert tool.vertex_rag_store.similarity_top_k == 10
        assert tool.vertex_rag_store.vector_distance_threshold == pytest.approx(0.45)


def test_create_rag_knowledge_agent_invalid_env_fallbacks():
    """Verify graceful fallback to defaults when numeric env vars contain invalid strings."""
    with patch.dict(
        "os.environ",
        {
            "RAG_CORPUS_ID": "projects/my-proj/locations/us-central1/ragCorpora/corp-999",
            "RAG_SIMILARITY_TOP_K": "invalid_int",
            "RAG_DISTANCE_THRESHOLD": "invalid_float",
        },
    ):
        agent = create_rag_knowledge_agent()
        tool = agent.tools[0]
        assert tool.vertex_rag_store.similarity_top_k == 5
        assert tool.vertex_rag_store.vector_distance_threshold == pytest.approx(0.6)


def test_sub_agents_package_exports():
    """Verify sub_agents package exports create_rag_knowledge_agent."""
    import agent_knowledge.sub_agents as sub_agents_pkg

    assert hasattr(sub_agents_pkg, "create_rag_knowledge_agent")
    assert callable(sub_agents_pkg.create_rag_knowledge_agent)
    assert "create_rag_knowledge_agent" in sub_agents_pkg.__all__
