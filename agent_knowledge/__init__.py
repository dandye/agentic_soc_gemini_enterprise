"""Unified Multi-Modal Knowledge Subsystem for Agentic SOC."""

from google.adk.tools.agent_tool import AgentTool
from .agent import (
    KNOWLEDGE_AGENT_DESCRIPTION,
    KNOWLEDGE_ROUTER_INSTRUCTION,
    create_knowledge_agent,
    knowledge_agent,
)

knowledge_agent_tool = AgentTool(
    agent=knowledge_agent,
)
knowledge_agent_tool.name = "query_enterprise_knowledge"
knowledge_agent_tool.description = (
    "Query the unified multi-modal SOC knowledge base spanning: "
    "1) Unstructured RAG (IRP runbooks, CTI threat actor dossiers, compliance policies, retrospectives), "
    "2) Neo4j Operational Graph (lateral movement, user-machine-process topologies), "
    "3) AlloyDB/Omnia (asset criticality catalogs and pgvector semantic case histories), "
    "4) Working Memory (analyst notes, active investigation hypotheses, entity tags)."
)

__all__ = [
    "KNOWLEDGE_AGENT_DESCRIPTION",
    "KNOWLEDGE_ROUTER_INSTRUCTION",
    "create_knowledge_agent",
    "knowledge_agent",
    "knowledge_agent_tool",
]
