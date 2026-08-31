"""KnowledgeAgent Router orchestrating multi-modal enterprise grounding."""

import logging
from pathlib import Path
from typing import Optional

from google.adk.agents import Agent
from google.adk.tools.skill_toolset import SkillToolset

from .skills import load_all_domain_skills
from .sub_agents.rag_agent import create_rag_knowledge_agent
from .tools.alloydb_tool import query_asset_catalog
from .tools.graph_tool import query_knowledge_graph
from .tools.memory_tool import query_investigation_memory

logger = logging.getLogger(__name__)

KNOWLEDGE_ROUTER_INSTRUCTION = """
You are the Chief Knowledge Agent for the Security Operations Center (SOC).
Your purpose is to deliver accurate, multi-modal intelligence and grounding to SOC analysts and orchestrator agents.

You have access to 4 distinct knowledge planes:
1. **Unstructured RAG (via rag_knowledge_specialist sub-agent)**: Incident Response Playbooks (IRPs), security policies, CTI actor dossiers, and historical post-mortems.
2. **Operational Graph (via query_knowledge_graph)**: Neo4j relationship topology, user logons, process trees, and lateral movement attack paths.
3. **Asset & Case Catalog (via query_asset_catalog)**: AlloyDB/Omnia structured asset inventories (Tier 0-2 ratings, owners, IPs) and pgvector semantic case histories.
4. **Working Memory (via query_investigation_memory)**: Cross-session analyst notes, active hypotheses, and previous containment tags.

When answering a question:
- Decompose complex inquiries into the appropriate store lookups.
- For topological, lateral movement, or parent-child process queries, query Neo4j using query_knowledge_graph.
- For asset criticality, owner, or business tier lookups, query AlloyDB using query_asset_catalog.
- For incident playbooks, threat actor TTPs, or policies, delegate to the rag_knowledge_specialist sub-agent.
- For past investigation context on an indicator, check investigation memory using query_investigation_memory.
- Synthesize all findings into a structured, cohesive response with actionable conclusions and citations.
"""

KNOWLEDGE_AGENT_DESCRIPTION = (
    "Query the unified multi-modal SOC knowledge base spanning: "
    "1) Unstructured RAG (IRP runbooks, CTI threat actor dossiers, compliance policies, retrospectives), "
    "2) Neo4j Operational Graph (lateral movement, user-machine-process topologies), "
    "3) AlloyDB/Omnia (asset criticality catalogs and pgvector semantic case histories), "
    "4) Working Memory (analyst notes, active investigation hypotheses, entity tags)."
)


def create_knowledge_agent(model: str = "gemini-2.5-flash") -> Agent:
    """Construct the unified KnowledgeAgent router.

    Args:
        model: Target Gemini model identifier (default: "gemini-2.5-flash").

    Returns:
        Configured Agent router instance with isolated RAG sub-agent, core query
        tools (Neo4j, AlloyDB, Working Memory), and loaded domain skills.
    """
    rag_sub_agent = create_rag_knowledge_agent(model=model)

    # Load domain-specific skills into SkillToolset
    try:
        domain_skills = load_all_domain_skills()
        skill_ts = SkillToolset(skills=list(domain_skills.values()))
        skill_tools = [skill_ts]
    except Exception as e:
        logger.warning("Could not load domain skills into SkillToolset: %s", e)
        skill_tools = []

    tools = [
        query_knowledge_graph,
        query_asset_catalog,
        query_investigation_memory,
    ] + skill_tools

    return Agent(
        name="knowledge_agent",
        description=KNOWLEDGE_AGENT_DESCRIPTION,
        model=model,
        instruction=KNOWLEDGE_ROUTER_INSTRUCTION,
        sub_agents=[rag_sub_agent],
        tools=tools,
    )


# Default singleton instance for direct export
knowledge_agent: Agent = create_knowledge_agent()

__all__ = [
    "KNOWLEDGE_AGENT_DESCRIPTION",
    "KNOWLEDGE_ROUTER_INSTRUCTION",
    "create_knowledge_agent",
    "knowledge_agent",
]
