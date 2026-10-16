"""Isolated RAG sub-agent for enterprise security documentation retrieval."""

import logging
import os
from google.adk.agents import Agent
from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval

logger = logging.getLogger(__name__)

RAG_AGENT_INSTRUCTION = """
You are the Enterprise RAG Knowledge Specialist for the Security Operations Center (SOC).
Your SOLE responsibility is to search and retrieve accurate information from the enterprise RAG corpus covering:
1. Incident Response Playbooks (IRPs) and Runbooks (containment, eradication, recovery procedures).
2. Cyber Threat Intelligence (CTI) dossiers, Threat Actor profiles, and campaign TTPs.
3. Security & Compliance Policies (NIST, ISO 27001, organizational security standards).
4. Historical Incident Post-Mortems and Root Cause Analyses (RCAs).

Always provide clear citations and source references for retrieved documentation.
If the RAG corpus does not cover the requested topic, explicitly state that no matching documentation was found.
"""


def create_rag_knowledge_agent(model: str = "gemini-2.5-flash") -> Agent:
    """Instantiate the dedicated RAG Knowledge Agent with single-tool isolation.

    Uses VertexAiRagRetrieval for native Gemini 2.0+ server-side grounding.
    Single-tool isolation is strictly maintained to prevent Gemini API 400
    INVALID_ARGUMENT conflicts when mixing retrieval tools with function declarations.

    Args:
        model: Target Gemini model identifier (default: "gemini-2.5-flash").

    Returns:
        Configured Agent instance with exactly one VertexAiRagRetrieval tool.
    """
    rag_corpus_id = os.environ.get("RAG_CORPUS_ID", "").strip()
    rag_corpora = [rag_corpus_id] if rag_corpus_id else []

    try:
        similarity_top_k = int(os.environ.get("RAG_SIMILARITY_TOP_K", "5"))
    except (ValueError, TypeError):
        logger.warning("Invalid RAG_SIMILARITY_TOP_K value; defaulting to 5")
        similarity_top_k = 5

    try:
        vector_distance_threshold = float(os.environ.get("RAG_DISTANCE_THRESHOLD", "0.6"))
    except (ValueError, TypeError):
        logger.warning("Invalid RAG_DISTANCE_THRESHOLD value; defaulting to 0.6")
        vector_distance_threshold = 0.6

    rag_retrieval_tool = VertexAiRagRetrieval(
        name="retrieve_enterprise_docs",
        description=(
            "Search enterprise security playbooks, CTI dossiers, policies, and "
            "incident retrospectives in the RAG corpus."
        ),
        rag_corpora=rag_corpora,
        similarity_top_k=similarity_top_k,
        vector_distance_threshold=vector_distance_threshold,
    )

    return Agent(
        name="rag_knowledge_specialist",
        model=model,
        instruction=RAG_AGENT_INSTRUCTION,
        tools=[rag_retrieval_tool],
    )
