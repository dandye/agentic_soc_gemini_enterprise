"""Standalone ADK evaluation test agent for KnowledgeAgent."""

from agent_knowledge import knowledge_agent

# Export root_agent for adk eval runner
root_agent = knowledge_agent

__all__ = ["root_agent"]
