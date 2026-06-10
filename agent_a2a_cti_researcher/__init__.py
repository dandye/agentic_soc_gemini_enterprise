"""
SOC Agent CTI Researcher Module

This module provides a Cyber Threat Intelligence (CTI) Researcher agent configured with
specific persona, responsibilities, and MCP tools for threat research, campaigns/actors
tracking, and malware intelligence enrichment.

Usage:
    # Standard ADK import pattern
    from agent_a2a_cti_researcher import agent
    my_agent = agent.root_agent

    # Or create a fresh agent
    from agent_a2a_cti_researcher import create_agent
    my_agent = create_agent()
"""

# Import the agent module (ADK standard pattern)
from . import agent

# Also expose the main functions for convenience
from .agent import create_agent, root_agent


__version__ = "1.0.0"

__all__ = [
    "agent",
    "create_agent",
    "root_agent",
]
