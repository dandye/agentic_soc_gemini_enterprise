"""
SOC Agent Threat Hunter Module

This module provides a proactive Threat Hunter agent configured with
specific persona, responsibilities, and MCP tools for hypothesis-driven
threat hunting, log analysis, and threat intelligence enrichment.

The Threat Hunter focuses on:
- Hypothesis-driven threat hunting
- Advanced log querying and UDM query development
- Threat intelligence enrichment and campaign correlation
- Generating hunt reports and remediation/containment recommendations

Usage:
    # Standard ADK import pattern
    from agent_a2a_threat_hunter import agent
    my_agent = agent.root_agent

    # Or create a fresh agent
    from agent_a2a_threat_hunter import create_agent
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
