"""
SOC Agent Tier 2 Responder Module

This module provides a Tier 2 Incident Responder agent configured with
specific persona, responsibilities, and MCP tools for threat containment
and active mitigation operations.

The Tier 2 Responder focuses on:
- Threat containment and endpoint isolation
- Active remediation (disabling accounts, domain sinkholing, container destruction)
- Human-in-the-loop approvals for high-stakes actions
- Post-incident verification and retrospective feedback

Usage:
    # Standard ADK import pattern
    from agent_a2a_tier2 import agent
    my_agent = agent.root_agent

    # Or create a fresh agent
    from agent_a2a_tier2 import create_agent
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

