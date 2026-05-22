"""
SOC Agent Package - Simple and Explicit

This package provides a straightforward Security Operations Agent
following ADK standards with clear, explicit configuration.

Usage:
    # Standard ADK import pattern
    from agent_soc_manager import agent
    my_agent = agent.root_agent

    # Or create a fresh agent
    from agent_soc_manager import create_agent
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
