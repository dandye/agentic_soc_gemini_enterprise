"""
SOC Agent Detection Engineer Module

This module provides a Detection Engineer agent configured with
specific persona, responsibilities, and the remote OneMCP server connection
for detection rule development, validation, tuning, and lifecycle management.

Usage:
    # Standard ADK import pattern
    from agent_a2a_detection_engineer import agent
    my_agent = agent.root_agent

    # Or create a fresh agent
    from agent_a2a_detection_engineer import create_agent
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
