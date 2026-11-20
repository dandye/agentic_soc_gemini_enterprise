"""SecOps GLiNER Operational Decision & Routing Agent Package.

Exposes the decision router agent for local execution and Vertex AI
Agent Engine deployment.
"""

from .agent import create_agent, root_agent

__all__ = [
    "create_agent",
    "root_agent",
]
