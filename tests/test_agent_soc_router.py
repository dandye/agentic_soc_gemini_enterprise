"""Unit tests for the SecOps GLiNER Decision Router agent module."""

import pytest
from google.adk.agents import Agent


def test_agent_module_imports():
  from agent_soc_router import create_agent, root_agent

  agent = create_agent()
  assert isinstance(agent, Agent)
  assert isinstance(root_agent, Agent)
  assert agent.name == "soc_decision_router"


def test_agent_tools_configuration():
  from agent_soc_router import create_agent

  agent = create_agent()
  tool_names = [getattr(t, "__name__", str(t)) for t in agent.tools]

  # Core GLiNER decision tools
  assert "triage_alert_with_gliner" in tool_names
  assert "route_case_to_specialist_with_gliner" in tool_names
  assert "evaluate_hitl_gate_with_gliner" in tool_names
  assert "filter_cti_advisory_with_gliner" in tool_names

  # Investigation enrichment tools
  assert "lookup_ip_reputation" in tool_names
  assert "check_host_isolation_status" in tool_names
  assert "request_containment_approval" in tool_names


def test_agent_system_instruction():
  from agent_soc_router import create_agent

  agent = create_agent()
  instruction = agent.instruction.lower()
  assert "gliner" in instruction or "decision" in instruction
  assert "triage" in instruction
  assert "human-in-the-loop" in instruction or "hitl" in instruction
  assert "routing" in instruction
