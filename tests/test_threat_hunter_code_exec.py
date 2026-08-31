"""
Unit tests for Threat Hunter Agent Code Execution integration.
Follows strict Test-Driven Development (TDD).
"""

import os
import pytest
from google.adk.agents import Agent
from google.adk.code_executors import BaseCodeExecutor

from agent_a2a_threat_hunter.agent import create_agent, THREAT_HUNTER_PERSONA


class TestThreatHunterCodeExecution:
    """Tests verifying Threat Hunter integration with Code Execution Sandbox."""

    def test_threat_hunter_has_code_executor(self, monkeypatch, tmp_path):
        # Provide minimal mock env for offline creation
        fake_sa = tmp_path / "fake_sa.json"
        fake_sa.write_text('{"type": "service_account"}')

        monkeypatch.setenv("CHRONICLE_PROJECT_ID", "test-project")
        monkeypatch.setenv("CHRONICLE_CUSTOMER_ID", "test-customer")
        monkeypatch.setenv("CHRONICLE_SERVICE_ACCOUNT_PATH", str(fake_sa))
        monkeypatch.setenv("GCP_VERTEXAI_ENABLED", "False")

        agent = create_agent()
        assert isinstance(agent, Agent)
        assert hasattr(agent, "code_executor")
        assert agent.code_executor is not None
        assert isinstance(agent.code_executor, BaseCodeExecutor)

    def test_threat_hunter_instruction_contains_analytics_recipes(self, monkeypatch, tmp_path):
        fake_sa = tmp_path / "fake_sa.json"
        fake_sa.write_text('{"type": "service_account"}')

        monkeypatch.setenv("CHRONICLE_PROJECT_ID", "test-project")
        monkeypatch.setenv("CHRONICLE_CUSTOMER_ID", "test-customer")
        monkeypatch.setenv("CHRONICLE_SERVICE_ACCOUNT_PATH", str(fake_sa))
        monkeypatch.setenv("GCP_VERTEXAI_ENABLED", "False")

        agent = create_agent()
        instructions = agent.instruction.lower()
        
        # Verify instructions teach the agent how to leverage Python sandbox
        assert "python" in instructions or "sandbox" in instructions or "code" in instructions
        assert "entropy" in instructions or "beacon" in instructions or "telemetry" in instructions
