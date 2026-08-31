"""
Unit tests for Vertex AI Code Execution Sandbox and CodeExecutorFactory.
Follows strict Test-Driven Development (TDD).
"""

import math
import os
import pytest
from google.adk.agents import Agent
from google.adk.code_executors import (
    BaseCodeExecutor,
    BuiltInCodeExecutor,
    UnsafeLocalCodeExecutor,
    VertexAiCodeExecutor,
    AgentEngineSandboxCodeExecutor,
)
from google.adk.code_executors.code_execution_utils import (
    CodeExecutionInput,
    CodeExecutionResult,
)

from installation_scripts.code_executor_factory import (
    get_code_executor,
    calculate_shannon_entropy,
    calculate_beaconing_jitter,
)


class TestCodeExecutorFactory:
    """Tests for CodeExecutorFactory resolution and instantiation."""

    def test_factory_resolves_local_executor(self):
        executor = get_code_executor("local")
        assert isinstance(executor, UnsafeLocalCodeExecutor)

    def test_factory_resolves_builtin_executor(self):
        executor = get_code_executor("builtin")
        assert isinstance(executor, BuiltInCodeExecutor)

    def test_factory_resolves_agent_engine_sandbox(self):
        res_name = "projects/test-proj/locations/us-central1/reasoningEngines/123"
        executor = get_code_executor(
            "agent_engine", agent_engine_resource_name=res_name
        )
        assert isinstance(executor, AgentEngineSandboxCodeExecutor)
        assert executor.agent_engine_resource_name == res_name

    def test_factory_resolves_vertex_ai_extension(self):
        from installation_scripts.code_executor_factory import LazyVertexAiCodeExecutor
        executor = get_code_executor("vertex_ai")
        assert isinstance(executor, (VertexAiCodeExecutor, LazyVertexAiCodeExecutor))
        assert isinstance(executor, BaseCodeExecutor)

    def test_factory_auto_mode_fallback(self, monkeypatch):
        monkeypatch.delenv("AGENT_ENGINE_RESOURCE_NAME", raising=False)
        monkeypatch.delenv("SANDBOX_RESOURCE_NAME", raising=False)
        executor = get_code_executor("auto")
        assert isinstance(executor, (BuiltInCodeExecutor, AgentEngineSandboxCodeExecutor))


class TestSocCodeAnalysisAgent:
    """Tests for standalone test agent equipped with Code Execution."""

    def test_agent_initialization(self):
        from test_agents.soc_code_analysis_agent.agent import root_agent

        assert isinstance(root_agent, Agent)
        assert root_agent.name == "soc_code_analysis_agent"
        assert hasattr(root_agent, "code_executor")
        assert root_agent.code_executor is not None
        assert "threat" in root_agent.instruction.lower() or "analytics" in root_agent.instruction.lower()


class TestSecurityAnalyticsMath:
    """Tests for security analytics calculations supported by Code Execution."""

    def test_shannon_entropy_calculation(self):
        # Benign structured domain: low entropy
        benign_entropy = calculate_shannon_entropy("google.com")
        # High entropy DGA domain: high entropy
        dga_entropy = calculate_shannon_entropy("xk92bvf0q81lzmn04.evil-c2.net")
        
        assert benign_entropy < 3.5
        assert dga_entropy > 3.8

    def test_beaconing_jitter_calculation(self):
        # Strict periodic beaconing: 60s +/- 1s interval (low standard deviation)
        periodic_timestamps = [
            "2026-08-31T12:00:00Z",
            "2026-08-31T12:01:00Z",
            "2026-08-31T12:02:01Z",
            "2026-08-31T12:03:00Z",
            "2026-08-31T12:04:02Z",
        ]
        stats = calculate_beaconing_jitter(periodic_timestamps)
        assert stats["is_periodic"] is True
        assert stats["mean_interval_seconds"] == pytest.approx(60.5, abs=1.0)
        assert stats["coefficient_of_variation"] < 0.1
