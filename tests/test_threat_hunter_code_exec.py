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
        assert "deobfuscate" in instructions or "xor" in instructions or "string" in instructions
        assert "yara" in instructions

    def test_threat_hunter_sandboxed_deobfuscation_and_yara_execution(self):
        from google.adk.code_executors import UnsafeLocalCodeExecutor
        from google.adk.code_executors.code_execution_utils import CodeExecutionInput
        from google.adk.agents.invocation_context import InvocationContext

        # Test that sandboxed Python code executes de-obfuscation and YARA testing successfully
        code_snippet = """
from installation_scripts.code_executor_factory import deobfuscate_xor_strings, validate_and_test_yara_rule

# 1. De-obfuscate payload with XOR key 0x5A
raw_payload = bytes([b ^ 0x5A for b in b"https://apt29-c2.evil-domain.com/beacon"])
deobf_results = deobfuscate_xor_strings(raw_payload)
print(f"KEY_FOUND:{deobf_results[0]['key_hex']}")
print(f"STRING_FOUND:{deobf_results[0]['decoded_strings'][0]}")

# 2. Validate YARA rule
rule_text = '''
rule APT29_C2_Dropper {
    strings:
        $s = "apt29-c2.evil-domain.com"
    condition:
        $s
}
'''
yara_res = validate_and_test_yara_rule(rule_text, b"Trigger: https://apt29-c2.evil-domain.com/beacon")
print(f"YARA_VALID:{yara_res['valid']}")
print(f"YARA_MATCH:{yara_res['matches']}")
"""
        from unittest.mock import MagicMock

        executor = UnsafeLocalCodeExecutor()
        dummy_context = MagicMock()
        res = executor.execute_code(dummy_context, CodeExecutionInput(code=code_snippet))

        assert res.stderr == ""
        assert "KEY_FOUND:0x5A" in res.stdout
        assert "STRING_FOUND:https://apt29-c2.evil-domain.com/beacon" in res.stdout
        assert "YARA_VALID:True" in res.stdout
        assert "YARA_MATCH:True" in res.stdout

