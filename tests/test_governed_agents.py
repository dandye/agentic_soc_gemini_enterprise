"""Unit tests for the five governed SecOps ADK A2A agents and governance assets."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch


REPO_ROOT = Path(__file__).resolve().parent.parent
GOVERNED_AGENTS_DIR = REPO_ROOT / "governed_agents"
TERRAFORM_DIR = REPO_ROOT / "terraform"
GOVERNANCE_SCRIPTS_DIR = REPO_ROOT / "scripts" / "governance"


def _load_module(
    module_name: str, file_path: Path, env_overrides: dict[str, str]
) -> Any:
    """Loads a file-backed module under temporary environment variables."""
    with patch.dict(os.environ, env_overrides, clear=False):
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


def _contains_emoji(text: str) -> bool:
    """Checks for emoji codepoints across Supplementary Multilingual & symbol ranges."""
    for ch in text:
        cp = ord(ch)
        if 0x1F300 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF or 0xFE00 <= cp <= 0xFE0F:
            return True
    return False


def test_zero_emojis_across_governance_files() -> None:
    """Verifies that governed_agents/, terraform/, and scripts/governance/ contain zero emojis."""
    checked = 0
    for root in (GOVERNED_AGENTS_DIR, TERRAFORM_DIR, GOVERNANCE_SCRIPTS_DIR):
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(
                part in {".terraform", "dist", "__pycache__"} for part in path.parts
            ):
                continue
            if (
                path.suffix in {".gz", ".pyc", ".lock", ".hcl"}
                and path.name != ".terraform.lock.hcl"
            ):
                continue
            if path.name == ".terraform.lock.hcl":
                continue
            text = path.read_text(encoding="utf-8")
            assert not _contains_emoji(text), f"Emoji character found in {path}"
            checked += 1
    assert checked >= 30


def test_all_five_agent_cards_build_cleanly() -> None:
    """Imports all five governed agent entrypoints and verifies A2A AgentCard metadata."""
    test_env = {
        "GTI_AUTH_PROVIDER": "projects/example-proj/locations/us-central1/authProviders/agw-secops-gti-api-key",
        "CHRONICLE_PROJECT_ID": "example-proj",
        "CHRONICLE_CUSTOMER_ID": "00000000-0000-0000-0000-000000000000",
        "CHRONICLE_REGION": "us",
        "CTI_RESEARCHER_URL": "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/example-proj/locations/us-central1/reasoningEngines/101/a2a",
        "THREAT_HUNTER_URL": "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/example-proj/locations/us-central1/reasoningEngines/102/a2a",
        "DETECTION_ENGINEER_URL": "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/example-proj/locations/us-central1/reasoningEngines/103/a2a",
        "TIER2_RESPONDER_URL": "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/example-proj/locations/us-central1/reasoningEngines/104/a2a",
    }
    expected_names = {
        "cti_researcher": "cti_researcher_agent",
        "threat_hunter": "threat_hunter_agent",
        "detection_engineer": "detection_engineer_agent",
        "tier2_responder": "tier2_responder_agent",
        "soc_orchestrator": "soc_orchestrator_agent",
    }
    for folder, card_name in expected_names.items():
        agent_dir = GOVERNED_AGENTS_DIR / folder
        import sys

        sys.path.insert(0, str(agent_dir))
        try:
            for helper_mod in ("gti_tools", "secops_mcp", "response_tools"):
                sys.modules.pop(helper_mod, None)
            mod = _load_module(f"test_card_{folder}", agent_dir / "agent.py", test_env)
            assert mod.agent_card.name == card_name
            assert mod.agent_card.version == "1.0.0"
            assert mod.root_agent is not None
            ops = mod.root_agent.register_operations()
            assert "a2a_extension" in ops
            if folder == "soc_orchestrator":
                assert "stream_query" in ops.get("stream", [])
                assert "streaming_agent_run_with_events" in ops.get("async_stream", [])
            else:
                assert "stream" not in ops
        finally:
            sys.path.remove(str(agent_dir))


def test_gti_tools_retrieves_auth_manager_secret_without_leaking_key() -> None:
    """Verifies AuthProvider credential retrieval and HTTP error scrubbing without leaking secret material."""
    mod = _load_module(
        "test_gti_tools",
        GOVERNED_AGENTS_DIR / "cti_researcher" / "gti_tools.py",
        {"GTI_AUTH_PROVIDER": "projects/p/locations/us-central1/authProviders/gti"},
    )
    fake_secret = "SUPER_SECRET_VT_KEY_DO_NOT_ECHO"  # noqa: S105

    mock_creds_client = MagicMock()
    mock_creds_client.retrieve_credentials.return_value = SimpleNamespace(
        success=SimpleNamespace(token=fake_secret)
    )
    mod._creds_client = mock_creds_client

    mock_http_resp = MagicMock()
    mock_http_resp.status_code = 200
    mock_http_resp.json.return_value = {
        "data": {
            "id": "example.com",
            "attributes": {
                "reputation": -42,
                "last_analysis_stats": {
                    "malicious": 9,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 15,
                },
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan.beacon"
                },
                "tags": ["c2"],
            },
        }
    }

    with (
        patch.dict(
            os.environ,
            {"GTI_AUTH_PROVIDER": "projects/p/locations/us-central1/authProviders/gti"},
            clear=False,
        ),
        patch.object(mod.httpx, "Client") as client_cls,
    ):
        client_instance = MagicMock()
        client_instance.get.return_value = mock_http_resp
        client_cls.return_value.__enter__.return_value = client_instance

        summary = mod.lookup_domain_reputation("Example.COM")
        assert summary["found"] is True
        assert summary["malicious_detections"] == 9
        assert fake_secret not in str(summary)
        _, kwargs = client_instance.get.call_args
        assert kwargs["headers"]["x-apikey"] == fake_secret

        mock_err_resp = MagicMock()
        mock_err_resp.status_code = 403
        mock_err_resp.text = "Access denied by gateway"
        client_instance.get.return_value = mock_err_resp
        err_summary = mod.lookup_ip_reputation("198.51.100.10")
        assert "HTTP 403" in err_summary["error"]
        assert fake_secret not in str(err_summary)


def test_secops_mcp_strips_response_schema_and_formats_tool_errors() -> None:
    """Verifies response_json_schema stripping and TOOL_ERROR short-circuiting on 403 denials."""
    mod = _load_module(
        "test_secops_mcp",
        GOVERNED_AGENTS_DIR / "threat_hunter" / "secops_mcp.py",
        {"CHRONICLE_PROJECT_ID": "example-proj"},
    )

    fd = SimpleNamespace(
        name="list_security_alerts", response_json_schema={"type": "object"}
    )
    tool_decl = SimpleNamespace(function_declarations=[fd])
    fn_resp = SimpleNamespace(
        name="delete_feed",
        response={
            "error": "HTTP 403 Forbidden: permission denied by IAP access policy"
        },
    )
    llm_request = SimpleNamespace(
        config=SimpleNamespace(tools=[tool_decl]),
        contents=[SimpleNamespace(parts=[SimpleNamespace(function_response=fn_resp)])],
    )

    short_circuit = mod.chronicle_before_model_callback(None, llm_request)
    assert fd.response_json_schema is None
    assert short_circuit is not None
    text = short_circuit.content.parts[0].text
    assert (
        text
        == "TOOL_ERROR: delete_feed -- HTTP 403 Forbidden: permission denied by IAP access policy"
    )


def test_tier2_response_tools_preserve_host_user_and_change_ticket() -> None:
    """Verifies Tier-2 containment tool return payloads."""
    mod = _load_module(
        "test_response_tools",
        GOVERNED_AGENTS_DIR / "tier2_responder" / "response_tools.py",
        {},
    )
    iso = mod.isolate_endpoint_host(
        " WKSTN-FIN-042 ", "Confirmed C2 beacon", " CHG-10492 "
    )
    assert iso["status"] == "ISOLATED"
    assert iso["hostname"] == "WKSTN-FIN-042"
    assert iso["change_ticket"] == "CHG-10492"

    acct = mod.disable_compromised_account("jdoe@example.com", "Credential theft")
    assert acct["status"] == "DISABLED_AND_SESSIONS_REVOKED"
    assert acct["change_ticket"] is None


def test_soc_orchestrator_policy_block_banners() -> None:
    """Verifies deterministic [POLICY BLOCK] banners for Model Armor and Tool Allowlist denials."""
    mod = _load_module(
        "test_soc_orchestrator_banners",
        GOVERNED_AGENTS_DIR / "soc_orchestrator" / "agent.py",
        {
            "CTI_RESEARCHER_URL": "https://example.invalid/cti/a2a",
            "THREAT_HUNTER_URL": "https://example.invalid/hunter/a2a",
            "DETECTION_ENGINEER_URL": "https://example.invalid/de/a2a",
            "TIER2_RESPONDER_URL": "https://example.invalid/tier2/a2a",
            "MODEL_ARMOR_CONTROL": "agw-secops-ma-content-authz",
        },
    )

    banner = mod._stream_notice(
        '{"result": "TOOL_ERROR: delete_feed -- HTTP 403 Forbidden from Agent Gateway"}'
    )
    assert banner is not None
    assert "[POLICY BLOCK] Blocked by AI security policy -- TOOL ALLOWLIST." in banner
    assert "`delete_feed`" in banner
    assert "`chronicle-mcp-tool-allowlist`" in banner

    exc = RuntimeError(
        '{"error": {"message": "Security Policy Violation: prompt injection detected"}}'
    )
    event = mod._notice_event(exc)
    notice_text = event.content.parts[0].text
    assert "[POLICY BLOCK] Blocked by AI security policy -- MODEL ARMOR." in notice_text
    assert "`agw-secops-ma-content-authz`" in notice_text
