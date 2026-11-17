"""Unit tests for Wiz Remote MCP integration in agent_soc_manager and governed_agents."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch


REPO_ROOT = Path(__file__).resolve().parent.parent
THREAT_HUNTER_DIR = REPO_ROOT / "governed_agents" / "threat_hunter"
SOC_MANAGER_WIZ_MCP = REPO_ROOT / "agent_soc_manager" / "wiz_mcp.py"
TERRAFORM_DIR = REPO_ROOT / "terraform"


def _load_soc_manager_wiz_mcp() -> Any:
    spec = importlib.util.spec_from_file_location(
        "soc_manager_wiz_mcp", SOC_MANAGER_WIZ_MCP
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["soc_manager_wiz_mcp"] = module
    spec.loader.exec_module(module)
    return module


def _placeholder_adc_path() -> str:
    configured = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if configured:
        return configured
    path = Path(tempfile.gettempdir()) / "wiz_mcp_placeholder_adc.json"
    path.write_text(
        json.dumps(
            {
                "type": "authorized_user",
                "client_id": "placeholder.apps.googleusercontent.com",
                "client_secret": "placeholder",
                "refresh_token": "placeholder",
                "quota_project_id": "example-secops-project",
            }
        ),
        encoding="utf-8",
    )
    return str(path)


_HERMETIC_ENV = {
    "GOOGLE_CLOUD_PROJECT": "example-secops-project",
    "GOOGLE_CLOUD_LOCATION": "us-central1",
    "GOOGLE_GENAI_USE_VERTEXAI": "TRUE",
    "GOOGLE_APPLICATION_CREDENTIALS": _placeholder_adc_path(),
    "NO_GCE_CHECK": "true",
    "CHRONICLE_PROJECT_ID": "example-secops-project",
    "CHRONICLE_CUSTOMER_ID": "a1b2c3d4-e5f6-4321-abcd-ef1234567890",
}

_SIBLING_MODULES = (
    "decision_client",
    "secops_mcp",
    "triage_tools",
    "wiz_mcp",
)


def _load_threat_hunter_agent(module_name: str, extra_env: dict[str, str]) -> Any:
    parent_dir = str(THREAT_HUNTER_DIR)
    added = parent_dir not in sys.path
    if added:
        sys.path.insert(0, parent_dir)
    for sibling in _SIBLING_MODULES:
        sys.modules.pop(sibling, None)
    try:
        with patch.dict(os.environ, {**_HERMETIC_ENV, **extra_env}, clear=False):
            spec = importlib.util.spec_from_file_location(
                module_name,
                THREAT_HUNTER_DIR / "agent.py",
            )
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            return module
    finally:
        if added and parent_dir in sys.path:
            sys.path.remove(parent_dir)


def test_agent_soc_manager_wiz_mcp_url_and_enablement(tmp_path: Path) -> None:
    wiz_mcp = _load_soc_manager_wiz_mcp()

    cache = tmp_path / "cfg" / "wiz_tokens.json"
    with patch.dict(
        os.environ,
        {
            "WIZ_MCP_ENABLED": "",
            "WIZ_AUTH_PROVIDER": "",
            "WIZ_MCP_BEARER_TOKEN": "",
            "WIZ_ACCESS_TOKEN": "",
            "WIZ_OAUTH_TOKEN_CACHE": str(cache),
        },
        clear=False,
    ):
        assert wiz_mcp.resolve_wiz_mcp_url() == "https://mcp.app.wiz.io/"
        assert (
            wiz_mcp.resolve_wiz_mcp_url("https://mcp.demo.wiz.io")
            == "https://mcp.demo.wiz.io/"
        )
        assert not wiz_mcp.is_wiz_mcp_enabled(cache)

    storage = wiz_mcp.FileTokenStorage(cache)
    storage._write_payload({"tokens": {"access_token": "tok-123"}})
    assert stat.S_IMODE(cache.stat().st_mode) == 0o600
    assert storage.has_cached_tokens()

    with patch.dict(
        os.environ,
        {
            "WIZ_MCP_ENABLED": "",
            "WIZ_AUTH_PROVIDER": "",
            "WIZ_MCP_BEARER_TOKEN": "",
            "WIZ_ACCESS_TOKEN": "",
            "WIZ_OAUTH_TOKEN_CACHE": str(cache),
        },
        clear=False,
    ):
        assert wiz_mcp.is_wiz_mcp_enabled(cache)

    with patch.dict(os.environ, {"WIZ_MCP_ENABLED": "false"}, clear=False):
        assert not wiz_mcp.is_wiz_mcp_enabled(cache)


def test_agent_soc_manager_wiz_mcp_auth_manager_provider() -> None:
    wiz_mcp = _load_soc_manager_wiz_mcp()

    fake_token = "wiz-secret-token-xyz"  # noqa: S105
    fake_client = MagicMock()
    fake_client.retrieve_credentials.return_value = SimpleNamespace(
        success=SimpleNamespace(token=fake_token)
    )

    provider_name = "projects/p/locations/us-central1/authProviders/soc-wiz-oauth"
    with (
        patch.dict(
            os.environ,
            {
                "WIZ_AUTH_PROVIDER": provider_name,
                "WIZ_MCP_URL": "https://mcp.app.wiz.io",
            },
            clear=False,
        ),
        patch(
            "google.cloud.agentidentitycredentials_v1.AuthProviderCredentialsServiceClient",
            return_value=fake_client,
        ),
    ):
        toolset = wiz_mcp.create_remote_wiz_toolset()
        assert toolset._connection_params.url == "https://mcp.app.wiz.io/"
        assert toolset.tool_name_prefix == "wiz_"
        headers = toolset._header_provider(None)
        assert headers == {"Authorization": f"Bearer {fake_token}"}


def test_agent_soc_manager_wiz_mcp_bearer_token() -> None:
    wiz_mcp = _load_soc_manager_wiz_mcp()

    with patch.dict(
        os.environ,
        {
            "WIZ_AUTH_PROVIDER": "",
            "WIZ_MCP_BEARER_TOKEN": "direct-bearer-abc",
        },
        clear=False,
    ):
        toolset = wiz_mcp.create_remote_wiz_toolset()
        assert toolset._header_provider(None) == {
            "Authorization": "Bearer direct-bearer-abc"
        }


def test_governed_threat_hunter_wiz_mcp_and_decision1_v2_callbacks() -> None:
    baseline = _load_threat_hunter_agent(
        "governed_threat_hunter_wiz_disabled_test",
        {"WIZ_AUTH_PROVIDER": ""},
    )
    baseline_wiz = [
        t for t in baseline.threat_hunter_tools if type(t).__name__ == "WizMcpToolset"
    ]
    assert baseline_wiz == []
    assert len(baseline.threat_hunter_llm.before_model_callback) == 3
    assert baseline.threat_hunter_llm.before_tool_callback is not None
    assert baseline.threat_hunter_llm.after_tool_callback is not None

    fake_token = "governed-wiz-token"  # noqa: S105
    fake_client = MagicMock()
    fake_client.retrieve_credentials.return_value = SimpleNamespace(
        success=SimpleNamespace(token=fake_token)
    )

    with patch(
        "google.cloud.agentidentitycredentials_v1.AuthProviderCredentialsServiceClient",
        return_value=fake_client,
    ):
        enabled = _load_threat_hunter_agent(
            "governed_threat_hunter_wiz_enabled_test",
            {
                "WIZ_AUTH_PROVIDER": "projects/p/locations/us-central1/authProviders/soc-wiz-oauth",
                "WIZ_MCP_URL": "https://mcp.app.wiz.io",
            },
        )
        wiz_toolsets = [
            t
            for t in enabled.threat_hunter_tools
            if type(t).__name__ == "WizMcpToolset"
        ]
        assert len(wiz_toolsets) == 1
        assert wiz_toolsets[0]._connection_params.url == "https://mcp.app.wiz.io/"
        assert wiz_toolsets[0].tool_name_prefix == "wiz_"
        assert wiz_toolsets[0].tool_filter == ["discover", "execute"]
        assert wiz_toolsets[0]._header_provider(None) == {
            "Authorization": f"Bearer {fake_token}"
        }
        assert len(enabled.threat_hunter_llm.before_model_callback) == 3
        assert enabled.threat_hunter_llm.before_tool_callback is not None
        assert enabled.threat_hunter_llm.after_tool_callback is not None


def test_terraform_wiz_mcp_opt_in_and_cel_chunking() -> None:
    variables_tf = (TERRAFORM_DIR / "variables.tf").read_text(encoding="utf-8")
    assert 'variable "enable_wiz_mcp"' in variables_tf
    assert "default     = false" in variables_tf

    registry_tf = (TERRAFORM_DIR / "11-registry-mcp.tf").read_text(encoding="utf-8")
    assert 'resource "google_agent_registry_service" "wiz_mcp"' in registry_tf
    assert "count = var.enable_wiz_mcp ? 1 : 0" in registry_tf

    auth_tf = (TERRAFORM_DIR / "20-authmanager.tf").read_text(encoding="utf-8")
    assert 'resource "terraform_data" "wiz_auth_provider"' in auth_tf
    assert 'resource "terraform_data" "wiz_auth_provider_grant"' in auth_tf

    access_tf = (TERRAFORM_DIR / "52-policies-access.tf").read_text(encoding="utf-8")
    assert "mcp_tools_per_rule = 9" in access_tf
    assert "chunklist(var.wiz_mcp_allowed_tools, local.mcp_tools_per_rule)" in access_tf
    assert "length(local.agent_tool_rules) <= 10" in access_tf
