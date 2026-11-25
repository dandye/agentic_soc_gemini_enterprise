"""Unit tests for Wizard_Agent and Wiz Remote MCP integration across ADK and Terraform."""

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
WIZARD_AGENT_DIR = REPO_ROOT / "governed_agents" / "wizard_agent"
SOC_ORCHESTRATOR_DIR = REPO_ROOT / "governed_agents" / "soc_orchestrator"
SOC_MANAGER_DIR = REPO_ROOT / "agent_soc_manager"
SOC_MANAGER_WIZ_MCP = SOC_MANAGER_DIR / "wiz_mcp.py"
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


def _load_agent_file(
    module_name: str, agent_dir: Path, filename: str, extra_env: dict[str, str]
) -> Any:
    repo_str = str(REPO_ROOT)
    parent_dir = str(agent_dir)
    added_repo = repo_str not in sys.path
    if added_repo:
        sys.path.insert(0, repo_str)
    added_parent = parent_dir not in sys.path
    if added_parent:
        sys.path.insert(0, parent_dir)
    for sibling in _SIBLING_MODULES:
        sys.modules.pop(sibling, None)
    try:
        with patch.dict(os.environ, {**_HERMETIC_ENV, **extra_env}, clear=False):
            spec = importlib.util.spec_from_file_location(
                module_name,
                agent_dir / filename,
            )
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            return module
    finally:
        if added_parent and parent_dir in sys.path:
            sys.path.remove(parent_dir)
        if added_repo and repo_str in sys.path:
            sys.path.remove(repo_str)


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


def test_enforce_wiz_readonly_callback_allows_reads_and_blocks_mutations() -> None:
    governed_wiz_mcp = _load_agent_file(
        "governed_wizard_wiz_mcp_test",
        WIZARD_AGENT_DIR,
        "wiz_mcp.py",
        {},
    )
    soc_mgr_wiz_mcp = _load_soc_manager_wiz_mcp()

    for mod in (governed_wiz_mcp, soc_mgr_wiz_mcp):
        cb = mod.enforce_wiz_readonly_callback
        assert (
            cb(SimpleNamespace(name="wiz_discover"), {"domain": "issues"}, None) is None
        )
        assert cb(SimpleNamespace(name="discover"), {"query": "ai_spm"}, None) is None
        assert (
            cb(
                SimpleNamespace(name="wiz_execute"),
                {
                    "tool": "list_issues",
                    "arguments": {"severity": ["CRITICAL", "HIGH"]},
                },
                None,
            )
            is None
        )
        assert (
            cb(
                SimpleNamespace(name="wiz_execute"),
                {
                    "tool": "get_issue",
                    "query": "query GetIssue($id: ID!) { issue(id: $id) { id status } }",
                },
                None,
            )
            is None
        )

        # Mutating actions, HTTP write verbs, GraphQL mutations, and unknown tools are blocked.
        for bad_tool, bad_args in (
            ("wiz_execute", {"tool": "update_issue", "id": "iss-1"}),
            ("wiz_execute", {"operation": "close_issue", "id": "iss-1"}),
            ("wiz_execute", {"action": "create_comment", "body": "note"}),
            ("wiz_execute", {"tool": "delete_resource", "id": "vm-1"}),
            ("wiz_execute", {"method": "DELETE", "endpoint": "/issues/1"}),
            (
                "wiz_execute",
                {"query": "mutation ResolveIssue($id: ID!) { updateIssue(id: $id) }"},
            ),
            ("wiz_admin_override", {"tool": "list_issues"}),
        ):
            blocked = cb(SimpleNamespace(name=bad_tool), bad_args, None)
            assert blocked is not None, (bad_tool, bad_args)
            assert "TOOL_ERROR:" in blocked["error"]
            assert "Read-only policy violation" in blocked["error"]


def test_threat_hunter_stays_clean_and_wizard_agent_owns_wiz_mcp() -> None:
    assert not (THREAT_HUNTER_DIR / "wiz_mcp.py").exists()
    hunter = _load_agent_file(
        "governed_threat_hunter_clean_test",
        THREAT_HUNTER_DIR,
        "agent.py",
        {},
    )
    hunter_tool_types = [type(t).__name__ for t in hunter.threat_hunter_llm.tools]
    assert "WizMcpToolset" not in hunter_tool_types
    assert len(hunter.threat_hunter_llm.before_model_callback) == 3
    assert hunter.threat_hunter_llm.before_tool_callback is not None
    assert hunter.threat_hunter_llm.after_tool_callback is not None

    fake_token = "governed-wizard-token"  # noqa: S105
    fake_client = MagicMock()
    fake_client.retrieve_credentials.return_value = SimpleNamespace(
        success=SimpleNamespace(token=fake_token)
    )
    provider = "projects/p/locations/us-central1/authProviders/agw-secops-wiz-oauth"

    with patch(
        "google.cloud.agentidentitycredentials_v1.AuthProviderCredentialsServiceClient",
        return_value=fake_client,
    ):
        wizard = _load_agent_file(
            "governed_wizard_agent_test",
            WIZARD_AGENT_DIR,
            "agent.py",
            {
                "WIZ_AUTH_PROVIDER": provider,
                "WIZ_MCP_URL": "https://mcp.app.wiz.io",
            },
        )
        assert wizard.APP_NAME == "wizard_agent"
        assert wizard.agent_card.name == "wizard_agent"
        assert wizard.agent_card.version == "1.0.0"
        assert "secops-wiz-cloud-security" in wizard.INSTRUCTION
        assert "YARA-L 2.0" in wizard.INSTRUCTION
        assert len(wizard.wizard_llm.tools) == 1
        toolset = wizard.wizard_llm.tools[0]
        assert type(toolset).__name__ == "WizMcpToolset"
        assert toolset._connection_params.url == "https://mcp.app.wiz.io/"
        assert toolset.tool_name_prefix == "wiz_"
        assert toolset.tool_filter == ["discover", "execute"]
        assert toolset._header_provider(None) == {
            "Authorization": f"Bearer {fake_token}"
        }
        assert wizard.wizard_llm.before_model_callback is not None
        assert wizard.wizard_llm.before_tool_callback is not None
        assert wizard.wizard_llm.after_tool_callback is not None

    card_json = json.loads(
        (TERRAFORM_DIR / "agentcards" / "wizard_agent.json").read_text(encoding="utf-8")
    )
    assert card_json["name"] == "wizard_agent"
    assert len(card_json["skills"]) == 2


def test_soc_orchestrator_opt_in_wizard_agent_a2a_wiring() -> None:
    base_env = {
        "CTI_RESEARCHER_URL": "https://example.invalid/cti/a2a",
        "THREAT_HUNTER_URL": "https://example.invalid/hunter/a2a",
        "DETECTION_ENGINEER_URL": "https://example.invalid/de/a2a",
        "TIER2_RESPONDER_URL": "https://example.invalid/tier2/a2a",
        "WIZARD_AGENT_CARD_URL": "",
        "WIZARD_AGENT_URL": "",
    }
    orch_default = _load_agent_file(
        "soc_orchestrator_wiz_unset_test",
        SOC_ORCHESTRATOR_DIR,
        "agent.py",
        base_env,
    )
    default_peers = [t.agent.name for t in orch_default.orchestrator_llm.tools]
    assert default_peers == [
        "CTI_Researcher",
        "Threat_Hunter",
        "Detection_Engineer",
        "Tier2_Responder",
    ]
    assert "needs_wiz_cloud" not in orch_default._PREFLIGHT_QUESTIONS

    orch_wiz = _load_agent_file(
        "soc_orchestrator_wiz_set_test",
        SOC_ORCHESTRATOR_DIR,
        "agent.py",
        {**base_env, "WIZARD_AGENT_CARD_URL": "https://example.invalid/wizard/a2a"},
    )
    wiz_peers = [t.agent.name for t in orch_wiz.orchestrator_llm.tools]
    assert wiz_peers == [
        "CTI_Researcher",
        "Threat_Hunter",
        "Detection_Engineer",
        "Tier2_Responder",
        "Wizard_Agent",
    ]
    assert "needs_wiz_cloud" in orch_wiz._PREFLIGHT_QUESTIONS
    target = orch_wiz._short_circuit_target(
        {
            "enabled": True,
            "answers": {
                "needs_cti": {"noul": 0.05},
                "needs_threat_hunt": {"noul": 0.08},
                "needs_detection_eng": {"noul": 0.02},
                "needs_tier2_response": {"noul": 0.01},
                "needs_wiz_cloud": {"noul": 0.96},
                "workflow_mode": {"choice": "single_specialist", "confidence": 0.95},
            },
        }
    )
    assert target == "Wizard_Agent"


def test_agent_soc_manager_wizard_agent_and_delegate_support(tmp_path: Path) -> None:
    sa_file = tmp_path / "dummy_chronicle_sa.json"
    sa_file.write_text('{"type": "service_account"}', encoding="utf-8")
    empty_cache = tmp_path / "no_wiz_tokens.json"

    repo_str = str(REPO_ROOT)
    added = repo_str not in sys.path
    if added:
        sys.path.insert(0, repo_str)
    try:
        base_mgr_env = {
            **_HERMETIC_ENV,
            "GCP_PROJECT_ID": "example-secops-project",
            "CHRONICLE_PROJECT_ID": "example-secops-project",
            "CHRONICLE_CUSTOMER_ID": "a1b2c3d4-e5f6-4321-abcd-ef1234567890",
            "CHRONICLE_SERVICE_ACCOUNT_PATH": str(sa_file),
            "SKIP_VERTEXAI_INIT": "True",
            "ALLOYDB_GROUNDING_ENABLED": "False",
            "ELASTICSEARCH_GROUNDING_ENABLED": "False",
            "RAG_CORPUS_ID": "",
            "WIZ_MCP_ENABLED": "false",
            "WIZ_AUTH_PROVIDER": "",
            "WIZ_MCP_BEARER_TOKEN": "",
            "WIZ_ACCESS_TOKEN": "",
            "WIZ_OAUTH_TOKEN_CACHE": str(empty_cache),
            "WIZARD_AGENT_RESOURCE_NAME": "",
        }
        with (
            patch.dict(os.environ, base_mgr_env, clear=False),
            patch(
                "google.cloud.secretmanager.SecretManagerServiceClient",
                side_effect=RuntimeError("hermetic unit test"),
            ),
        ):
            import agent_soc_manager.agent as soc_mgr

            orch_off = soc_mgr.create_agent()
            assert [a.name for a in orch_off.sub_agents] == ["tier1_analyst"]
            off_tool_names = [
                getattr(t, "__name__", getattr(t, "name", "")) for t in orch_off.tools
            ]
            assert "delegate_to_wizard_agent" not in off_tool_names

        with (
            patch.dict(
                os.environ,
                {
                    **base_mgr_env,
                    "WIZ_MCP_ENABLED": "true",
                    "WIZ_MCP_BEARER_TOKEN": "test-wiz-token",
                },
                clear=False,
            ),
            patch(
                "google.cloud.secretmanager.SecretManagerServiceClient",
                side_effect=RuntimeError("hermetic unit test"),
            ),
        ):
            orch_on = soc_mgr.create_agent()
            assert [a.name for a in orch_on.sub_agents] == [
                "tier1_analyst",
                "wizard_agent",
            ]
            on_tool_names = [
                getattr(t, "__name__", getattr(t, "name", "")) for t in orch_on.tools
            ]
            assert "delegate_to_wizard_agent" in on_tool_names
    finally:
        if added and repo_str in sys.path:
            sys.path.remove(repo_str)


def test_terraform_wizard_agent_opt_in_and_dedicated_wiz_policy() -> None:
    variables_tf = (TERRAFORM_DIR / "variables.tf").read_text(encoding="utf-8")
    assert 'variable "enable_wiz_mcp"' in variables_tf
    assert "default     = false" in variables_tf

    package_tf = (TERRAFORM_DIR / "40-package.tf").read_text(encoding="utf-8")
    assert '"wizard_agent"' in package_tf
    assert (
        "agent_names = var.enable_wiz_mcp ? local.all_agent_names : local.core_agent_names"
        in package_tf
    )

    agents_tf = (TERRAFORM_DIR / "41-agents.tf").read_text(encoding="utf-8")
    assert 'resource "google_vertex_ai_reasoning_engine" "wizard_agent"' in agents_tf
    assert 'display_name    = "${var.resource_prefix}-wizard-agent"' in agents_tf
    assert "WIZARD_AGENT_CARD_URL" in agents_tf

    registry_tf = (TERRAFORM_DIR / "11-registry-mcp.tf").read_text(encoding="utf-8")
    assert 'resource "google_agent_registry_service" "wiz_mcp"' in registry_tf
    assert "count = var.enable_wiz_mcp ? 1 : 0" in registry_tf

    auth_tf = (TERRAFORM_DIR / "20-authmanager.tf").read_text(encoding="utf-8")
    assert 'resource "terraform_data" "wiz_auth_provider"' in auth_tf
    assert 'resource "terraform_data" "wiz_auth_provider_grant"' in auth_tf
    assert 'local.agent_principals["wizard_agent"]' in auth_tf

    a2a_tf = (TERRAFORM_DIR / "51-policies-a2a.tf").read_text(encoding="utf-8")
    assert 'data "google_agent_registry_agent" "wizard_agent"' in a2a_tf
    assert (
        'resource "google_vertex_ai_reasoning_engine_iam_member" "orch_to_wizard_agent"'
        in a2a_tf
    )

    access_tf = (TERRAFORM_DIR / "52-policies-access.tf").read_text(encoding="utf-8")
    assert "mcp_tools_per_rule = 9" in access_tf
    assert "threat_hunter_wiz_mcp" not in access_tf
    assert "orch_to_wizard_agent" in access_tf
    assert "length(local.agent_tool_rules) <= 10" in access_tf

    wiz_policy_tf = (TERRAFORM_DIR / "52b-policies-wiz.tf").read_text(encoding="utf-8")
    assert (
        'wiz_tools_access_policy_id  = "${var.resource_prefix}-wiz-tools"'
        in wiz_policy_tf
    )
    assert 'resource "google_iam_project_access_policy" "wiz_tools"' in wiz_policy_tf
    assert "count = var.enable_wiz_mcp ? 1 : 0" in wiz_policy_tf
    assert (
        "chunklist(var.wiz_mcp_allowed_tools, local.mcp_tools_per_rule)"
        in wiz_policy_tf
    )
    assert "length(local.wiz_mcp_rules) <= 10" in wiz_policy_tf
