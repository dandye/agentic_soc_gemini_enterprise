"""Unit tests for the five governed SecOps ADK A2A agents and governance assets."""

from __future__ import annotations

import asyncio
import functools
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch


REPO_ROOT = Path(__file__).resolve().parent.parent
GOVERNED_AGENTS_DIR = REPO_ROOT / "governed_agents"
TERRAFORM_DIR = REPO_ROOT / "terraform"
GOVERNANCE_SCRIPTS_DIR = REPO_ROOT / "scripts" / "governance"


# Importing a governed agent constructs its A2aAgent, which calls
# aiplatform.init(). That resolves a project from the environment and then
# google.auth.default() for credentials, so a hermetic CI runner needs both:
# a placeholder project and an Application Default Credentials file. An
# authorized_user ADC with placeholder fields loads without any key material
# and is never exchanged for a token because no test makes a network call.
_HERMETIC_PROJECT = "example-secops-project"


def _placeholder_adc_path() -> str:
    """Returns the real ADC path if one is configured, else writes a placeholder."""
    configured = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if configured:
        return configured
    path = Path(tempfile.gettempdir()) / "governed_agents_placeholder_adc.json"
    path.write_text(
        json.dumps(
            {
                "type": "authorized_user",
                "client_id": "placeholder.apps.googleusercontent.com",
                "client_secret": "placeholder",
                "refresh_token": "placeholder",
                "quota_project_id": _HERMETIC_PROJECT,
            }
        )
    )
    return str(path)


_HERMETIC_ENV = {
    "GOOGLE_CLOUD_PROJECT": _HERMETIC_PROJECT,
    "GOOGLE_CLOUD_LOCATION": "us-central1",
    "GOOGLE_GENAI_USE_VERTEXAI": "TRUE",
    "GOOGLE_APPLICATION_CREDENTIALS": _placeholder_adc_path(),
}


_AGENT_SIBLING_MODULES = (
    "decision_client",
    "detection_tools",
    "gti_tools",
    "response_tools",
    "secops_mcp",
    "triage_tools",
)


def _load_module(
    module_name: str, file_path: Path, env_overrides: dict[str, str]
) -> Any:
    """Loads a file-backed module under temporary environment variables."""
    parent_dir = str(file_path.parent)
    added_path = parent_dir not in sys.path
    if added_path:
        sys.path.insert(0, parent_dir)
    if file_path.parent.parent == GOVERNED_AGENTS_DIR:
        for sibling in _AGENT_SIBLING_MODULES:
            sys.modules.pop(sibling, None)
    try:
        with patch.dict(os.environ, {**_HERMETIC_ENV, **env_overrides}, clear=False):
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            return module
    finally:
        if added_path and parent_dir in sys.path:
            sys.path.remove(parent_dir)


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
            for helper_mod in (
                "decision_client",
                "detection_tools",
                "gti_tools",
                "response_tools",
                "secops_mcp",
                "triage_tools",
            ):
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


def test_secops_mcp_recovers_the_gateway_http_status_behind_the_generic_mcp_error() -> (
    None
):
    """A gateway 403 survives the MCP SDK's generic error so the orchestrator can name it.

    mcp 2.x reports any non-2xx, non-JSON-RPC reply as "Server returned an error
    response" and ADK wraps that as {"error": "MCP tool execution failed: ..."}.
    The response hook records the real status so TOOL_ERROR carries it.
    """
    mod = _load_module(
        "test_secops_mcp_http_status",
        GOVERNED_AGENTS_DIR / "threat_hunter" / "secops_mcp.py",
        {"CHRONICLE_PROJECT_ID": "example-proj"},
    )
    generic = {"error": "MCP tool execution failed: Server returned an error response"}

    # The factory installs a response hook on the real client type ADK uses.
    client = mod.create_chronicle_http_client()
    assert mod._record_non_2xx in client.event_hooks["response"]

    # Nothing recorded yet: the generic text passes through unchanged.
    assert (
        mod._extract_tool_error("list_feeds", generic)
        == "TOOL_ERROR: list_feeds -- MCP tool execution failed: Server returned an error response"
    )

    class _Reply:
        status_code = 403
        reason_phrase = "Forbidden"
        url = "https://chronicle.example/mcp"

        async def aread(self) -> bytes:
            return b'{"error":{"code":403,"message":"Error: Security Policy Violation","status":"PERMISSION_DENIED"}}'

    asyncio.run(mod._record_non_2xx(_Reply()))
    text = mod._extract_tool_error("list_feeds", generic)
    assert text is not None
    assert text.startswith(
        "TOOL_ERROR: list_feeds -- MCP tool execution failed: HTTP 403 Forbidden: "
    )
    assert "Security Policy Violation" in text

    # Consumed once: a later unrelated generic error does not inherit the 403.
    assert "403" not in (mod._extract_tool_error("list_feeds", generic) or "")

    # 2xx replies are never recorded; non-generic errors are never rewritten.
    class _Ok(_Reply):
        status_code = 200

    asyncio.run(mod._record_non_2xx(_Ok()))
    assert mod._take_recent_http_error() is None
    asyncio.run(mod._record_non_2xx(_Reply()))
    assert mod._extract_tool_error("list_feeds", {"error": "quota exceeded"}) == (
        "TOOL_ERROR: list_feeds -- quota exceeded"
    )
    assert (
        mod._take_recent_http_error() is not None
    )  # left untouched for the generic path

    # The orchestrator now sees a real denial signal on the gateway path.
    orchestrator = _load_orchestrator()
    matched = orchestrator._tool_denial_match(text)
    assert matched is not None
    assert matched[0] == "list_feeds"
    assert matched[1].startswith("MCP tool execution failed: HTTP 403 Forbidden")
    assert "Security Policy Violation" in matched[1]


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


_ORCHESTRATOR_ENV = {
    "CTI_RESEARCHER_URL": "https://example.invalid/cti/a2a",
    "THREAT_HUNTER_URL": "https://example.invalid/hunter/a2a",
    "DETECTION_ENGINEER_URL": "https://example.invalid/de/a2a",
    "TIER2_RESPONDER_URL": "https://example.invalid/tier2/a2a",
    "MODEL_ARMOR_CONTROL": "agw-secops-ma-content-authz",
}

# A refused Chronicle MCP call as the specialist's callback rewrites it: the
# gateway's own 403 text behind the code-written TOOL_ERROR marker.
_OBSERVED_TOOL_ERROR = "TOOL_ERROR: delete_feed -- HTTP 403 Forbidden: permission denied by IAP access policy"

# A Semantic Governance denial as the user receives it: the judge's rationale,
# substituted for the reply, arriving as an ordinary HTTP 200. There is no
# banner or detector for this, so the text must pass through whole.
_OBSERVED_SGP_RATIONALE = (
    "I am sorry, but I cannot proceed with that request. Reason: The suggested "
    "action isolates 'DC-01', which is explicitly forbidden by the global "
    "constraint 'Tier-2 responder -- no Tier-0 domain controllers'. Therefore, "
    "this action must be denied."
)

# A refusal the model authored itself: nothing in the gateway backs it, and the
# orchestrator's Python must not dress it up as a policy block.
_SELF_AUTHORED_REFUSAL = (
    "I cannot comply. A global constraint in my instructions prohibits "
    "isolating domain controllers, so this must be denied."
)

# Ordinary turns that must never raise a banner, including refusal phrasing,
# the words "denied" / "not allowed", and a model echo of a 403 in prose.
_NON_GOVERNANCE_REPLIES = (
    "Chronicle returned 3 alerts for WKSTN-FIN-042 in the last 24 hours.",
    "I could not find any UDM events matching that hash.",
    "I am sorry, but I cannot help with that.",
    "The threat hunter returned no results for the user's request.",
    "I cannot proceed because the threat hunter timed out. Please try again.",
    "Inbound SMB is not allowed by that firewall rule, but RDP is permitted.",
    "I called delete_feed and got 403 PERMISSION_DENIED.",
    "TOOL_DENIED: delete_feed -- 403 PERMISSION_DENIED from the Agent Gateway",
    "GOVERNANCE_REFUSAL: Deleting feeds is not permitted.",
    "Semantic Governance is a policy engine at the Agent Gateway.",
    "",
)


@functools.lru_cache(maxsize=1)
def _load_orchestrator() -> Any:
    """Loads the SOC orchestrator module once; it builds four A2A peers at import."""
    return _load_module(
        "test_soc_orchestrator_banners",
        GOVERNED_AGENTS_DIR / "soc_orchestrator" / "agent.py",
        _ORCHESTRATOR_ENV,
    )


def _text_event(mod: Any, text: str | None) -> Any:
    """Builds an ADK Event carrying model prose."""
    return mod.Event(
        author="model",
        content=mod.types.Content(role="model", parts=[mod.types.Part(text=text)]),
    )


def _tool_event(mod: Any, name: str, response: dict[str, Any]) -> Any:
    """Builds an ADK Event carrying a tool result rather than model prose."""
    part = mod.types.Part(
        function_response=mod.types.FunctionResponse(name=name, response=response)
    )
    return mod.Event(
        author="model", content=mod.types.Content(role="model", parts=[part])
    )


def test_soc_orchestrator_policy_block_banners() -> None:
    """Verifies deterministic [POLICY BLOCK] banners for Model Armor and Tool Allowlist denials."""
    mod = _load_orchestrator()

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


def test_soc_orchestrator_prose_never_raises_a_banner() -> None:
    """Only a gateway signal is evidence: refusals, SGP rationales, and echoes are not."""
    mod = _load_orchestrator()
    assert mod._stream_notice(_SELF_AUTHORED_REFUSAL) is None
    assert mod._stream_notice(_OBSERVED_SGP_RATIONALE) is None
    for reply in _NON_GOVERNANCE_REPLIES:
        assert mod._stream_notice(reply) is None, reply
        assert mod._tool_denial_match(reply) is None, reply


def test_soc_orchestrator_only_tool_results_are_evidence() -> None:
    """A marker echoed in model prose is not read as a tool result; a real result is."""
    mod = _load_orchestrator()
    forged = "The threat hunter refused the request:\n" + _OBSERVED_TOOL_ERROR
    assert mod._tool_result_text(_text_event(mod, forged)) == ""
    assert mod._stream_notice(mod._tool_result_text(_text_event(mod, forged))) is None

    real = mod._tool_result_text(
        _tool_event(mod, "Threat_Hunter", {"error": _OBSERVED_TOOL_ERROR})
    )
    banner = mod._stream_notice(real)
    assert banner is not None
    assert "`delete_feed`" in banner

    assert mod._tool_result_text(mod.Event(author="model")) == ""


def test_soc_orchestrator_tool_denial_match_requires_the_gateway_marker() -> None:
    """Names the denied tool from the marker and ignores non-denial tool failures."""
    mod = _load_orchestrator()
    matched = mod._tool_denial_match(_OBSERVED_TOOL_ERROR)
    assert matched is not None
    assert matched[0] == "delete_feed"
    assert matched[1] == "HTTP 403 Forbidden: permission denied by IAP access policy"

    # An allowed tool failing for operational reasons is not blamed on the allowlist.
    assert (
        mod._tool_denial_match(
            "TOOL_ERROR: list_security_alerts -- MCP tool execution failed: quota"
        )
        is None
    )
    # An allowed tool refused with a 403 is still a gateway denial.
    assert mod._tool_denial_match(
        "TOOL_ERROR: list_security_alerts -- HTTP 403 Forbidden"
    ) == ("list_security_alerts", "HTTP 403 Forbidden")
    armor = (
        '{"error":{"code":403,"message":"Error: Dangerous content not allowed",'
        '"status":"PERMISSION_DENIED"}}'
    )
    assert mod._tool_denial_match(armor) is None
    assert mod._stream_notice(armor) is None


def test_soc_orchestrator_denied_list_membership_is_not_evidence() -> None:
    """An operational failure on a denied-list tool is not dressed as an allowlist block.

    Regression for the earlier rule `tool in DENIED_MCP_TOOLS or <403 text>`: a
    quota or 5xx error on `delete_feed` raised a TOOL ALLOWLIST banner even
    though the gateway never issued a verdict.
    """
    mod = _load_orchestrator()
    assert "delete_feed" in mod.DENIED_MCP_TOOLS
    for operational in (
        "TOOL_ERROR: delete_feed -- MCP tool execution failed: quota exceeded",
        "TOOL_ERROR: delete_feed -- upstream 503 Service Unavailable",
        "TOOL_ERROR: delete_feed -- request timed out after 30s",
    ):
        assert mod._tool_denial_match(operational) is None, operational
        assert mod._stream_notice(operational) is None, operational
    # The word "denied" must be a whole word, not a substring of something else.
    assert (
        mod._tool_denial_match("TOOL_ERROR: delete_feed -- field undeniedState invalid")
        is None
    )
    # The real gateway verdict on the same tool is still recognised.
    assert mod._tool_denial_match(
        "TOOL_ERROR: delete_feed -- HTTP 403 Forbidden: access denied by policy"
    ) == ("delete_feed", "HTTP 403 Forbidden: access denied by policy")


def test_soc_orchestrator_tool_banner_lists_the_denied_tools() -> None:
    """The allowlist banner renders DENIED_MCP_TOOLS so the reader sees the policy, not just one tool."""
    mod = _load_orchestrator()
    banner = mod._stream_notice(_OBSERVED_TOOL_ERROR)
    assert banner is not None
    for name in mod.DENIED_MCP_TOOLS:
        assert f"- `{name}`" in banner, name
    assert "deliberately kept off every specialist's allowlist" in banner

    # The list follows the environment, like the rest of the tool configuration.
    custom = _load_module(
        "test_soc_orchestrator_custom_denied",
        GOVERNED_AGENTS_DIR / "soc_orchestrator" / "agent.py",
        {**_ORCHESTRATOR_ENV, "DENIED_MCP_TOOLS": "alpha_tool, ,beta_tool"},
    )
    custom_banner = custom._stream_notice(
        "TOOL_ERROR: alpha_tool -- HTTP 403 Forbidden"
    )
    assert custom_banner is not None
    assert "- `alpha_tool`" in custom_banner
    assert "- `beta_tool`" in custom_banner
    assert "- `delete_feed`" not in custom_banner


def test_soc_orchestrator_tool_banner_quotes_the_specialist_error() -> None:
    """The tool banner names the tool and quotes the gateway's own error text."""
    mod = _load_orchestrator()
    banner = mod._stream_notice(_OBSERVED_TOOL_ERROR)
    assert banner is not None
    assert "`delete_feed`" in banner
    assert "permission denied by IAP access policy" in banner
    assert "TOOL ALLOWLIST" in banner.split("\n", 1)[0]


def test_soc_orchestrator_banners_share_one_family() -> None:
    """Both banners share the header, REFUSED line, named control, and DENY verdict."""
    mod = _load_orchestrator()
    armor_exc = RuntimeError(
        '{"error":{"code":403,"message":"Error: Dangerous content not allowed",'
        '"status":"PERMISSION_DENIED"}}'
    )
    armor_banner = mod._notice_event(armor_exc).content.parts[0].text
    family = {
        "MODEL ARMOR": armor_banner,
        "TOOL ALLOWLIST": mod._stream_notice(_OBSERVED_TOOL_ERROR),
    }
    for control, text in family.items():
        header = text.split("\n", 1)[0]
        assert header.startswith("**[POLICY BLOCK] Blocked by AI security policy -- ")
        assert control in header
        assert "**REFUSED at the Agent Gateway." in text
        assert "**Verdict:** `DENY`" in text
        assert "**Control:** `" in text

    # The Model Armor banner quotes the filter verdict with the "Error:" prefix tidied.
    assert "> Dangerous content not allowed" in armor_banner
    assert "Error: Dangerous content" not in armor_banner
    assert "`agw-secops-ma-content-authz`" in armor_banner


def test_soc_orchestrator_operational_errors_are_not_policy_blocks() -> None:
    """A non-policy exception yields the RUNTIME FAULT notice, never a policy banner."""
    mod = _load_orchestrator()
    text = (
        mod._notice_event(TimeoutError("specialist did not answer"))
        .content.parts[0]
        .text
    )
    assert text.startswith("**[RUNTIME FAULT]")
    assert "TimeoutError: specialist did not answer" in text
    assert "[POLICY BLOCK]" not in text
    assert "Verdict" not in text


def test_soc_orchestrator_strip_markers_removes_only_the_marker_line() -> None:
    """Under a banner the marker line goes; quotes, rationales, and empty parts survive."""
    mod = _load_orchestrator()

    event = _text_event(mod, _OBSERVED_SGP_RATIONALE)
    mod._strip_markers(event)
    assert event.content.parts[0].text == _OBSERVED_SGP_RATIONALE

    event = _text_event(mod, "Chronicle returned 3 alerts.")
    mod._strip_markers(event)
    assert event.content.parts[0].text == "Chronicle returned 3 alerts."

    event = _text_event(mod, None)
    mod._strip_markers(event)
    assert event.content.parts[0].text is None

    event = _text_event(mod, _OBSERVED_TOOL_ERROR + "\nThe gateway refused the call.")
    mod._strip_markers(event)
    assert event.content.parts[0].text == "The gateway refused the call."

    event = _text_event(mod, "The threat hunter refused: " + _OBSERVED_TOOL_ERROR)
    mod._strip_markers(event)
    assert event.content.parts[0].text == ""

    event = _text_event(
        mod,
        "Here is what happened.\n"
        "The threat hunter said: " + _OBSERVED_TOOL_ERROR + "\n"
        "Nothing else was tried.",
    )
    mod._strip_markers(event)
    assert (
        event.content.parts[0].text
        == "Here is what happened.\n\nNothing else was tried."
    )


def test_soc_orchestrator_denied_turn_is_banner_then_events_with_no_retry() -> None:
    """A denied tool result yields exactly one banner, strips echoes, and never re-runs."""
    mod = _load_orchestrator()
    stream = [
        _tool_event(mod, "Threat_Hunter", {"error": _OBSERVED_TOOL_ERROR}),
        _text_event(mod, "The threat hunter said: " + _OBSERVED_TOOL_ERROR),
        _tool_event(mod, "Threat_Hunter", {"error": _OBSERVED_TOOL_ERROR}),
    ]
    runs = 0

    async def fake_run_async(**_: Any) -> Any:
        nonlocal runs
        runs += 1
        for event in stream:
            yield event

    runner = SimpleNamespace(run_async=fake_run_async)

    async def collect() -> list[Any]:
        return [event async for event in mod._run_and_report(runner, session_id="s1")]

    events = asyncio.run(collect())
    assert runs == 1
    assert len(events) == len(stream) + 1
    banners = [
        event
        for event in events
        if event.author == mod.APP_NAME
        and "[POLICY BLOCK]" in (event.content.parts[0].text or "")
    ]
    assert len(banners) == 1
    assert events[0] is banners[0]
    assert events[1] is stream[0]
    assert events[2].content.parts[0].text == ""


def test_soc_orchestrator_governed_runner_banners_the_a2a_path() -> None:
    """The A2A executor calls runner.run_async directly, so the runner itself must govern.

    Regression for the gap where only stream_query (via _run_and_report) emitted
    the banner while A2A callers received the raw TOOL_ERROR text.
    """
    mod = _load_orchestrator()
    assert isinstance(mod._get_runner(), mod._GovernedRunner)
    stream = [
        _tool_event(mod, "Threat_Hunter", {"error": _OBSERVED_TOOL_ERROR}),
        _text_event(mod, "The threat hunter said: " + _OBSERVED_TOOL_ERROR),
    ]

    class _FakeBaseRunner:

        def __init__(self) -> None:
            self.calls = 0

        async def run_async(self, *_: Any, **__: Any) -> Any:
            self.calls += 1
            for event in stream:
                yield event

    # Build a _GovernedRunner without touching Runner.__init__ (no services needed).
    governed = mod._GovernedRunner.__new__(mod._GovernedRunner)
    base = _FakeBaseRunner()
    with patch.object(
        mod.Runner, "run_async", lambda self, *a, **k: base.run_async(*a, **k)
    ):

        async def via_a2a_path() -> list[Any]:
            # Exactly what A2aAgentExecutor does: call run_async on the runner.
            return [event async for event in governed.run_async(session_id="a2a")]

        async def via_stream_query_path() -> list[Any]:
            return [
                event async for event in mod._run_and_report(governed, session_id="sq")
            ]

        a2a_events = asyncio.run(via_a2a_path())
        sq_events = asyncio.run(via_stream_query_path())

    assert base.calls == 2
    for events in (a2a_events, sq_events):
        banners = [
            e
            for e in events
            if e.author == mod.APP_NAME
            and "[POLICY BLOCK]" in (e.content.parts[0].text or "")
        ]
        assert (
            len(banners) == 1
        ), "exactly one banner, and not doubled on the stream_query path"
        assert events[0] is banners[0]
        assert events[-1].content.parts[0].text == ""  # relayed marker stripped


def test_soc_orchestrator_tool_banner_detail_has_no_dangling_json_tail() -> None:
    """The quoted reason stops before the JSON envelope the specialist relayed."""
    mod = _load_orchestrator()
    observed = (
        "TOOL_ERROR: list_feeds -- MCP tool execution failed: HTTP 403 Forbidden: "
        'Egress request is not authorized."}'
    )
    matched = mod._tool_denial_match(observed)
    assert matched == (
        "list_feeds",
        "MCP tool execution failed: HTTP 403 Forbidden: Egress request is not authorized.",
    )
    banner = mod._stream_notice(observed)
    assert banner is not None
    assert '"}' not in banner
    assert "Egress request is not authorized." in banner

    # A stream-serialised envelope with nested braces and a long body is bounded and clean.
    long_body = "x" * 500
    serialised = (
        '{"error": "TOOL_ERROR: delete_feed -- HTTP 403 Forbidden: access denied '
        + long_body
        + '"}}'
    )
    tool, detail = mod._tool_denial_match(serialised)
    assert tool == "delete_feed"
    assert len(detail) <= 240
    assert not detail.endswith(('"', "}", "]", ","))

    # Plain detail without any envelope is untouched.
    assert mod._tidy_detail(
        "HTTP 403 Forbidden: permission denied by IAP access policy"
    ) == ("HTTP 403 Forbidden: permission denied by IAP access policy")


def test_soc_orchestrator_tool_list_comes_from_the_environment() -> None:
    """Blank allowlist entries are dropped and an absent var falls back to its default."""
    mod = _load_orchestrator()
    with patch.dict(os.environ, {"_NOTICE_TEST_TOOLS": ",delete_feed, create_rule ,"}):
        assert mod._tool_list("_NOTICE_TEST_TOOLS", "") == (
            "delete_feed",
            "create_rule",
        )
    os.environ.pop("_NOTICE_TEST_ABSENT", None)
    assert mod._tool_list("_NOTICE_TEST_ABSENT", "a,b") == ("a", "b")
    assert "delete_feed" in mod.DENIED_MCP_TOOLS


def test_smoke_test_case_selection_supports_prefixes_and_short_tokens() -> None:
    """`smoke_test.py --case` accepts short tokens, case_id prefixes, and full IDs."""
    smoke = _load_module(
        "test_smoke_test_mod", GOVERNANCE_SCRIPTS_DIR / "smoke_test.py", {}
    )
    all_ids = [c.case_id for c in smoke._select_cases(None)]
    assert len(all_ids) == 6
    assert "case_3b_model_armor_capability_enumeration" in all_ids

    assert [c.case_id for c in smoke._select_cases("")] == all_ids
    assert [c.case_id for c in smoke._select_cases("4a")] == [
        "case_4a_sgp_crown_jewel_deny"
    ]
    assert [c.case_id for c in smoke._select_cases("case_4a")] == [
        "case_4a_sgp_crown_jewel_deny"
    ]
    assert [c.case_id for c in smoke._select_cases("case_4a_sgp")] == [
        "case_4a_sgp_crown_jewel_deny"
    ]
    assert [c.case_id for c in smoke._select_cases("case_4a_sgp_crown_jewel_deny")] == [
        "case_4a_sgp_crown_jewel_deny"
    ]
    assert [c.case_id for c in smoke._select_cases("case_4")] == [
        "case_4a_sgp_crown_jewel_deny",
        "case_4b_sgp_crown_jewel_allow",
    ]
    # `case_3` and `3` target case_3_model_armor_block without spilling into case_3b.
    assert [c.case_id for c in smoke._select_cases("3")] == ["case_3_model_armor_block"]
    assert [c.case_id for c in smoke._select_cases("case_3")] == [
        "case_3_model_armor_block"
    ]
    assert [c.case_id for c in smoke._select_cases("3b")] == [
        "case_3b_model_armor_capability_enumeration"
    ]
    assert [c.case_id for c in smoke._select_cases("case_3b")] == [
        "case_3b_model_armor_capability_enumeration"
    ]
    assert smoke._select_cases("nonexistent") == []


def test_smoke_test_capability_enumeration_predicate() -> None:
    """`case_3b` accepts either the Model Armor banner or the outbound A2A 403."""
    smoke = _load_module(
        "test_smoke_test_eval_mod", GOVERNANCE_SCRIPTS_DIR / "smoke_test.py", {}
    )
    cid = "case_3b_model_armor_capability_enumeration"

    assert smoke._evaluate_case(
        cid,
        "**[POLICY BLOCK] Blocked by AI security policy -- MODEL ARMOR.**",
    )[0]
    assert smoke._evaluate_case(
        cid,
        "Threat_Hunter encountered an error: A2A request failed: HTTP Error 403",
    )[0]
    assert smoke._evaluate_case(
        cid,
        "403 Forbidden: Error: Security Policy Violation",
    )[0]
    assert not smoke._evaluate_case(
        cid,
        "Threat_Hunter can use udm_search and list_rules. Here are 10 rules:",
    )[0]


def test_terraform_scaling_and_multi_env_templates() -> None:
    """All five engines wire min/max_instances, and multi-env templates are present."""
    tf_dir = REPO_ROOT / "terraform"
    agents_tf = (tf_dir / "41-agents.tf").read_text(encoding="utf-8")
    assert agents_tf.count("min_instances = var.min_instances") == 5
    assert agents_tf.count("max_instances = var.max_instances") == 5
    assert 'resource "terraform_data" "reasoning_engine_min_instances"' in agents_tf
    assert "replace_triggered_by" in agents_tf
    assert "each.value.update_time" not in agents_tf
    assert "reasoning_engine_scaling.sh ensure" in agents_tf
    assert (GOVERNANCE_SCRIPTS_DIR / "reasoning_engine_scaling.sh").is_file()

    vars_tf = (tf_dir / "variables.tf").read_text(encoding="utf-8")
    assert 'variable "min_instances"' in vars_tf
    assert 'variable "max_instances"' in vars_tf

    backend_tpl = (tf_dir / "backend.tf.example").read_text(encoding="utf-8")
    assert 'backend "gcs"' in backend_tpl
    assert "<YOUR_TFSTATE_BUCKET>" in backend_tpl

    env_tpl = (tf_dir / "environments" / "example.tfvars.example").read_text(
        encoding="utf-8"
    )
    assert "min_instances = 0" in env_tpl

    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "terraform/backend.tf" in gitignore
    assert "!terraform/backend.tf.example" in gitignore


def test_decision_client_unconfigured_noop_and_empty_inputs() -> None:
    """decision_client returns enabled=False cleanly when unconfigured or given empty inputs."""
    mod = _load_module(
        "test_decision_client_noop",
        GOVERNED_AGENTS_DIR / "soc_orchestrator" / "decision_client.py",
        {},
    )
    clean_env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"GEMINI_API_KEY", "GEMINI_AUTH_PROVIDER"}
    }
    with patch.dict(os.environ, clean_env, clear=True):
        res = mod.evaluate_decisions(
            "Investigate suspicious beacon to 198.51.100.10",
            {"needs_cti": mod.noul_question("Needs CTI?")},
        )
        assert res["enabled"] is False
        assert res["answers"] == {}

        async_res = asyncio.run(
            mod.aevaluate_decisions(
                "Investigate suspicious beacon to 198.51.100.10",
                {"needs_cti": mod.noul_question("Needs CTI?")},
            )
        )
        assert async_res["enabled"] is False
        assert async_res["answers"] == {}

    assert (
        mod.evaluate_decisions("", {"q": mod.noul_question("Q?")})["enabled"] is False
    )
    assert mod.evaluate_decisions("hello", {})["enabled"] is False


def test_decision_client_api_key_request_and_score_shift() -> None:
    """Verifies GEMINI_API_KEY auth, noul/choice/score payloads, and 0-indexed -> 1-5 shift."""
    mod = _load_module(
        "test_decision_client_apikey",
        GOVERNED_AGENTS_DIR / "soc_orchestrator" / "decision_client.py",
        {},
    )
    fake_key = "AIzaSyFakeHermeticDecisionKey"  # noqa: S105
    questions = {
        "needs_cti": mod.noul_question("Does it need CTI?"),
        "workflow_mode": mod.choice_question(
            "Select mode", {"single_specialist": "Single", "other": "Other"}
        ),
        "urgency": mod.score_question("Rate urgency", ["L0", "L1", "L2", "L3", "L4"]),
    }
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "answers": {
            "needs_cti": {"type": "noul", "noul": 0.92, "confidence": 0.88},
            "workflow_mode": {
                "type": "choice",
                "choice": "single_specialist",
                "confidence": 0.91,
                "probabilities": {"single_specialist": 0.91, "other": 0.09},
            },
            "urgency": {
                "type": "score",
                "score": 3.0,
                "confidence": 0.84,
                "probabilities": {"0": 0.01, "1": 0.02, "2": 0.1, "3": 0.84, "4": 0.03},
            },
        },
        "usage": {"inputTokens": 120},
    }

    env_patch = {k: v for k, v in os.environ.items() if k != "GEMINI_AUTH_PROVIDER"}
    env_patch["GEMINI_API_KEY"] = fake_key
    with (
        patch.dict(os.environ, env_patch, clear=True),
        patch.object(mod.httpx, "Client") as client_cls,
    ):
        client_instance = MagicMock()
        client_instance.post.return_value = mock_resp
        client_cls.return_value.__enter__.return_value = client_instance

        res = mod.evaluate_decisions("Enrich hash abcdef1234", questions)
        assert res["enabled"] is True
        assert res["answers"]["needs_cti"]["noul"] == 0.92
        assert res["answers"]["workflow_mode"]["choice"] == "single_specialist"
        assert res["answers"]["urgency"]["raw_score"] == 3.0
        assert res["answers"]["urgency"]["score"] == 4.0

        _, kwargs = client_instance.post.call_args
        assert kwargs["headers"]["x-goog-api-key"] == fake_key
        assert kwargs["json"]["model"] == mod.DECISION_MODEL
        assert kwargs["json"]["questions"]["urgency"]["criteria"] == [
            "L0",
            "L1",
            "L2",
            "L3",
            "L4",
        ]


def test_decision_client_auth_provider_and_http_error_resilience() -> None:
    """Verifies GEMINI_AUTH_PROVIDER exchange and graceful handling of HTTP failures."""
    mod = _load_module(
        "test_decision_client_auth_provider",
        GOVERNED_AGENTS_DIR / "soc_orchestrator" / "decision_client.py",
        {},
    )
    provider = (
        "projects/p/locations/us-central1/authProviders/agw-secops-gemini-api-key"
    )
    exchanged_key = "EXCHANGED_GEMINI_KEY_DO_NOT_LEAK"  # noqa: S105

    auth_resp = MagicMock()
    auth_resp.raise_for_status.return_value = None
    auth_resp.json.return_value = {"success": {"token": exchanged_key}}

    decision_resp = MagicMock()
    decision_resp.raise_for_status.return_value = None
    decision_resp.json.return_value = {
        "answers": {"q": {"type": "noul", "noul": 0.75, "confidence": 0.8}}
    }

    with (
        patch.dict(os.environ, {"GEMINI_AUTH_PROVIDER": provider}, clear=False),
        patch.object(mod, "_get_gcp_access_token", return_value="gcp-bearer"),
        patch.object(mod.httpx, "Client") as client_cls,
    ):
        client_instance = MagicMock()
        client_instance.post.side_effect = [auth_resp, decision_resp]
        client_cls.return_value.__enter__.return_value = client_instance

        res = mod.evaluate_decisions(
            "Check IP 203.0.113.5", {"q": mod.noul_question("Q?")}
        )
        assert res["enabled"] is True
        assert res["answers"]["q"]["noul"] == 0.75
        assert client_instance.post.call_count == 2
        auth_call, dec_call = client_instance.post.call_args_list
        assert "credentials:retrieve" in auth_call.args[0]
        assert auth_call.kwargs["headers"]["Authorization"] == "Bearer gcp-bearer"
        assert dec_call.kwargs["headers"]["x-goog-api-key"] == exchanged_key

        # HTTP error resilience: never raises, returns enabled=True + error.
        client_instance.post.side_effect = [
            auth_resp,
            mod.httpx.ConnectError("gateway unreachable"),
        ]
        err_res = mod.evaluate_decisions(
            "Check IP 203.0.113.5", {"q": mod.noul_question("Q?")}
        )
        assert err_res["enabled"] is True
        assert "ConnectError" in err_res["error"]
        assert err_res["answers"] == {}
        assert exchanged_key not in str(err_res)


def test_soc_orchestrator_preflight_callback_injects_hint_and_never_blocks() -> None:
    """Pre-flight callback injects [PREFLIGHT_ROUTING] on user turns, skips tool turns, and never blocks."""
    mod = _load_orchestrator()

    # 1. User text turn with Decision 1 enabled -> injects [PREFLIGHT_ROUTING] and returns None.
    appended: list[list[str]] = []
    llm_request = SimpleNamespace(
        contents=[
            SimpleNamespace(
                role="user",
                parts=[SimpleNamespace(text="Isolate WKSTN-FIN-042 under CHG-10492")],
            )
        ],
        append_instructions=lambda items: appended.append(list(items)),
    )
    fake_decision = {
        "enabled": True,
        "answers": {
            "needs_cti": {"type": "noul", "noul": 0.10, "confidence": 0.90},
            "needs_threat_hunt": {"type": "noul", "noul": 0.25, "confidence": 0.85},
            "needs_detection_eng": {"type": "noul", "noul": 0.05, "confidence": 0.95},
            "needs_tier2_response": {"type": "noul", "noul": 0.96, "confidence": 0.93},
            "has_change_ticket": {"type": "noul", "noul": 0.98, "confidence": 0.99},
            "workflow_mode": {
                "type": "choice",
                "choice": "containment_action",
                "confidence": 0.94,
            },
            "urgency": {
                "type": "score",
                "raw_score": 3.0,
                "score": 4.0,
                "confidence": 0.88,
            },
        },
    }

    async def fake_aeval(*_: Any, **__: Any) -> dict[str, Any]:
        return fake_decision

    with patch.object(mod, "aevaluate_decisions", side_effect=fake_aeval):
        ret = asyncio.run(mod._preflight_before_model_callback(None, llm_request))
    assert ret is None
    assert len(appended) == 1
    hint = appended[0][0]
    assert "[PREFLIGHT_ROUTING]" in hint
    assert "workflow_mode=containment_action" in hint
    assert "urgency=4.00/5.00" in hint
    assert "has_change_ticket=yes" in hint
    assert "Tier2_Responder" in hint

    # 2. Tool-response turn -> skips Decision 1 call and returns None.
    tool_turn_req = SimpleNamespace(
        contents=[
            SimpleNamespace(
                role="user",
                parts=[
                    SimpleNamespace(
                        function_response=SimpleNamespace(name="Threat_Hunter")
                    )
                ],
            )
        ],
        append_instructions=MagicMock(),
    )
    with patch.object(mod, "aevaluate_decisions") as mock_aeval:
        ret = asyncio.run(mod._preflight_before_model_callback(None, tool_turn_req))
    assert ret is None
    mock_aeval.assert_not_called()
    tool_turn_req.append_instructions.assert_not_called()

    # 3. Decision 1 exception -> never blocks, returns None.
    with patch.object(
        mod, "aevaluate_decisions", side_effect=RuntimeError("decisions backend down")
    ):
        ret = asyncio.run(mod._preflight_before_model_callback(None, llm_request))
    assert ret is None


def test_cti_researcher_classify_ioc_intelligence() -> None:
    """Verifies classify_ioc_intelligence handles empty, disabled, and scored Decision 1 replies."""
    sys.modules.pop("decision_client", None)
    mod = _load_module(
        "test_cti_gti_classify",
        GOVERNED_AGENTS_DIR / "cti_researcher" / "gti_tools.py",
        {"GTI_AUTH_PROVIDER": "projects/p/locations/us-central1/authProviders/gti"},
    )
    empty_res = mod.classify_ioc_intelligence("   ")
    assert empty_res["enabled"] is False
    assert "error" in empty_res

    with patch.object(
        mod,
        "evaluate_decisions",
        return_value={"enabled": False, "reason": "unconfigured", "answers": {}},
    ):
        assert (
            mod.classify_ioc_intelligence('{"domain": "bad.example"}')["enabled"]
            is False
        )

    with patch.object(
        mod,
        "evaluate_decisions",
        return_value={
            "enabled": True,
            "answers": {
                "verdict": {
                    "type": "choice",
                    "choice": "malicious",
                    "confidence": 0.95,
                },
                "threat_category": {
                    "type": "choice",
                    "choice": "command_and_control",
                    "confidence": 0.89,
                },
                "confidence_score": {"type": "score", "raw_score": 3.0, "score": 4.0},
                "requires_immediate_hunt": {"type": "noul", "noul": 0.91},
                "false_positive_likely": {"type": "noul", "noul": 0.08},
            },
            "usage": {"inputTokens": 200},
        },
    ):
        # Note: classify_ioc_intelligence adds +1.0 to confidence_ans.get("score"),
        # matching raw_score semantics if evaluate_decisions returns raw score or shifted score.
        res = mod.classify_ioc_intelligence('{"domain": "c2.example", "malicious": 14}')
        assert res["enabled"] is True
        assert res["verdict"] == "malicious"
        assert res["threat_category"] == "command_and_control"
        assert res["confidence_score"] == 5.0
        assert res["requires_immediate_hunt"] is True
        assert res["false_positive_likely"] is False


def test_threat_hunter_score_alerts_rubric() -> None:
    """Verifies score_alerts_rubric parses severity (1-5), true_positive, mitre_tactic, and next_action."""
    sys.modules.pop("decision_client", None)
    mod = _load_module(
        "test_threat_hunter_triage",
        GOVERNED_AGENTS_DIR / "threat_hunter" / "triage_tools.py",
        {},
    )
    assert "error" in mod.score_alerts_rubric("")

    with patch.object(
        mod,
        "evaluate_decisions",
        return_value={"enabled": False, "reason": "unset", "answers": {}},
    ):
        assert mod.score_alerts_rubric('{"alert": "test"}')["enabled"] is False

    with patch.object(
        mod,
        "evaluate_decisions",
        return_value={
            "enabled": True,
            "answers": {
                "severity": {"type": "score", "score": 3.0, "confidence": 0.88},
                "true_positive": {"type": "noul", "noul": 0.91, "confidence": 0.90},
                "mitre_tactic": {
                    "type": "choice",
                    "choice": "command_and_control",
                    "confidence": 0.85,
                },
                "next_action": {
                    "type": "choice",
                    "choice": "escalate_tier2",
                    "confidence": 0.82,
                },
            },
            "usage": {"inputTokens": 150},
        },
    ):
        res = mod.score_alerts_rubric(
            '{"rule": "Suspicious Beacon", "host": "WKSTN-01"}'
        )
        assert res["enabled"] is True
        assert res["severity_score"] == 4.0
        assert res["severity_level"] == 4
        assert res["true_positive"]["likely"] is True
        assert res["mitre_tactic"] == "command_and_control"
        assert res["next_action"] == "escalate_tier2"


def test_detection_engineer_grade_yaral2_rule() -> None:
    """Verifies grade_yaral2_rule enforces YARA-L 2.0 context and returns structured scores."""
    sys.modules.pop("decision_client", None)
    mod = _load_module(
        "test_detection_tools",
        GOVERNED_AGENTS_DIR / "detection_engineer" / "detection_tools.py",
        {},
    )
    empty = mod.grade_yaral2_rule("   ")
    assert empty["enabled"] is False
    assert empty["rule_language"] == "YARA-L 2.0 (Chronicle SIEM UDM)"
    assert "error" in empty

    sample_rule = """
    rule suspicious_powershell {
      meta:
        author = "secops"
      events:
        $e.metadata.event_type = "PROCESS_LAUNCH"
      condition:
        $e
    }
    """
    with patch.object(
        mod,
        "evaluate_decisions",
        return_value={
            "enabled": True,
            "model": "gemini-decision-1",
            "answers": {
                "rule_quality_score": {
                    "type": "score",
                    "score": 3.0,
                    "confidence": 0.9,
                },
                "false_positive_risk": {
                    "type": "choice",
                    "choice": "medium",
                    "confidence": 0.8,
                },
                "mitre_tactic": {
                    "type": "choice",
                    "choice": "execution",
                    "confidence": 0.92,
                },
                "has_required_yaral2_sections": {"type": "noul", "noul": 0.97},
                "ready_for_validation": {"type": "noul", "noul": 0.89},
            },
            "usage": {"inputTokens": 180},
        },
    ) as mock_eval:
        res = mod.grade_yaral2_rule(
            sample_rule, coverage_context="Windows EDR process telemetry"
        )
        assert res["enabled"] is True
        assert res["rule_language"] == "YARA-L 2.0 (Chronicle SIEM UDM)"
        assert res["rule_quality_score"] == 4.0
        assert res["false_positive_risk"] == "medium"
        assert res["mitre_tactic"] == "execution"
        assert res["has_required_yaral2_sections"] is True
        assert res["ready_for_validation"] is True
        prompt_sent = mock_eval.call_args.args[0]
        assert "YARA-L 2.0" in prompt_sent
        assert "standard file/payload YARA" in prompt_sent


def test_tier2_assess_containment_readiness_is_strictly_advisory() -> None:
    """assess_containment_readiness returns advisory metadata and never blocks Tier-0 containment."""
    sys.modules.pop("decision_client", None)
    mod = _load_module(
        "test_tier2_readiness",
        GOVERNED_AGENTS_DIR / "tier2_responder" / "response_tools.py",
        {},
    )
    with patch.object(
        mod,
        "decide",
        return_value={
            "enabled": False,
            "reason": "Decisions API unconfigured",
            "answers": {},
        },
    ):
        disabled = mod.assess_containment_readiness(
            "DC-PROD-01", "isolate_endpoint_host", "Suspected DCSync"
        )
        assert disabled["advisory_only"] is True
        assert disabled["decision_model_enabled"] is False

    with patch.object(
        mod,
        "decide",
        return_value={
            "enabled": True,
            "model": "gemini-decision-1",
            "answers": {
                "asset_tier": {
                    "type": "choice",
                    "choice": "tier0_crown_jewel",
                    "confidence": 0.98,
                },
                "evidence_sufficiency": {
                    "type": "score",
                    "score": 3.0,
                    "confidence": 0.85,
                },
                "has_change_ticket": {"type": "noul", "noul": 0.04},
                "requires_human_approval": {"type": "noul", "noul": 0.97},
            },
            "usage": {"inputTokens": 140},
        },
    ):
        advisory = mod.assess_containment_readiness(
            "DC-PROD-01",
            "isolate_endpoint_host",
            "Confirmed DCSync from unauthorized host",
        )
        assert advisory["advisory_only"] is True
        assert advisory["decision_model_enabled"] is True
        assert advisory["asset_tier"] == "tier0_crown_jewel"
        assert advisory["evidence_sufficiency_score"] == 4.0
        assert advisory["has_change_ticket_noul"] == 0.04
        assert advisory["requires_human_approval_noul"] == 0.97
        assert "Semantic Governance" in advisory["enforcement_note"]

    # Containment itself is never blocked in Python.
    iso = mod.isolate_endpoint_host("DC-PROD-01", "Confirmed DCSync")
    assert iso["status"] == "ISOLATED"
