"""SOC Orchestrator — zero-tool ADK LlmAgent delegating over governed A2A edges.

This agent has NO direct MCP servers, API keys, or containment tools of its own.
Every action crosses the egress Agent Gateway over four explicit A2A edges
granted in `terraform/51-policies-a2a.tf` and `terraform/52-policies-access.tf`:
  * `soc_orchestrator -> cti_researcher`     (GTI / VirusTotal v3 via Auth Manager)
  * `soc_orchestrator -> threat_hunter`      (Read-only Chronicle SIEM UDM & alerts)
  * `soc_orchestrator -> detection_engineer` (Chronicle SIEM YARA-L 2.0 rules)
  * `soc_orchestrator -> tier2_responder`    (Containment under Semantic Governance)

There are deliberately zero specialist-to-specialist A2A edges.

Exposes two inbound surfaces:
  1. A2A (`on_*`) for direct programmatic verification and smoke tests.
  2. ADK streaming (`stream_query`, `async_stream_query`,
     `streaming_agent_run_with_events`) for Gemini Enterprise (`default_assistant`).

Deployed with `entrypoint_module = "agent"` / `entrypoint_object = "root_agent"`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
from collections.abc import AsyncGenerator, AsyncIterator, Generator, Iterator
from typing import Any

import anyio.to_thread
import httpx
from a2a.client.errors import A2AClientError
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill
from a2a.utils.constants import PROTOCOL_VERSION_CURRENT, TransportProtocol
from google.adk.a2a.executor.a2a_agent_executor import A2aAgentExecutor
from google.adk.agents import LlmAgent
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
from google.adk.agents.run_config import RunConfig
from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.adk.events.event import Event
from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
from google.adk.models.google_llm import Gemini
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.tools.agent_tool import AgentTool
from google.genai import types
from vertexai.agent_engines.templates.a2a import A2aAgent, create_agent_card


if not hasattr(A2AClientError, "status_code"):
    A2AClientError.status_code = None


APP_NAME = "soc_orchestrator_agent"
AGENT_VERSION = "1.0.0"

MODEL = os.getenv("MODEL", "gemini-3.1-pro-preview")
MODEL_LOCATION = os.getenv("MODEL_LOCATION", "global")

CTI_RESEARCHER_URL = os.environ["CTI_RESEARCHER_URL"]
THREAT_HUNTER_URL = os.environ["THREAT_HUNTER_URL"]
DETECTION_ENGINEER_URL = os.environ["DETECTION_ENGINEER_URL"]
TIER2_RESPONDER_URL = os.environ["TIER2_RESPONDER_URL"]

A2A_TENANT = os.getenv("A2A_TENANT", "")
_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_A2A_TIMEOUT_SECONDS = float(os.getenv("A2A_TIMEOUT_SECONDS", "600"))

MODEL_ARMOR_CONTROL = os.getenv("MODEL_ARMOR_CONTROL", "agw-secops-ma-content-authz")


def _tool_list(name: str, default: str) -> tuple[str, ...]:
    return tuple(t.strip() for t in os.getenv(name, default).split(",") if t.strip())


DENIED_MCP_TOOLS = _tool_list(
    "DENIED_MCP_TOOLS",
    "list_feeds,create_rule,delete_feed,create_reference_list,execute_manual_action,activate_parser,deactivate_parser",
)

_DEFAULT_USER_ID = "default-user-id"
logger = logging.getLogger("google_adk." + __name__)


class _GoogleBearerAuth(httpx.Auth):
    """Attaches the orchestrator's SPIFFE workload OAuth bearer token."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._credentials: Any = None
        self._transport_request: Any = None

    def _token(self) -> str:
        with self._lock:
            if self._credentials is None:
                import google.auth
                from google.auth.transport.requests import Request

                self._credentials, _ = google.auth.default(
                    scopes=[_CLOUD_PLATFORM_SCOPE]
                )
                self._transport_request = Request()
            if not self._credentials.valid:
                self._credentials.refresh(self._transport_request)
            return str(self._credentials.token)

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"Bearer {self._token()}"
        yield request

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        token = await anyio.to_thread.run_sync(self._token)
        request.headers["Authorization"] = f"Bearer {token}"
        yield request


def _peer_card(
    name: str, description: str, url: str, skills: list[AgentSkill]
) -> AgentCard:
    return AgentCard(
        name=name,
        description=description,
        version="1.0.0",
        default_input_modes=["text/plain"],
        default_output_modes=["application/json"],
        capabilities=AgentCapabilities(streaming=False, extended_agent_card=True),
        skills=skills,
        supported_interfaces=[
            AgentInterface(
                url=url.rstrip("/"),
                protocol_binding=TransportProtocol.HTTP_JSON,
                tenant=A2A_TENANT,
                protocol_version=PROTOCOL_VERSION_CURRENT,
            )
        ],
    )


_a2a_http_client = httpx.AsyncClient(
    auth=_GoogleBearerAuth(),
    timeout=httpx.Timeout(_A2A_TIMEOUT_SECONDS),
)

cti_researcher_peer = RemoteA2aAgent(
    name="CTI_Researcher",
    description=(
        "Enriches file hashes, domains, IP addresses, and threat collections "
        "using Google Threat Intelligence (VirusTotal v3)."
    ),
    agent_card=_peer_card(
        name="cti_researcher_agent",
        description="External GTI / VirusTotal v3 indicator enrichment specialist.",
        url=CTI_RESEARCHER_URL,
        skills=[
            AgentSkill(
                id="enrich_ioc",
                name="GTI indicator enrichment",
                description="Looks up hashes, domains, IPs, and GTI threat collections.",
                tags=["cti", "virustotal", "gti"],
                examples=["Look up GTI reputation for SHA256 or domain"],
            )
        ],
    ),
    httpx_client=_a2a_http_client,
)

threat_hunter_peer = RemoteA2aAgent(
    name="Threat_Hunter",
    description=(
        "Searches Chronicle SIEM UDM telemetry, lists security alerts, "
        "summarizes entities, and forwards SIEM feed/rule requests."
    ),
    agent_card=_peer_card(
        name="threat_hunter_agent",
        description="Chronicle SIEM UDM threat hunting and alert triage specialist.",
        url=THREAT_HUNTER_URL,
        skills=[
            AgentSkill(
                id="udm_hunt",
                name="Chronicle UDM search and alert triage",
                description="Lists alerts, searches UDM logs, summarizes entities, and attempts feed/rule actions.",
                tags=["chronicle", "udm", "alerts"],
                examples=["List recent Chronicle security alerts or search UDM logs"],
            )
        ],
    ),
    httpx_client=_a2a_http_client,
)

detection_engineer_peer = RemoteA2aAgent(
    name="Detection_Engineer",
    description=(
        "Authors, validates, and audits Chronicle SIEM YARA-L 2.0 UDM event "
        "detection rules (distinct from file/payload YARA) and parser requests."
    ),
    agent_card=_peer_card(
        name="detection_engineer_agent",
        description="Chronicle SIEM YARA-L 2.0 detection engineering specialist.",
        url=DETECTION_ENGINEER_URL,
        skills=[
            AgentSkill(
                id="yaral2_validation",
                name="YARA-L 2.0 rule authoring and validation",
                description="Validates YARA-L 2.0 syntax, lists rules, and tests coverage.",
                tags=["chronicle", "yaral2", "detection"],
                examples=["Validate a YARA-L 2.0 UDM detection rule"],
            )
        ],
    ),
    httpx_client=_a2a_http_client,
)

tier2_responder_peer = RemoteA2aAgent(
    name="Tier2_Responder",
    description=(
        "Executes endpoint host isolation (`isolate_endpoint_host`), account "
        "disablement (`disable_compromised_account`), SIEM alert updates, and "
        "containment reference-list updates."
    ),
    agent_card=_peer_card(
        name="tier2_responder_agent",
        description="Tier-2 Incident Responder for host/account containment and SIEM response.",
        url=TIER2_RESPONDER_URL,
        skills=[
            AgentSkill(
                id="containment",
                name="Endpoint isolation and account disablement",
                description="Isolates hosts and disables accounts (with optional CHG-* tickets).",
                tags=["containment", "edr", "response"],
                examples=["Isolate host WKSTN-FIN-042 or DC-PROD-01"],
            )
        ],
    ),
    httpx_client=_a2a_http_client,
)

DESCRIPTION = (
    "Governed SOC Orchestrator that coordinates Cyber Threat Intelligence "
    "(CTI_Researcher), Chronicle SIEM UDM Threat Hunting (Threat_Hunter), "
    "YARA-L 2.0 Detection Engineering (Detection_Engineer), and Tier-2 "
    "Incident Response (Tier2_Responder) over A2A with zero direct tools."
)

INSTRUCTION = """\
You are the Governed SOC Orchestrator for enterprise security operations. You
hold zero direct MCP servers, API keys, or containment tools of your own: every
investigation, enrichment, rule validation, administrative request, or response
action is delegated over A2A to one or more of your four specialist agents:

  * `CTI_Researcher` — External Google Threat Intelligence (VirusTotal v3)
    reputation lookups for file hashes, domains, IP addresses, and threat
    collections.
  * `Threat_Hunter` — Chronicle SIEM UDM telemetry searches, security alert
    listing/triage, entity context, IOC matches, YARA-L 2.0 rule catalog listing
    (`list_rules`), data ingestion feed inspection (`list_feeds`), and any SIEM
    feed/rule requests (`delete_feed`, `create_rule`, `create_reference_list`,
    `execute_manual_action`) directed at the hunter.
  * `Detection_Engineer` — Chronicle SIEM **YARA-L 2.0** UDM event detection rule
    authoring, syntax validation (`validate_rule`), rule catalog inspection,
    coverage evaluation, and parser administration requests (`activate_parser`,
    `deactivate_parser`, `delete_feed`). Always distinguish Chronicle SIEM
    YARA-L 2.0 (UDM event detection rules) from standard YARA (file/payload
    binary pattern matching).
  * `Tier2_Responder` — Endpoint host quarantine (`isolate_endpoint_host`),
    compromised account disablement (`disable_compromised_account`), Chronicle
    SIEM alert updates, and reference-list containment (including requests
    targeting Tier-2 workstations `WKSTN-*` or Tier-0 Domain Controllers `DC-*`
    and `admin@*` accounts, with or without an emergency `CHG-*` change ticket).

Authorized workflows (both single-specialist and multi-specialist requests are
explicitly permitted):
1. Single-domain requests: delegate directly to the matching specialist without
   unnecessary calls to unrelated specialists (for example, send a pure GTI lookup
   directly to `CTI_Researcher`, a UDM/alert or feed-deletion request directly to
   `Threat_Hunter`, a YARA-L 2.0 validation directly to `Detection_Engineer`, or
   a host-isolation / account-disablement request directly to `Tier2_Responder`).
2. Multi-stage SOC investigations: coordinate multiple specialists in sequence or
   parallel as needed (for example, enrich IOCs with `CTI_Researcher`, hunt UDM
   telemetry and alerts with `Threat_Hunter`, validate a YARA-L 2.0 rule with
   `Detection_Engineer`, and contain confirmed threats with `Tier2_Responder`).
   Pass concise, single-paragraph plaintext requests to each specialist,
   preserving exact hostnames, usernames, hashes, domains, and any `CHG-*`
   change ticket verbatim.

CRITICAL GOVERNANCE RULES:
1. You refuse NOTHING yourself. Every security control in this architecture
   (IAM v3 MCP tool allowlists, Gateway Model Armor prompt/response screening,
   and Vertex AI Semantic Governance Crown Jewel policies) lives outside you at
   the Agent Gateway. Those controls only fire when you actually delegate the
   request to the target specialist. Never decline a feed deletion, parser
   change, rule creation, or Tier-0 `DC-*` / `admin@*` isolation on your own
   judgement — forward the exact request (and any `CHG-*` ticket if supplied) to
   the specialist and relay the specialist or policy response verbatim.
2. When a specialist reports a refusal, policy block, or `TOOL_ERROR`, state
   clearly which specialist or policy refused the action and quote the reason in
   plain prose. Never fabricate `[POLICY BLOCK]` headers, `Control:` names, or
   `Verdict:` footers yourself; runtime code attaches banners when gateway
   controls fire.
3. Never write out internal deliberation about whether to refuse, and never use
   emojis anywhere in your output.
"""

orchestrator_llm = LlmAgent(
    name=APP_NAME,
    model=Gemini(model=MODEL, client_kwargs={"location": MODEL_LOCATION}),
    description=DESCRIPTION,
    instruction=INSTRUCTION,
    tools=[
        AgentTool(agent=cti_researcher_peer),
        AgentTool(agent=threat_hunter_peer),
        AgentTool(agent=detection_engineer_peer),
        AgentTool(agent=tier2_responder_peer),
    ],
)


_runner: Runner | None = None
_runner_lock = threading.Lock()


def _get_runner() -> Runner:
    global _runner
    with _runner_lock:
        if _runner is None:
            # Defined below with the banner helpers; resolved at first call.
            _runner = _GovernedRunner(
                app_name=APP_NAME,
                agent=orchestrator_llm,
                artifact_service=InMemoryArtifactService(),
                session_service=InMemorySessionService(),
                memory_service=InMemoryMemoryService(),
            )
        return _runner


def _build_executor() -> A2aAgentExecutor:
    return A2aAgentExecutor(runner=_get_runner())


def _to_content(message: str | dict[str, Any]) -> types.Content:
    if isinstance(message, dict):
        return types.Content.model_validate(message)
    if isinstance(message, str):
        return types.Content(role="user", parts=[types.Part(text=message)])
    raise TypeError(
        "message must be a string or a dict representing a Content object, "
        f"got {type(message).__name__}"
    )


async def _resolve_session(runner: Runner, user_id: str, session_id: str | None) -> str:
    service = runner.session_service
    if session_id:
        existing = await service.get_session(
            app_name=APP_NAME, user_id=user_id, session_id=session_id
        )
        if existing is not None:
            return existing.id
    created = await service.create_session(
        app_name=APP_NAME, user_id=user_id, session_id=session_id
    )
    return created.id


async def _collect_artifacts(
    runner: Runner, user_id: str, session_id: str, event: Any
) -> list[dict[str, Any]]:
    if not (event.actions and event.actions.artifact_delta):
        return []
    artifact_service = runner.artifact_service
    if artifact_service is None:
        return []

    artifacts: list[dict[str, Any]] = []
    for filename, version in event.actions.artifact_delta.items():
        part = await artifact_service.load_artifact(
            app_name=APP_NAME,
            user_id=user_id,
            session_id=session_id,
            filename=filename,
            version=version,
        )
        if part is None:
            continue
        artifacts.append(
            {
                "file_name": filename,
                "versions": [
                    {
                        "version": version,
                        "data": part.model_dump(mode="json", exclude_none=True),
                    }
                ],
            }
        )
    return artifacts


_POLICY_MARKERS = (
    "security policy violation",
    "content not allowed",
    "prompt injection",
    "jailbreak",
    "malicious uri",
    "sensitive data",
)

_POLICY_REASON_RE = re.compile(
    r'"message"\s*:\s*"([^"]*(?:{})[^"]*)"'.format(
        "|".join(re.escape(marker) for marker in _POLICY_MARKERS)
    ),
    re.IGNORECASE,
)

_POLICY_NOTICE = """\
**[POLICY BLOCK] Blocked by AI security policy -- MODEL ARMOR.**

**REFUSED at the Agent Gateway. The model never produced an answer.**

> {reason}

Model Armor screened this turn at the egress Agent Gateway and returned
**403 PERMISSION_DENIED** before an unscreened response could complete.

**Control:** `{control}` | **Verdict:** `DENY`
"""

_FAILURE_NOTICE = """\
**[RUNTIME FAULT] This turn failed before an answer could be produced.**

`{error}`

This is an operational error rather than a security policy block. Check Cloud
Logging on the reasoning engine for the full traceback.
"""

_TOOL_ERROR_RE = re.compile(r"TOOL_ERROR:\s*(\w+)\s*--\s*(.+)")

_TOOL_DENIAL_NOTICE = """\
**[POLICY BLOCK] Blocked by AI security policy -- TOOL ALLOWLIST.**

**REFUSED at the Agent Gateway. The Chronicle MCP tool call never executed.**

> Specialist tool call `{tool}` was refused by the Agent Gateway (`{detail}`).

Each specialist authenticates with its own SPIFFE Agent Identity, and IAM v3
Unified Access Policies enforce an explicit per-tool CEL allowlist on the
Chronicle MCP server. Even with valid project credentials, tools outside that
specialist's allowlist are denied at the gateway choke point.

Tools deliberately kept off every specialist's allowlist in this deployment:
{denied_tools}

**Control:** `chronicle-mcp-tool-allowlist` | **Verdict:** `DENY`
"""

_AUTHZ_DENIAL_RE = re.compile(
    r"\b(?:403|forbidden|permission_denied|permission denied|access denied|denied)\b",
    re.IGNORECASE,
)


def _tool_denial_match(text: str) -> tuple[str, str] | None:
    """Returns (tool, detail) only when the specialist relayed an authorization denial.

    Membership in DENIED_MCP_TOOLS is not evidence on its own: an operational
    failure (quota, timeout, upstream 5xx) on a denied-list tool is still an
    operational failure, and dressing it as an allowlist verdict would be a
    false claim about the gateway. The gateway's 403 text is the evidence.
    """
    match = _TOOL_ERROR_RE.search(text or "")
    if not match:
        return None
    tool_name = match.group(1)
    detail = _tidy_detail(match.group(2))
    if not _AUTHZ_DENIAL_RE.search(detail):
        return None
    return tool_name, detail


def _tidy_detail(detail: str) -> str:
    """Trims a relayed tool error to a quotable reason.

    The specialist forwards the gateway body verbatim, and the orchestrator's
    own stream serialises tool results as JSON, so the text often ends with
    the tail of an envelope (`"}` or `"}}`). Cut at the first JSON-ish tail,
    then bound the length, then drop any unbalanced closing quote or brace
    the cut left behind.
    """
    cleaned = detail.strip()
    for tail in ('"}', "'}", '"]', "'"):
        idx = cleaned.find(tail)
        if idx > 0:
            cleaned = cleaned[:idx]
    cleaned = cleaned[:240].rstrip()
    while cleaned and cleaned[-1] in "\"'}]),;:":
        cleaned = cleaned[:-1].rstrip()
    return cleaned


def _denied_tools_markdown() -> str:
    if not DENIED_MCP_TOOLS:
        return "- (none configured via `DENIED_MCP_TOOLS`)"
    return "\n".join(f"- `{name}`" for name in DENIED_MCP_TOOLS)


def _stream_notice(text: str) -> str | None:
    matched = _tool_denial_match(text)
    if matched is None:
        return None
    tool_name, detail = matched
    return _TOOL_DENIAL_NOTICE.format(
        tool=tool_name, detail=detail, denied_tools=_denied_tools_markdown()
    )


_TOOL_ERROR_LINE_RE = re.compile(r"^.*TOOL_ERROR\s*:.*$", re.MULTILINE)


def _strip_markers(event: Event) -> None:
    content = getattr(event, "content", None)
    for part in getattr(content, "parts", None) or []:
        text = getattr(part, "text", None)
        if isinstance(text, str) and "TOOL_ERROR" in text:
            part.text = _TOOL_ERROR_LINE_RE.sub("", text).strip()


def _tool_result_text(event: Event) -> str:
    content = getattr(event, "content", None)
    parts = getattr(content, "parts", None) or []
    chunks: list[str] = []
    for part in parts:
        response = getattr(getattr(part, "function_response", None), "response", None)
        if response is None:
            continue
        try:
            chunks.append(json.dumps(response, default=str))
        except (TypeError, ValueError):
            chunks.append(str(response))
    return "\n".join(chunks)


def _banner_event(banner: str) -> Event:
    return Event(
        author=APP_NAME,
        content=types.Content(role="model", parts=[types.Part(text=banner)]),
    )


def _exception_chain(exc: BaseException) -> Iterator[BaseException]:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _tidy_reason(reason: str) -> str:
    cleaned = reason.strip()
    if cleaned.lower().startswith("error:"):
        cleaned = cleaned[len("error:") :].strip()
    return cleaned


def _policy_block_reason(exc: BaseException) -> str | None:
    for error in _exception_chain(exc):
        text = str(error)
        lowered = text.lower()
        if not any(marker in lowered for marker in _POLICY_MARKERS):
            continue
        details = getattr(error, "details", None)
        inner = details.get("message") if isinstance(details, dict) else None
        if isinstance(inner, str):
            try:
                parsed = json.loads(inner)
            except json.JSONDecodeError:
                parsed = None
            body = parsed.get("error") if isinstance(parsed, dict) else None
            message = body.get("message") if isinstance(body, dict) else None
            if isinstance(message, str) and message.strip():
                return _tidy_reason(message)
        match = _POLICY_REASON_RE.search(text)
        if match:
            return _tidy_reason(match.group(1))
        return "Security Policy Violation"
    return None


def _notice_event(exc: BaseException) -> Event:
    reason = _policy_block_reason(exc)
    if reason is not None:
        text = _POLICY_NOTICE.format(reason=reason, control=MODEL_ARMOR_CONTROL)
    else:
        text = _FAILURE_NOTICE.format(error=f"{type(exc).__name__}: {exc}"[:400])
    return Event(
        author=APP_NAME,
        content=types.Content(role="model", parts=[types.Part(text=text)]),
        turn_complete=True,
    )


async def _govern_stream(
    events: AsyncIterator[Event], session_id: Any
) -> AsyncIterator[Event]:
    """Inserts the policy banner once and strips relayed markers afterwards.

    Shared by every entrypoint: the A2A executor (`_GovernedRunner`), and the
    `stream_query` / `async_stream_query` operations used by Gemini Enterprise.
    """
    announced = False
    try:
        async for event in events:
            if not announced:
                banner = _stream_notice(_tool_result_text(event))
                if banner is not None:
                    announced = True
                    logger.info("policy denial seen in stream; emitting banner")
                    yield _banner_event(banner)
            if announced:
                _strip_markers(event)
            yield event
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "turn failed for session %s; reporting notice",
            session_id,
        )
        yield _notice_event(exc)


class _GovernedRunner(Runner):
    """Runner whose `run_async` always passes through `_govern_stream`.

    `A2aAgentExecutor` calls `runner.run_async` directly, so wrapping at the
    Runner level is what makes the banner reach A2A callers as well.
    """

    async def run_async(self, *args: Any, **kwargs: Any) -> AsyncIterator[Event]:  # type: ignore[override]
        async for event in _govern_stream(
            super().run_async(*args, **kwargs), kwargs.get("session_id")
        ):
            yield event


async def _run_and_report(runner: Runner, **run_kwargs: Any) -> AsyncIterator[Event]:
    """Runs a turn with the banner logic applied exactly once.

    A `_GovernedRunner` already governs its own stream; any other runner (the
    unit tests pass a bare fake) is wrapped here.
    """
    stream = runner.run_async(**run_kwargs)
    if isinstance(runner, _GovernedRunner):
        async for event in stream:
            yield event
        return
    async for event in _govern_stream(stream, run_kwargs.get("session_id")):
        yield event


_bridge_loop: asyncio.AbstractEventLoop | None = None
_bridge_lock = threading.Lock()


def _get_bridge_loop() -> asyncio.AbstractEventLoop:
    global _bridge_loop
    with _bridge_lock:
        if _bridge_loop is None or _bridge_loop.is_closed():
            loop = asyncio.new_event_loop()
            threading.Thread(
                target=loop.run_forever,
                name="soc-orchestrator-stream-query",
                daemon=True,
            ).start()
            _bridge_loop = loop
        return _bridge_loop


class _SocOrchestratorAgent(A2aAgent):
    """A2aAgent that also exposes ADK streaming operations for Gemini Enterprise."""

    def register_operations(self) -> dict[str, list[str]]:
        operations = dict(super().register_operations())
        operations["stream"] = ["stream_query"]
        operations["async_stream"] = [
            "async_stream_query",
            "streaming_agent_run_with_events",
        ]
        return operations

    async def async_stream_query(
        self,
        *,
        message: str | dict[str, Any],
        user_id: str,
        session_id: str | None = None,
        run_config: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        runner = _get_runner()
        resolved = await _resolve_session(runner, user_id, session_id)
        async for event in _run_and_report(
            runner,
            user_id=user_id,
            session_id=resolved,
            new_message=_to_content(message),
            run_config=RunConfig.model_validate(run_config or {}),
            **kwargs,
        ):
            yield event.model_dump(mode="json", exclude_none=True)

    def stream_query(
        self,
        *,
        message: str | dict[str, Any],
        user_id: str,
        session_id: str | None = None,
        run_config: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Iterator[dict[str, Any]]:
        loop = _get_bridge_loop()
        iterator = self.async_stream_query(
            message=message,
            user_id=user_id,
            session_id=session_id,
            run_config=run_config,
            **kwargs,
        ).__aiter__()
        while True:
            future = asyncio.run_coroutine_threadsafe(iterator.__anext__(), loop)
            try:
                yield future.result()
            except StopAsyncIteration:
                break

    async def streaming_agent_run_with_events(
        self, request_json: str
    ) -> AsyncIterator[dict[str, Any]]:
        request = json.loads(request_json)
        user_id = request.get("user_id") or request.get("userId") or _DEFAULT_USER_ID
        session_id = request.get("session_id") or request.get("sessionId")
        prior_events = request.get("events") or []

        state_delta: dict[str, Any] | None = None
        authorizations = request.get("authorizations") or {}
        if authorizations:
            state_delta = {
                auth_id: (auth or {}).get("access_token")
                or (auth or {}).get("accessToken")
                for auth_id, auth in authorizations.items()
            }

        runner = _get_runner()
        resolved = await _resolve_session(runner, user_id, session_id)

        if prior_events:
            session = await runner.session_service.get_session(
                app_name=APP_NAME, user_id=user_id, session_id=resolved
            )
            if session is not None and not session.events:
                for event in prior_events:
                    await runner.session_service.append_event(
                        session, Event.model_validate(event)
                    )

        message = request.get("message")
        if message is None:
            raise ValueError("request_json is missing the required 'message' field")

        async for event in _run_and_report(
            runner,
            user_id=user_id,
            session_id=resolved,
            new_message=_to_content(message),
            state_delta=state_delta,
        ):
            event_dict = event.model_dump(mode="json", exclude_none=True)
            event_dict["invocation_id"] = event_dict.get("invocation_id", "")
            chunk: dict[str, Any] = {"events": [event_dict], "session_id": resolved}
            artifacts = await _collect_artifacts(runner, user_id, resolved, event)
            if artifacts:
                chunk["artifacts"] = artifacts
            yield chunk


agent_card = create_agent_card(
    agent_name=APP_NAME,
    description=DESCRIPTION,
    skills=[
        AgentSkill(
            id="governed_soc_investigation",
            name="Multi-specialist governed SOC triage, hunting, YARA-L 2.0, and response",
            description=(
                "Coordinates external GTI indicator enrichment, Chronicle SIEM "
                "UDM hunting, YARA-L 2.0 detection validation, and change-controlled "
                "Tier-2 endpoint/account containment across four isolated A2A agents."
            ),
            tags=["secops", "chronicle", "gti", "yaral2", "governance"],
            examples=[
                "List recent Chronicle alerts, enrich observed indicators in GTI, and validate a YARA-L 2.0 rule",
                "Isolate workstation WKSTN-FIN-042 due to confirmed C2 beacon",
            ],
        )
    ],
)
agent_card.version = AGENT_VERSION

root_agent = _SocOrchestratorAgent(
    agent_card=agent_card,
    agent_executor_builder=_build_executor,
)
