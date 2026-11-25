"""Wiz Remote MCP toolset adapter and read-only guard for Wizard_Agent.

Retrieves the Wiz OAuth bearer credential at tool-call time from Agent Platform
Auth Manager (`WIZ_AUTH_PROVIDER` via `agentidentitycredentials.googleapis.com`)
under `wizard_agent`'s SPIFFE workload identity, routes Streamable HTTP calls to
`https://mcp.app.wiz.io/` through the egress Agent Gateway, recovers HTTP 403
gateway denials into deterministic `TOOL_ERROR` markers, and blocks mutating
`wiz_execute` operations in `enforce_wiz_readonly_callback`.
"""

from __future__ import annotations

import collections
import os
import re
import threading
from typing import Any

from google.adk.models.llm_response import LlmResponse
from google.adk.tools.mcp_tool.mcp_session_manager import (
    StreamableHTTPConnectionParams,
    create_mcp_http_client,
)
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.genai import types
from mcp.client.session import ClientSession


DEFAULT_WIZ_MCP_URL = "https://mcp.app.wiz.io/"

_GENERIC_MCP_ERROR = "Server returned an error response"
_RECENT_HTTP_ERRORS: collections.deque[dict[str, Any]] = collections.deque(maxlen=8)
_RECENT_HTTP_ERRORS_LOCK = threading.Lock()
_HTTP_ERROR_BODY_LIMIT = 300

_ALLOWED_WIZ_TOOL_NAMES = frozenset(
    {
        "discover",
        "execute",
        "wiz_discover",
        "wiz_execute",
    }
)

_WRITE_HTTP_METHODS = frozenset({"PUT", "PATCH", "DELETE"})

_MUTATING_ACTION_RE = re.compile(
    r"(?:^|[._/\s-])(?:create|update|delete|remove|close|resolve|reopen|dismiss|"
    r"ignore|suppress|assign|comment|add_comment|create_comment|patch|modify|"
    r"apply|trigger|remediate|run_remediation|quarantine|isolate|disable|revoke|"
    r"rotate|set|write|mutate)(?:$|[._/\sA-Z0-9-])",
    re.IGNORECASE,
)

_GRAPHQL_MUTATION_RE = re.compile(
    r"(?:^\s*mutation\b|\bmutation\s+[A-Za-z_][A-Za-z0-9_]*\s*[\({]|\bmutation\s*\{)",
    re.MULTILINE,
)

_ACTION_KEYS = frozenset(
    {
        "tool",
        "tool_name",
        "toolName",
        "name",
        "action",
        "operation",
        "operation_name",
        "operationName",
        "command",
        "subtool",
        "endpoint",
        "path",
    }
)

_QUERY_KEYS = frozenset(
    {
        "query",
        "graphql",
        "graphql_query",
        "gql",
        "statement",
    }
)

_METHOD_KEYS = frozenset({"method", "http_method", "httpMethod", "verb"})


async def _noop_validate_tool_result(
    self: ClientSession, name: str, result: Any
) -> None:
    """Skips mcp 2.x client outputSchema checks on Wiz gateway responses."""
    del self, name, result
    return None


ClientSession.validate_tool_result = _noop_validate_tool_result  # type: ignore[method-assign]


def _remember_http_error(status_code: int, reason: str, body: str, url: str) -> None:
    with _RECENT_HTTP_ERRORS_LOCK:
        _RECENT_HTTP_ERRORS.append(
            {
                "status_code": status_code,
                "reason": reason,
                "body": body[:_HTTP_ERROR_BODY_LIMIT],
                "url": url,
            }
        )


def _take_recent_http_error() -> dict[str, Any] | None:
    with _RECENT_HTTP_ERRORS_LOCK:
        return _RECENT_HTTP_ERRORS.pop() if _RECENT_HTTP_ERRORS else None


async def _record_non_2xx(response: Any) -> None:
    status = getattr(response, "status_code", 0)
    if not isinstance(status, int) or 200 <= status < 300:
        return
    try:
        raw = await response.aread()
        body = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    except Exception:  # noqa: BLE001
        body = ""
    _remember_http_error(
        status,
        str(getattr(response, "reason_phrase", "") or ""),
        body.strip(),
        str(getattr(response, "url", "")),
    )


def create_wiz_http_client(
    headers: dict[str, str] | None = None,
    timeout: Any = None,
    auth: Any = None,
) -> Any:
    """ADK-compatible httpx client factory that records non-2xx gateway replies."""
    client = create_mcp_http_client(headers=headers, timeout=timeout, auth=auth)
    hooks = getattr(client, "event_hooks", None)
    if isinstance(hooks, dict):
        hooks.setdefault("response", []).append(_record_non_2xx)
    return client


def describe_http_error(error_text: str) -> str:
    """Replaces generic MCP SDK errors with recorded HTTP status and body."""
    if _GENERIC_MCP_ERROR not in error_text:
        return error_text
    recent = _take_recent_http_error()
    if recent is None:
        return error_text
    detail = f"HTTP {recent['status_code']} {recent['reason']}".strip()
    if recent["body"]:
        detail = f"{detail}: {recent['body']}"
    return error_text.replace(_GENERIC_MCP_ERROR, detail)


def _extract_tool_error(name: str, response: Any) -> str | None:
    """Formats a failed MCP tool response as `TOOL_ERROR: <tool> -- <error>`."""
    if not isinstance(response, dict):
        return None
    if "error" in response and response["error"]:
        return f"TOOL_ERROR: {name} -- {describe_http_error(str(response['error']))}"
    if response.get("isError") is True:
        content = response.get("content")
        return f"TOOL_ERROR: {name} -- {describe_http_error(str(content or response))}"
    return None


def wiz_before_model_callback(
    callback_context: Any, llm_request: Any
) -> LlmResponse | None:
    """Strips response_json_schema bloat and short-circuits failed Wiz MCP calls."""
    del callback_context
    config = getattr(llm_request, "config", None)
    for tool in getattr(config, "tools", None) or []:
        for fd in getattr(tool, "function_declarations", None) or []:
            if getattr(fd, "response_json_schema", None) is not None:
                fd.response_json_schema = None

    contents = getattr(llm_request, "contents", None) or []
    last = contents[-1] if contents else None
    for part in (getattr(last, "parts", None) or []) if last else []:
        fn_resp = getattr(part, "function_response", None)
        if fn_resp is None:
            continue
        error_text = _extract_tool_error(fn_resp.name, fn_resp.response)
        if error_text:
            return LlmResponse(
                content=types.Content(
                    role="model",
                    parts=[types.Part(text=error_text)],
                )
            )
    return None


def _detect_mutating_wiz_arg(payload: Any) -> str | None:
    """Returns a descriptive reason if `payload` requests a Wiz write/mutation."""
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_str = str(key)
            if key_str in _METHOD_KEYS and isinstance(value, str):
                upper_method = value.strip().upper()
                if upper_method in _WRITE_HTTP_METHODS:
                    return f"{key_str}={upper_method}"
            if key_str in _ACTION_KEYS and isinstance(value, str):
                candidate = value.strip()
                if candidate and _MUTATING_ACTION_RE.search(candidate):
                    return f"{key_str}={candidate}"
            if key_str in _QUERY_KEYS and isinstance(value, str):
                if _GRAPHQL_MUTATION_RE.search(value):
                    return f"GraphQL mutation in {key_str}"
            if isinstance(value, (dict, list, tuple)):
                nested = _detect_mutating_wiz_arg(value)
                if nested is not None:
                    return nested
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            nested = _detect_mutating_wiz_arg(item)
            if nested is not None:
                return nested
    return None


def enforce_wiz_readonly_callback(
    tool: Any,
    args: dict[str, Any],
    tool_context: Any,
) -> dict[str, Any] | None:
    """Blocks mutating Wiz MCP calls while allowing `wiz_discover` and read-only `wiz_execute`."""
    del tool_context
    tool_name = str(getattr(tool, "name", "") or tool or "").strip()
    if tool_name in {"discover", "wiz_discover"}:
        return None
    if tool_name not in _ALLOWED_WIZ_TOOL_NAMES:
        return {
            "error": (
                f"TOOL_ERROR: {tool_name or 'unknown'} -- Read-only policy violation: "
                "Wizard_Agent only permits wiz_discover and read-only wiz_execute."
            )
        }

    violation = _detect_mutating_wiz_arg(args or {})
    if violation is not None:
        return {
            "error": (
                f"TOOL_ERROR: {tool_name} -- Read-only policy violation: "
                "Wizard_Agent is restricted to read-only Wiz Cloud Graph, Attack Path, "
                f"vulnerability, and AI-SPM inspection ({violation} is blocked)."
            )
        }
    return None


class _WizAuthManagerHeaderProvider:
    """Retrieves the Wiz OAuth credential from Auth Manager on each MCP call."""

    def __init__(self, provider_name: str, user_id: str = "wizard_agent") -> None:
        self._provider_name = provider_name
        self._user_id = user_id
        self._lock = threading.Lock()
        self._client: Any = None

    def __call__(self, readonly_context: Any = None) -> dict[str, str]:
        del readonly_context
        from google.cloud.agentidentitycredentials_v1 import (
            AuthProviderCredentialsServiceClient,
            RetrieveCredentialsRequest,
        )

        with self._lock:
            if self._client is None:
                self._client = AuthProviderCredentialsServiceClient(transport="rest")
            client = self._client

        response = client.retrieve_credentials(
            RetrieveCredentialsRequest(
                auth_provider=self._provider_name,
                user_id=self._user_id,
            )
        )
        token = getattr(getattr(response, "success", None), "token", "") or ""
        if not token:
            raise RuntimeError(
                f"Auth Manager provider {self._provider_name!r} returned an empty credential"
            )
        return {"Authorization": f"Bearer {token}"}


class WizMcpToolset(McpToolset):
    """McpToolset pre-configured for Wiz Remote MCP through Agent Gateway."""

    async def get_tools(self, readonly_context: Any = None) -> list[Any]:
        tools = await super().get_tools(readonly_context=readonly_context)
        for tool in tools:
            raw = getattr(tool, "_mcp_tool", None)
            if raw is not None:
                if hasattr(raw, "outputSchema"):
                    raw.outputSchema = None
                if hasattr(raw, "output_schema"):
                    raw.output_schema = None
        return tools


def build_wiz_toolset(
    *,
    mcp_url: str | None = None,
    auth_provider: str | None = None,
    tool_filter: list[str] | None = None,
    user_id: str = "wizard_agent",
) -> WizMcpToolset:
    """Builds a WizMcpToolset authenticated via Agent Platform Auth Manager."""
    resolved_url = (mcp_url or os.getenv("WIZ_MCP_URL") or DEFAULT_WIZ_MCP_URL).strip()
    if not resolved_url.endswith("/"):
        resolved_url = f"{resolved_url}/"
    resolved_provider = (auth_provider or os.environ["WIZ_AUTH_PROVIDER"]).strip()
    return WizMcpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=resolved_url,
            timeout=30.0,
            sse_read_timeout=120.0,
            httpx_client_factory=create_wiz_http_client,
        ),
        header_provider=_WizAuthManagerHeaderProvider(
            resolved_provider, user_id=user_id
        ),
        tool_filter=tool_filter,
        tool_name_prefix="wiz_",
        tool_list_cache_ttl_seconds=300.0,
        use_mcp_resources=False,
    )
