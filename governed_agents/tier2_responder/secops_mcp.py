"""Chronicle OneMCP toolset adapter for governed SecOps specialist agents.

Handles three runtime requirements inside Vertex AI Agent Engine (`AGENT_IDENTITY`):
1. Attaches the agent's dynamic SPIFFE workload OAuth bearer token and
   `x-goog-user-project` header on Streamable HTTP calls to Chronicle OneMCP
   (`GOOGLE_API_USE_CLIENT_CERTIFICATE=false` disables mTLS transport).
2. Disables `mcp>=2.3.0` client-side `outputSchema` validation (`validate_tool_result`)
   and strips `response_json_schema` from Gemini `FunctionDeclaration` payloads so
   streaming Chronicle RPCs (`list_security_alerts`) that return text progress
   content without `structuredContent` succeed without bloat or `RuntimeError`.
3. Short-circuits failed MCP tool calls into `TOOL_ERROR: <tool> -- <error>`,
   recovering the HTTP status and body of Agent Gateway denials that the MCP
   SDK otherwise reduces to "Server returned an error response", so the SOC
   Orchestrator can deterministically emit the `[POLICY BLOCK]` Tool Allowlist
   notice on real 403s and nothing else.
"""

from __future__ import annotations

import collections
import os
import threading
from typing import Any

import google.auth
from google.adk.models.llm_response import LlmResponse
from google.adk.tools.mcp_tool.mcp_session_manager import (
    StreamableHTTPConnectionParams,
    create_mcp_http_client,
)
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.auth.transport.requests import Request
from google.genai import types
from mcp.client.session import ClientSession


_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


async def _noop_validate_tool_result(
    self: ClientSession, name: str, result: Any
) -> None:
    """Skips mcp 2.x client outputSchema checks on streaming Chronicle tools."""
    return None


ClientSession.validate_tool_result = _noop_validate_tool_result  # type: ignore[method-assign]


class _WorkloadAuthHeaderProvider:
    """Mints and caches the container's SPIFFE workload token off global mTLS."""

    def __init__(self, project_id: str) -> None:
        self._project_id = project_id
        self._lock = threading.Lock()
        self._credentials: Any = None
        self._request: Request | None = None

    def __call__(self, readonly_context: Any = None) -> dict[str, str]:
        with self._lock:
            if self._credentials is None:
                self._credentials, _ = google.auth.default(
                    scopes=[_CLOUD_PLATFORM_SCOPE]
                )
                self._request = Request()
            if not self._credentials.valid:
                self._credentials.refresh(self._request)
            token = self._credentials.token
        return {
            "Authorization": f"Bearer {token}",
            "x-goog-user-project": self._project_id,
        }


# The MCP SDK collapses every non-2xx, non-JSON-RPC HTTP reply into the generic
# `Server returned an error response`, and ADK then wraps that as
# `{"error": "MCP tool execution failed: ..."}`. The Agent Gateway's IAP
# allowlist denial is exactly such a reply (HTTP 403 with a plain body), so by
# the time the model sees the tool result the status is gone. The response
# hook below keeps the last few non-2xx replies so the TOOL_ERROR marker can
# carry the real status and body back to the orchestrator.
_GENERIC_MCP_ERROR = "Server returned an error response"
_RECENT_HTTP_ERRORS: collections.deque[dict[str, Any]] = collections.deque(maxlen=8)
_RECENT_HTTP_ERRORS_LOCK = threading.Lock()
_HTTP_ERROR_BODY_LIMIT = 300


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
    except Exception:  # pylint: disable=broad-exception-caught
        body = ""
    _remember_http_error(
        status,
        str(getattr(response, "reason_phrase", "") or ""),
        body.strip(),
        str(getattr(response, "url", "")),
    )


def create_chronicle_http_client(
    headers: dict[str, str] | None = None,
    timeout: Any = None,
    auth: Any = None,
) -> Any:
    """ADK-compatible httpx client factory that records non-2xx replies."""
    client = create_mcp_http_client(headers=headers, timeout=timeout, auth=auth)
    hooks = getattr(client, "event_hooks", None)
    if isinstance(hooks, dict):
        hooks.setdefault("response", []).append(_record_non_2xx)
    return client


def describe_http_error(error_text: str) -> str:
    """Replaces the SDK's generic MCP error with the recorded HTTP status and body."""
    if _GENERIC_MCP_ERROR not in error_text:
        return error_text
    recent = _take_recent_http_error()
    if recent is None:
        return error_text
    detail = f"HTTP {recent['status_code']} {recent['reason']}".strip()
    if recent["body"]:
        detail = f"{detail}: {recent['body']}"
    return error_text.replace(_GENERIC_MCP_ERROR, detail)


class ChronicleMcpToolset(McpToolset):
    """McpToolset pre-configured for Chronicle OneMCP through Agent Gateway."""

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


def build_chronicle_toolset(
    *,
    mcp_url: str | None = None,
    project_id: str | None = None,
    tool_filter: list[str] | None = None,
) -> ChronicleMcpToolset:
    """Builds a ChronicleMcpToolset scoped to the requested tool names."""
    resolved_project = project_id or os.environ["CHRONICLE_PROJECT_ID"]
    resolved_region = os.getenv("CHRONICLE_REGION", "us")
    resolved_url = mcp_url or os.getenv(
        "CHRONICLE_MCP_URL",
        f"https://chronicle.{resolved_region}.rep.googleapis.com/mcp",
    )
    return ChronicleMcpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=resolved_url,
            timeout=30.0,
            sse_read_timeout=120.0,
            httpx_client_factory=create_chronicle_http_client,
        ),
        header_provider=_WorkloadAuthHeaderProvider(resolved_project),
        tool_filter=tool_filter,
        tool_list_cache_ttl_seconds=300.0,
        use_mcp_resources=False,
    )


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


def chronicle_before_model_callback(
    callback_context: Any, llm_request: Any
) -> LlmResponse | None:
    """Strips response_json_schema bloat and short-circuits failed MCP calls."""
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
