"""Wiz Remote MCP toolset adapter for governed SecOps specialist agents.

Retrieves the Wiz OAuth bearer credential at tool-call time from Agent Platform
Auth Manager (`WIZ_AUTH_PROVIDER` via `agentidentitycredentials.googleapis.com`)
under the agent's SPIFFE workload identity, and routes Streamable HTTP calls to
`https://mcp.app.wiz.io/` through the egress Agent Gateway.
"""

from __future__ import annotations

import os
import threading
from typing import Any

from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from secops_mcp import create_chronicle_http_client


DEFAULT_WIZ_MCP_URL = "https://mcp.app.wiz.io/"


class _WizAuthManagerHeaderProvider:
    """Retrieves the Wiz OAuth credential from Auth Manager on each MCP call."""

    def __init__(self, provider_name: str, user_id: str = "threat_hunter") -> None:
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
    user_id: str = "threat_hunter",
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
            httpx_client_factory=create_chronicle_http_client,
        ),
        header_provider=_WizAuthManagerHeaderProvider(
            resolved_provider, user_id=user_id
        ),
        tool_filter=tool_filter,
        tool_name_prefix="wiz_",
        tool_list_cache_ttl_seconds=300.0,
        use_mcp_resources=False,
    )
