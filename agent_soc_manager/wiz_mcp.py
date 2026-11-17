"""Wiz Remote MCP toolset builder supporting OAuth 2.0 DCR+PKCE and Auth Manager.

Connects ADK agents to Wiz Remote MCP (`https://mcp.app.wiz.io/` by default,
overridable via `WIZ_MCP_URL`) using one of three credential paths in priority
order:

1. **Agent Platform Auth Manager** (`WIZ_AUTH_PROVIDER`): retrieves credentials
   at tool-call time from `agentidentitycredentials.googleapis.com` under the
   agent's SPIFFE workload identity.
2. **Explicit Bearer Token** (`WIZ_MCP_BEARER_TOKEN` or `WIZ_ACCESS_TOKEN`):
   attaches a static/injected OAuth bearer token via `header_provider`.
3. **OAuth 2.0 DCR + PKCE Token Cache** (`WIZ_OAUTH_TOKEN_CACHE`): uses
   `mcp.client.auth.OAuthClientProvider` with `FileTokenStorage` and an
   `httpx2.Timeout` factory bridge compatible with ADK + `mcp>=2.3.0`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import select
import sys
import threading
import urllib.parse
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from google.adk.tools.mcp_tool.mcp_session_manager import (
    StreamableHTTPConnectionParams,
)
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset


logger = logging.getLogger(__name__)

DEFAULT_WIZ_MCP_URL = "https://mcp.app.wiz.io/"
DEFAULT_WIZ_TOKEN_CACHE = Path.home() / ".config" / "agentic_soc" / "wiz_tokens.json"
LEGACY_WIZ_TOKEN_CACHE = Path.home() / ".config" / "wiz-secops-mcp" / "tokens.json"
DEFAULT_WIZ_CLIENT_NAME = "agentic-soc-wiz-mcp"

_SUCCESS_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Wiz MCP Auth Complete</title></head>
<body style="background:#0f172a;color:#e2e8f0;font-family:sans-serif;padding:2rem;">
<h2>Wiz MCP authentication received</h2>
<p>Authorization code captured cleanly. You may return to your terminal or ADK session.</p>
</body>
</html>"""


class WizRedirectCapturedError(RuntimeError):
    """Raised intentionally when running non-interactive OAuth preflight checks."""


def resolve_wiz_mcp_url(mcp_url: str | None = None) -> str:
    """Resolves the configured Wiz Remote MCP URL."""
    raw = (mcp_url or os.getenv("WIZ_MCP_URL") or DEFAULT_WIZ_MCP_URL).strip()
    return raw if raw.endswith("/") else f"{raw}/"


def resolve_wiz_token_cache_path(cache_path: str | Path | None = None) -> Path:
    """Resolves the OAuth token cache path, honoring existing legacy caches."""
    if cache_path:
        return Path(cache_path).expanduser()
    env_path = os.getenv("WIZ_OAUTH_TOKEN_CACHE", "").strip()
    if env_path:
        return Path(env_path).expanduser()
    if DEFAULT_WIZ_TOKEN_CACHE.exists():
        return DEFAULT_WIZ_TOKEN_CACHE
    if LEGACY_WIZ_TOKEN_CACHE.exists():
        return LEGACY_WIZ_TOKEN_CACHE
    return DEFAULT_WIZ_TOKEN_CACHE


class WizMcpToolset(McpToolset):
    """McpToolset pre-configured for Wiz Remote MCP (`discover` and `execute`)."""

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


class _AuthManagerHeaderProvider:
    """Retrieves a Wiz OAuth/bearer credential from Auth Manager at call time."""

    def __init__(self, provider_name: str, user_id: str = "soc_manager") -> None:
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


class _StaticBearerHeaderProvider:
    """Attaches an explicit Wiz OAuth bearer token from the environment."""

    def __init__(self, token: str) -> None:
        self._token = token

    def __call__(self, readonly_context: Any = None) -> dict[str, str]:
        del readonly_context
        return {"Authorization": f"Bearer {self._token}"}


class FileTokenStorage:
    """Persists Wiz DCR client registration and OAuth tokens in a 0600 JSON file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = asyncio.Lock()

    def _read_payload(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to read Wiz token cache %s: %s", self.path, exc)
            return {}

    def _write_payload(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        self.path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.chmod(self.path, 0o600)

    def has_cached_tokens(self) -> bool:
        """Returns True when an access token is persisted on disk."""
        payload = self._read_payload()
        tokens = payload.get("tokens")
        return isinstance(tokens, dict) and bool(tokens.get("access_token"))

    async def get_tokens(self) -> Any:
        from mcp.shared.auth import OAuthToken

        async with self._lock:
            raw = self._read_payload().get("tokens")
            if not raw:
                return None
            return OAuthToken.model_validate(raw)

    async def set_tokens(self, tokens: Any) -> None:
        async with self._lock:
            payload = self._read_payload()
            payload["tokens"] = tokens.model_dump(mode="json")
            self._write_payload(payload)

    async def get_client_info(self) -> Any:
        from mcp.shared.auth import OAuthClientInformationFull

        async with self._lock:
            raw = self._read_payload().get("client_info")
            if not raw:
                return None
            return OAuthClientInformationFull.model_validate(raw)

    async def set_client_info(self, client_info: Any) -> None:
        async with self._lock:
            payload = self._read_payload()
            payload["client_info"] = client_info.model_dump(mode="json")
            self._write_payload(payload)


def has_wiz_credentials(cache_path: str | Path | None = None) -> bool:
    """Returns True if Auth Manager, bearer token, or cached OAuth tokens exist."""
    if os.getenv("WIZ_AUTH_PROVIDER", "").strip():
        return True
    if (
        os.getenv("WIZ_MCP_BEARER_TOKEN", "").strip()
        or os.getenv("WIZ_ACCESS_TOKEN", "").strip()
    ):
        return True
    return FileTokenStorage(
        resolve_wiz_token_cache_path(cache_path)
    ).has_cached_tokens()


def is_wiz_mcp_enabled(cache_path: str | Path | None = None) -> bool:
    """Determines whether Wiz Remote MCP should be attached at agent startup."""
    raw = os.getenv("WIZ_MCP_ENABLED", "").strip().lower()
    if raw in {"false", "0", "no", "off"}:
        return False
    if raw in {"true", "1", "yes", "on"}:
        return True
    return has_wiz_credentials(cache_path)


def _bind_loopback_callback_server(
    port: int,
    result: dict[str, str],
    event: threading.Event,
) -> tuple[HTTPServer, str]:
    """Starts a single-request loopback HTTP server for OAuth PKCE callbacks."""

    class _CallbackHandler(BaseHTTPRequestHandler):

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if "code" in params:
                result["code"] = params["code"][0]
                if "state" in params:
                    result["state"] = params["state"][0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(_SUCCESS_HTML.encode("utf-8"))
                event.set()
            elif "error" in params:
                result["error"] = params.get("error_description", params["error"])[0]
                self.send_response(400)
                self.end_headers()
                self.wfile.write(f"Wiz OAuth error: {result['error']}".encode())
                event.set()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    server = HTTPServer(("127.0.0.1", port), _CallbackHandler)
    actual_port = server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{actual_port}/callback"
    return server, redirect_uri


def _build_wiz_oauth_provider(
    *,
    mcp_url: str,
    token_cache_path: Path,
    client_name: str = DEFAULT_WIZ_CLIENT_NAME,
    redirect_port: int = 0,
    preflight_only: bool = False,
    open_browser: bool = True,
    allow_stdin_paste: bool = False,
    preflight_capture: dict[str, Any] | None = None,
) -> Any:
    """Builds an `mcp.client.auth.OAuthClientProvider` for Wiz Remote MCP."""
    from mcp.client.auth import OAuthClientProvider
    from mcp.shared.auth import AuthorizationCodeResult, OAuthClientMetadata
    from pydantic import AnyUrl

    result: dict[str, str] = {}
    callback_event = threading.Event()
    server: HTTPServer | None = None
    if preflight_only:
        redirect_uri = f"http://127.0.0.1:{redirect_port or 8765}/callback"
    else:
        server, redirect_uri = _bind_loopback_callback_server(
            redirect_port, result, callback_event
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

    async def _redirect_handler(auth_url: str) -> None:
        if preflight_capture is not None:
            parsed = urllib.parse.urlparse(auth_url)
            preflight_capture["authorize_endpoint"] = (
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            )
            preflight_capture["query_keys"] = sorted(
                urllib.parse.parse_qs(parsed.query).keys()
            )
        if preflight_only:
            raise WizRedirectCapturedError("Wiz OAuth authorization redirect captured.")
        print(f"\nWiz MCP login required. Open this URL in your browser:\n{auth_url}\n")
        if open_browser:
            webbrowser.open(auth_url)

    async def _callback_handler() -> AuthorizationCodeResult:
        try:
            if allow_stdin_paste:
                print(
                    "Waiting for browser callback, or paste the redirected callback URL "
                    "(or raw code) and press Enter:"
                )
                loop = asyncio.get_running_loop()
                while not callback_event.is_set():
                    if sys.stdin and not sys.stdin.closed:
                        ready, _, _ = await loop.run_in_executor(
                            None, lambda: select.select([sys.stdin], [], [], 0.25)
                        )
                        if ready:
                            line = await loop.run_in_executor(None, sys.stdin.readline)
                            pasted = line.strip()
                            if pasted:
                                if "code=" in pasted:
                                    qs = urllib.parse.parse_qs(
                                        urllib.parse.urlparse(pasted).query
                                    )
                                    if "code" in qs:
                                        return AuthorizationCodeResult(
                                            code=qs["code"][0],
                                            state=qs.get("state", [None])[0],
                                        )
                                return AuthorizationCodeResult(code=pasted, state=None)
                    await asyncio.sleep(0.05)
            else:
                loop = asyncio.get_running_loop()
                while not callback_event.is_set():
                    await loop.run_in_executor(None, callback_event.wait, 0.25)
            if "error" in result:
                raise RuntimeError(f"Wiz OAuth callback error: {result['error']}")
            return AuthorizationCodeResult(
                code=result["code"],
                state=result.get("state"),
            )
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()

    metadata = OAuthClientMetadata(
        client_name=client_name,
        redirect_uris=[AnyUrl(redirect_uri)],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",  # noqa: S106
    )
    return OAuthClientProvider(
        server_url=mcp_url,
        client_metadata=metadata,
        storage=FileTokenStorage(token_cache_path),
        redirect_handler=_redirect_handler,
        callback_handler=_callback_handler,
    )


def build_wiz_httpx_client_factory(
    auth_provider: Any,
) -> Callable[..., Any]:
    """Bridges ADK's `httpx` timeout objects to `mcp>=2.3.0`'s `httpx2` client."""
    import httpx2
    from mcp.shared._httpx_utils import create_mcp_http_client

    def _factory(
        headers: dict[str, str] | None = None,
        timeout: Any = None,
        auth: Any = None,
    ) -> Any:
        effective_timeout: httpx2.Timeout | None = None
        if timeout is not None:
            effective_timeout = httpx2.Timeout(
                connect=getattr(timeout, "connect", 5.0),
                read=getattr(timeout, "read", 30.0),
                write=getattr(timeout, "write", 5.0),
                pool=getattr(timeout, "pool", 5.0),
            )
        return create_mcp_http_client(
            headers=headers,
            timeout=effective_timeout,
            auth=auth or auth_provider,
        )

    return _factory


def create_remote_wiz_toolset(
    *,
    mcp_url: str | None = None,
    auth_provider_name: str | None = None,
    bearer_token: str | None = None,
    token_cache_path: str | Path | None = None,
    open_browser: bool = False,
    allow_stdin_paste: bool = False,
    timeout_seconds: float = 30.0,
    tool_filter: list[str] | None = None,
    user_id: str = "soc_manager",
) -> WizMcpToolset:
    """Creates an ADK `WizMcpToolset` connected to Wiz Remote MCP.

    Selects Auth Manager when `WIZ_AUTH_PROVIDER` is configured, static bearer
    auth when `WIZ_MCP_BEARER_TOKEN`/`WIZ_ACCESS_TOKEN` is set, and otherwise
    uses OAuth 2.0 DCR + PKCE via `FileTokenStorage`.
    """
    resolved_url = resolve_wiz_mcp_url(mcp_url)
    resolved_auth_provider = (
        auth_provider_name or os.getenv("WIZ_AUTH_PROVIDER", "").strip()
    )
    resolved_bearer = (
        bearer_token
        or os.getenv("WIZ_MCP_BEARER_TOKEN", "").strip()
        or os.getenv("WIZ_ACCESS_TOKEN", "").strip()
    )

    if resolved_auth_provider:
        logger.info(
            "Initializing Wiz Remote MCP toolset (%s) via Auth Manager (%s)",
            resolved_url,
            resolved_auth_provider,
        )
        return WizMcpToolset(
            connection_params=StreamableHTTPConnectionParams(
                url=resolved_url,
                timeout=timeout_seconds,
                sse_read_timeout=max(timeout_seconds, 300.0),
            ),
            header_provider=_AuthManagerHeaderProvider(
                resolved_auth_provider, user_id=user_id
            ),
            tool_filter=tool_filter,
            tool_name_prefix="wiz_",
            tool_list_cache_ttl_seconds=300.0,
            use_mcp_resources=False,
            errlog=None,
        )

    if resolved_bearer:
        logger.info(
            "Initializing Wiz Remote MCP toolset (%s) via bearer token",
            resolved_url,
        )
        return WizMcpToolset(
            connection_params=StreamableHTTPConnectionParams(
                url=resolved_url,
                timeout=timeout_seconds,
                sse_read_timeout=max(timeout_seconds, 300.0),
            ),
            header_provider=_StaticBearerHeaderProvider(resolved_bearer),
            tool_filter=tool_filter,
            tool_name_prefix="wiz_",
            tool_list_cache_ttl_seconds=300.0,
            use_mcp_resources=False,
            errlog=None,
        )

    cache_path = resolve_wiz_token_cache_path(token_cache_path)
    logger.info(
        "Initializing Wiz Remote MCP toolset (%s) via OAuth DCR + PKCE (cache=%s)",
        resolved_url,
        cache_path,
    )
    oauth_provider = _build_wiz_oauth_provider(
        mcp_url=resolved_url,
        token_cache_path=cache_path,
        client_name=os.getenv("WIZ_MCP_CLIENT_NAME", DEFAULT_WIZ_CLIENT_NAME),
        open_browser=open_browser,
        allow_stdin_paste=allow_stdin_paste,
    )
    factory = build_wiz_httpx_client_factory(oauth_provider)
    return WizMcpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=resolved_url,
            timeout=timeout_seconds,
            sse_read_timeout=max(timeout_seconds, 300.0),
            httpx_client_factory=factory,  # type: ignore[arg-type]
        ),
        tool_filter=tool_filter,
        tool_name_prefix="wiz_",
        tool_list_cache_ttl_seconds=300.0,
        use_mcp_resources=False,
        errlog=None,
    )


async def _run_interactive_login(
    mcp_url: str,
    cache_path: Path,
    open_browser: bool,
    allow_stdin_paste: bool,
) -> list[str]:
    toolset = create_remote_wiz_toolset(
        mcp_url=mcp_url,
        token_cache_path=cache_path,
        open_browser=open_browser,
        allow_stdin_paste=allow_stdin_paste,
        timeout_seconds=180.0,
    )
    try:
        tools = await toolset.get_tools()
        return [getattr(t, "name", str(t)) for t in tools]
    finally:
        await toolset.close()


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for interactive Wiz Remote MCP OAuth login."""
    parser = argparse.ArgumentParser(description="Wiz Remote MCP helper CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    login_p = sub.add_parser("login", help="Run interactive OAuth DCR+PKCE login")
    login_p.add_argument("--url", default=None, help="Override WIZ_MCP_URL")
    login_p.add_argument("--cache", default=None, help="Override token cache path")
    login_p.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open a local browser (for headless/SSH sessions)",
    )
    login_p.add_argument(
        "--paste-callback",
        action="store_true",
        help="Allow pasting redirected callback URL on stdin",
    )

    args = parser.parse_args(argv)
    if args.command == "login":
        url = resolve_wiz_mcp_url(args.url)
        cache = resolve_wiz_token_cache_path(args.cache)
        tools = asyncio.run(
            _run_interactive_login(
                mcp_url=url,
                cache_path=cache,
                open_browser=not args.no_browser,
                allow_stdin_paste=args.paste_callback or args.no_browser,
            )
        )
        print(f"Authenticated to {url}. Cached tokens at {cache}. Tools: {tools}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
