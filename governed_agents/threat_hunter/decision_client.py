"""REST client for Gemini Decision 1 (`gemini-decision-1`) via httpx.

Supports Agent Platform Auth Manager (`GEMINI_AUTH_PROVIDER`) with SPIFFE
workload identity token exchange against `agentidentitycredentials.googleapis.com`,
`GEMINI_API_KEY` environment fallback, and a graceful disabled no-op when
neither credential source is configured.
"""

from __future__ import annotations

import os
import threading
from typing import Any

import google.auth
import httpx
from google.auth.transport.requests import Request


DECISIONS_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/decisions"
DECISION_MODEL = "gemini-decision-1"
_AUTH_MANAGER_BASE = "https://agentidentitycredentials.googleapis.com/v1"
_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_DEFAULT_TIMEOUT_SECONDS = 20.0

_auth_lock = threading.Lock()
_workload_credentials: Any = None
_auth_request: Request | None = None


def _get_workload_bearer_token() -> str:
    """Mints or refreshes the SPIFFE workload OAuth bearer token."""
    global _workload_credentials, _auth_request
    with _auth_lock:
        if _workload_credentials is None:
            _workload_credentials, _ = google.auth.default(
                scopes=[_CLOUD_PLATFORM_SCOPE]
            )
            _auth_request = Request()
        if not _workload_credentials.valid:
            _workload_credentials.refresh(_auth_request)
        token = getattr(_workload_credentials, "token", "") or ""
    if not token:
        raise RuntimeError("Workload identity returned an empty OAuth token.")
    return token


def _retrieve_api_key_from_auth_manager(
    provider_name: str,
    user_id: str = "threat_hunter",
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Exchanges the workload OAuth token for the Gemini API key via Auth Manager."""
    bearer_token = _get_workload_bearer_token()
    url = f"{_AUTH_MANAGER_BASE}/{provider_name.lstrip('/')}/credentials:retrieve"
    with httpx.Client(timeout=timeout) as client:
        response = client.post(
            url,
            headers={
                "Authorization": f"Bearer {bearer_token}",
                "Content-Type": "application/json",
            },
            json={"userId": user_id},
        )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Auth Manager returned HTTP {response.status_code}: "
            f"{response.text[:300]}"
        )
    payload = response.json()
    token = (payload.get("success") or {}).get("token", "") or ""
    if not token:
        raise RuntimeError(
            f"Auth Manager provider {provider_name!r} returned an empty credential."
        )
    return token


def resolve_gemini_api_key(
    user_id: str = "threat_hunter",
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> str | None:
    """Resolves the Gemini API key from Auth Manager or environment fallback.

    Returns None when neither GEMINI_AUTH_PROVIDER nor GEMINI_API_KEY is set.
    """
    provider_name = os.getenv("GEMINI_AUTH_PROVIDER", "").strip()
    if provider_name:
        return _retrieve_api_key_from_auth_manager(
            provider_name=provider_name,
            user_id=user_id,
            timeout=timeout,
        )
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    return api_key or None


def evaluate_decisions(
    input_text: str,
    questions: dict[str, dict[str, Any]],
    *,
    model: str = DECISION_MODEL,
    endpoint: str = DECISIONS_ENDPOINT,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    user_id: str = "threat_hunter",
) -> dict[str, Any]:
    """Evaluates a batch of Decision 1 questions against `input_text`.

    Returns ``{"enabled": False, ...}`` when unconfigured so hermetic tests
    and environments without Decision 1 credentials degrade gracefully.
    """
    try:
        api_key = resolve_gemini_api_key(user_id=user_id, timeout=timeout)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return {
            "enabled": True,
            "error": f"Failed to resolve Gemini Decision 1 credentials: {exc}",
            "answers": {},
            "usage": {},
        }

    if not api_key:
        return {
            "enabled": False,
            "reason": (
                "Gemini Decision 1 is not configured "
                "(set GEMINI_AUTH_PROVIDER or GEMINI_API_KEY)."
            ),
            "answers": {},
            "usage": {},
        }

    body: dict[str, Any] = {
        "model": model,
        "input": input_text,
        "questions": questions,
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(
                endpoint,
                headers={
                    "x-goog-api-key": api_key,
                    "Content-Type": "application/json",
                },
                json=body,
            )
    except httpx.HTTPError as exc:
        return {
            "enabled": True,
            "error": f"Decision 1 HTTP request failed: {exc}",
            "answers": {},
            "usage": {},
        }

    if response.status_code >= 400:
        return {
            "enabled": True,
            "error": (
                f"Decision 1 API returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            ),
            "answers": {},
            "usage": {},
        }

    payload = response.json()
    return {
        "enabled": True,
        "answers": payload.get("answers") or {},
        "usage": payload.get("usage") or {},
    }
