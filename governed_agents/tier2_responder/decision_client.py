"""Lightweight REST client for the Gemini Decisions API (`gemini-decision-1`).

Uses `httpx` directly so `google-adk==2.13.0` (`google-genai<3,>=2.30`) stays
compatible with `requirements.txt` while calling
`POST https://generativelanguage.googleapis.com/v1beta/decisions`.

Credential resolution order:
1. `GEMINI_AUTH_PROVIDER`: retrieves the API key at call time from Agent
   Platform Auth Manager (`agentidentitycredentials.googleapis.com`) using
   the container's SPIFFE workload identity via `google.auth.default()`.
2. `GEMINI_API_KEY`: environment variable fallback for local development.
3. Unconfigured: returns `{"enabled": False, ...}` so hermetic tests and
   environments without a Decisions API key never fail.
"""

from __future__ import annotations

import os
import threading
from typing import Any

import google.auth
import httpx
from google.auth.transport.requests import Request


DECISIONS_API_URL = os.getenv(
    "GEMINI_DECISIONS_URL",
    "https://generativelanguage.googleapis.com/v1beta/decisions",
)
DECISIONS_MODEL = os.getenv("GEMINI_DECISION_MODEL", "gemini-decision-1")
_AUTH_MANAGER_BASE_URL = "https://agentidentitycredentials.googleapis.com/v1"
_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_HTTP_TIMEOUT_SECONDS = 15.0

_auth_lock = threading.Lock()
_workload_credentials: Any = None
_auth_request: Request | None = None


def _get_workload_bearer_token() -> str:
    """Mints and caches the workload OAuth bearer token for Auth Manager."""
    global _workload_credentials, _auth_request
    with _auth_lock:
        if _workload_credentials is None:
            _workload_credentials, _ = google.auth.default(
                scopes=[_CLOUD_PLATFORM_SCOPE]
            )
            _auth_request = Request()
        if not _workload_credentials.valid:
            _workload_credentials.refresh(_auth_request)
        token = str(_workload_credentials.token or "")
    if not token:
        raise RuntimeError("Workload identity returned an empty OAuth token.")
    return token


def _retrieve_api_key_from_auth_manager(
    provider_name: str,
    user_id: str = "tier2_responder",
) -> str:
    """Retrieves the Gemini API key from Agent Platform Auth Manager."""
    bearer_token = _get_workload_bearer_token()
    url = f"{_AUTH_MANAGER_BASE_URL}/{provider_name.lstrip('/')}/credentials:retrieve"
    with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
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
    token = str((payload.get("success") or {}).get("token") or "")
    if not token:
        raise RuntimeError(
            f"Auth Manager provider {provider_name!r} returned an empty credential."
        )
    return token


def _resolve_api_key() -> str | None:
    """Resolves the Decisions API key from Auth Manager or environment."""
    provider_name = os.getenv("GEMINI_AUTH_PROVIDER", "").strip()
    if provider_name:
        return _retrieve_api_key_from_auth_manager(provider_name)
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    return api_key or None


def decide(
    input_text: str,
    questions: dict[str, dict[str, Any]],
    *,
    model: str = DECISIONS_MODEL,
    timeout_seconds: float = _HTTP_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Calls the Gemini Decisions REST API with structured rubric questions.

    Args:
        input_text: Context string to evaluate against the rubric.
        questions: Mapping of question IDs to `noul`, `choice`, or `score`
            question definitions matching the `v1beta/decisions` schema.
        model: Decisions model identifier (defaults to `gemini-decision-1`).
        timeout_seconds: HTTP request timeout in seconds.

    Returns:
        Dictionary with `enabled` boolean and either `answers`/`usage` on
        success, `reason` when unconfigured, or `error` on request failure.
    """
    try:
        api_key = _resolve_api_key()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return {
            "enabled": True,
            "error": f"Failed to resolve Decisions API credential: {exc}",
        }

    if not api_key:
        return {
            "enabled": False,
            "reason": (
                "Neither GEMINI_AUTH_PROVIDER nor GEMINI_API_KEY is configured."
            ),
        }

    body = {
        "model": model,
        "input": input_text,
        "questions": questions,
    }

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            response = client.post(
                DECISIONS_API_URL,
                headers={
                    "x-goog-api-key": api_key,
                    "Content-Type": "application/json",
                },
                json=body,
            )
    except httpx.HTTPError as exc:
        return {
            "enabled": True,
            "error": f"Decisions API request failed: {exc}",
        }

    if response.status_code >= 400:
        return {
            "enabled": True,
            "status_code": response.status_code,
            "error": (
                f"Decisions API returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            ),
        }

    payload = response.json()
    return {
        "enabled": True,
        "model": model,
        "answers": payload.get("answers", {}),
        "usage": payload.get("usage", {}),
    }
