"""Lightweight REST client for the Gemini Decision 1 API (`gemini-decision-1`).

Uses `httpx` directly against `https://generativelanguage.googleapis.com/v1beta/decisions`
so it introduces zero new package dependencies and avoids `GOOGLE_GENAI_USE_VERTEXAI`
routing conflicts.

Credential resolution order:
  1. `GEMINI_AUTH_PROVIDER`: Agent Platform Auth Manager provider resource name
     (`projects/<project>/locations/<region>/authProviders/<id>`), exchanged via
     `agentidentitycredentials.googleapis.com` using the workload's ADC/SPIFFE token.
  2. `GEMINI_API_KEY`: Direct API key fallback for local development.
  3. Neither configured: returns a graceful `{"enabled": False, ...}` no-op dict.
"""

from __future__ import annotations

import os
import threading
from typing import Any

import google.auth
import httpx
from google.auth.transport.requests import Request


DECISIONS_API_URL = os.getenv(
    "DECISIONS_API_URL",
    "https://generativelanguage.googleapis.com/v1beta/decisions",
)
DECISION_MODEL = os.getenv("DECISION_MODEL", "gemini-decision-1")

_AUTH_MANAGER_BASE = "https://agentidentitycredentials.googleapis.com/v1"
_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_HTTP_TIMEOUT_SECONDS = 20.0

_auth_lock = threading.Lock()
_workload_credentials: Any = None
_auth_request: Request | None = None


def _get_workload_bearer_token() -> str:
    """Mints or refreshes the workload's Google Cloud OAuth bearer token."""
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
        raise RuntimeError("Workload ADC returned an empty OAuth access token.")
    return token


def _retrieve_api_key_from_auth_manager(
    provider_name: str,
    user_id: str = "detection_engineer",
) -> str:
    """Fetches the Gemini API key from Agent Platform Auth Manager over REST."""
    bearer_token = _get_workload_bearer_token()
    url = f"{_AUTH_MANAGER_BASE}/{provider_name.lstrip('/')}/credentials:retrieve"
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
            f"Auth Manager returned HTTP {response.status_code}: {response.text[:300]}"
        )
    payload = response.json()
    token = str(((payload.get("success") or {}).get("token")) or "")
    if not token:
        raise RuntimeError(
            f"Auth Manager provider {provider_name!r} returned an empty credential."
        )
    return token


def _resolve_api_key() -> str | None:
    """Resolves the Gemini API key from Auth Manager or environment fallback."""
    auth_provider = os.getenv("GEMINI_AUTH_PROVIDER", "").strip()
    if auth_provider:
        return _retrieve_api_key_from_auth_manager(auth_provider)
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    return api_key or None


def evaluate_decisions(
    input_text: str,
    questions: dict[str, dict[str, Any]],
    *,
    model: str = DECISION_MODEL,
    timeout_seconds: float = _HTTP_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Evaluates a Decision 1 rubric against `input_text` in a single REST call.

    Args:
        input_text: Text payload to evaluate.
        questions: Mapping of question IDs to Decision 1 question definitions
            (`noul`, `choice`, or `score`).
        model: Decision model identifier (defaults to `gemini-decision-1`).
        timeout_seconds: HTTP request timeout in seconds.

    Returns:
        A dict containing `enabled`, and on success `model`, `answers`, and `usage`.
        Returns `{"enabled": False, "reason": ..., "answers": {}}` when unconfigured.
    """
    try:
        api_key = _resolve_api_key()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return {
            "enabled": True,
            "error": f"Failed to resolve Gemini Decision API credential: {exc}",
            "answers": {},
        }

    if not api_key:
        return {
            "enabled": False,
            "reason": (
                "Decision 1 scoring is disabled: neither GEMINI_AUTH_PROVIDER nor "
                "GEMINI_API_KEY is configured."
            ),
            "answers": {},
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
            "answers": {},
        }

    if response.status_code >= 400:
        return {
            "enabled": True,
            "error": (
                f"Decisions API returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            ),
            "answers": {},
        }

    payload = response.json()
    return {
        "enabled": True,
        "model": model,
        "answers": payload.get("answers", {}),
        "usage": payload.get("usage", {}),
    }
