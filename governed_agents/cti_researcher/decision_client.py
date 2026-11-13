"""Zero-output-token Gemini Decision 1 REST client using httpx.

Supports Auth Manager (`GEMINI_AUTH_PROVIDER`) with TTL-cached credentials,
`GEMINI_API_KEY` fallback, module-level `httpx.Client` connection reuse, and
multimodal `input` parts (`text`, `image`, `document`, `audio`, `video`).
Returns a graceful ``{"enabled": False, ...}`` no-op when unconfigured so
hermetic tests and unconfigured environments do not fail.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any

import httpx
from google.cloud.agentidentitycredentials_v1 import (
    AuthProviderCredentialsServiceClient,
    RetrieveCredentialsRequest,
)


DECISIONS_API_URL = os.getenv(
    "GEMINI_DECISIONS_API_URL",
    "https://generativelanguage.googleapis.com/v1beta/decisions",
)
DECISION_MODEL = os.getenv("GEMINI_DECISION_MODEL", "gemini-decision-1")
_HTTP_TIMEOUT_SECONDS = 15.0
_TOKEN_CACHE_TTL_SECONDS = 300.0

_creds_lock = threading.Lock()
_creds_client: AuthProviderCredentialsServiceClient | None = None
_cached_provider: str = ""
_cached_token: str = ""
_cached_token_expiry: float = 0.0

_http_lock = threading.Lock()
_http_client: httpx.Client | None = None


def _get_http_client() -> httpx.Client:
    """Returns a reusable module-level httpx.Client."""
    global _http_client
    with _http_lock:
        if _http_client is None or _http_client.is_closed:
            _http_client = httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS)
        return _http_client


def noul_question(instructions: str) -> dict[str, Any]:
    """Builds a binary probability (noul) Decision 1 question."""
    return {"type": "noul", "instructions": instructions}


def choice_question(instructions: str, criteria: dict[str, str]) -> dict[str, Any]:
    """Builds a categorical choice Decision 1 question."""
    return {
        "type": "choice",
        "instructions": instructions,
        "criteria": criteria,
    }


def score_question(instructions: str, criteria: list[str]) -> dict[str, Any]:
    """Builds an ordinal score Decision 1 question with 0-indexed level list."""
    return {
        "type": "score",
        "instructions": instructions,
        "criteria": criteria,
    }


def _mime_to_part_type(mime_type: str) -> str:
    """Maps a MIME type to a Decision 1 multimodal part type."""
    lower = mime_type.lower()
    if lower.startswith("image/"):
        return "image"
    if lower.startswith("audio/"):
        return "audio"
    if lower.startswith("video/"):
        return "video"
    return "document"


def _normalize_input(
    input_text: str | list[dict[str, Any]],
) -> str | list[dict[str, Any]]:
    """Normalizes string or multimodal parts to the v1beta/decisions schema."""
    if isinstance(input_text, str):
        return input_text

    normalized: list[dict[str, Any]] = []
    for part in input_text:
        if "type" in part:
            normalized.append(part)
        elif "text" in part:
            normalized.append({"type": "text", "text": part["text"]})
        elif "inlineData" in part:
            inline = part["inlineData"]
            mime_type = inline.get("mimeType", "application/octet-stream")
            normalized.append(
                {
                    "type": _mime_to_part_type(mime_type),
                    "data": inline.get("data", ""),
                    "mime_type": mime_type,
                }
            )
        else:
            normalized.append(part)
    return normalized


def _get_gemini_api_key() -> str:
    """Resolves the Gemini API key from TTL-cached Auth Manager or env."""
    global _creds_client, _cached_provider, _cached_token, _cached_token_expiry
    provider_name = os.getenv("GEMINI_AUTH_PROVIDER", "").strip()
    if provider_name:
        now = time.monotonic()
        with _creds_lock:
            if (
                _cached_token
                and _cached_provider == provider_name
                and now < _cached_token_expiry
            ):
                return _cached_token
            if _creds_client is None:
                _creds_client = AuthProviderCredentialsServiceClient(transport="rest")
            client = _creds_client

        response = client.retrieve_credentials(
            RetrieveCredentialsRequest(
                auth_provider=provider_name,
                user_id="cti_researcher",
            )
        )
        token = getattr(getattr(response, "success", None), "token", "") or ""
        if not token:
            raise RuntimeError(
                f"Auth Manager provider {provider_name!r} returned an empty credential"
            )
        with _creds_lock:
            _cached_provider = provider_name
            _cached_token = token
            _cached_token_expiry = time.monotonic() + _TOKEN_CACHE_TTL_SECONDS
        return token

    return os.getenv("GEMINI_API_KEY", "").strip()


def evaluate_decisions(
    input_text: str | list[dict[str, Any]],
    questions: dict[str, dict[str, Any]],
    model: str = DECISION_MODEL,
) -> dict[str, Any]:
    """Calls POST /v1beta/decisions and returns structured answers + usage."""
    try:
        api_key = _get_gemini_api_key()
    except Exception as exc:
        return {
            "enabled": False,
            "reason": f"Failed to resolve Gemini Decision 1 credentials: {exc}",
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

    payload: dict[str, Any] = {
        "model": model,
        "input": _normalize_input(input_text),
        "questions": questions,
    }

    try:
        client = _get_http_client()
        response = client.post(
            DECISIONS_API_URL,
            headers={
                "x-goog-api-key": api_key,
                "Content-Type": "application/json",
            },
            json=payload,
        )
    except httpx.HTTPError as exc:
        return {
            "enabled": True,
            "error": f"Decisions API request failed: {exc}",
            "answers": {},
            "usage": {},
        }

    if response.status_code >= 400:
        return {
            "enabled": True,
            "error": (
                f"Decisions API returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            ),
            "answers": {},
            "usage": {},
        }

    data = response.json()
    return {
        "enabled": True,
        "answers": data.get("answers", {}),
        "usage": data.get("usage", {}),
    }
