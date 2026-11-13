"""Zero-output-token Gemini Decision 1 REST client using httpx.

Supports Auth Manager (`GEMINI_AUTH_PROVIDER`) with `GEMINI_API_KEY` fallback,
and returns a graceful ``{"enabled": False, ...}`` no-op when neither is
configured so hermetic tests and unconfigured environments do not fail.
"""

from __future__ import annotations

import os
import threading
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

_creds_lock = threading.Lock()
_creds_client: AuthProviderCredentialsServiceClient | None = None


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


def _get_gemini_api_key() -> str:
    """Resolves the Gemini API key from Auth Manager or GEMINI_API_KEY env."""
    global _creds_client
    provider_name = os.getenv("GEMINI_AUTH_PROVIDER", "").strip()
    if provider_name:
        with _creds_lock:
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
        return token

    return os.getenv("GEMINI_API_KEY", "").strip()


def evaluate_decisions(
    input_text: str,
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
        "input": input_text,
        "questions": questions,
    }

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
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
