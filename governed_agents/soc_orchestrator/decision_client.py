"""REST client for Gemini Decision 1 (`generativelanguage.googleapis.com/v1beta/decisions`).

Uses `httpx` directly so `google-adk==2.13.0` / `google-genai==2.34.0` dependency
pins remain untouched. Supports Agent Platform Auth Manager (`GEMINI_AUTH_PROVIDER`)
via `google.auth.default()` + `agentidentitycredentials.googleapis.com`, or direct
`GEMINI_API_KEY` environment fallback, and returns a graceful disabled response
when neither is configured so hermetic CI and unit tests never fail.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

import anyio.to_thread
import httpx


DECISIONS_API_URL = os.getenv(
    "GEMINI_DECISIONS_URL",
    "https://generativelanguage.googleapis.com/v1beta/decisions",
)
DECISION_MODEL = os.getenv("GEMINI_DECISION_MODEL", "gemini-decision-1")
_AUTH_MANAGER_BASE_URL = "https://agentidentitycredentials.googleapis.com/v1"
_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_DEFAULT_TIMEOUT_SECONDS = float(os.getenv("GEMINI_DECISION_TIMEOUT_SECONDS", "15"))

logger = logging.getLogger("google_adk." + __name__)

_credentials_lock = threading.Lock()
_credentials: Any = None
_transport_request: Any = None


def noul_question(instructions: str) -> dict[str, Any]:
    """Builds a binary probability (`noul`) question payload."""
    return {"type": "noul", "instructions": instructions}


def choice_question(instructions: str, criteria: dict[str, str]) -> dict[str, Any]:
    """Builds a single-label `choice` question payload."""
    return {
        "type": "choice",
        "instructions": instructions,
        "criteria": dict(criteria),
    }


def score_question(instructions: str, criteria: list[str]) -> dict[str, Any]:
    """Builds an ordinal `score` question payload with a 0-indexed criteria list."""
    return {
        "type": "score",
        "instructions": instructions,
        "criteria": list(criteria),
    }


def _get_gcp_access_token() -> str:
    """Returns a fresh GCP OAuth bearer token from Application Default Credentials."""
    global _credentials, _transport_request
    with _credentials_lock:
        if _credentials is None:
            import google.auth
            from google.auth.transport.requests import Request

            _credentials, _ = google.auth.default(scopes=[_CLOUD_PLATFORM_SCOPE])
            _transport_request = Request()
        if not _credentials.valid:
            _credentials.refresh(_transport_request)
        return str(_credentials.token)


def _auth_manager_request_args(
    provider_name: str, bearer_token: str
) -> tuple[str, dict[str, str], dict[str, str]]:
    url = (
        f"{_AUTH_MANAGER_BASE_URL}/{provider_name.strip().lstrip('/')}"
        "/credentials:retrieve"
    )
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
    }
    body = {"userId": "soc_orchestrator"}
    return url, headers, body


def _extract_auth_manager_token(payload: dict[str, Any], provider_name: str) -> str:
    token = str((payload.get("success") or {}).get("token") or "").strip()
    if not token:
        raise RuntimeError(
            f"Auth Manager provider {provider_name!r} returned an empty credential"
        )
    return token


def _retrieve_auth_manager_key(provider_name: str, timeout: float) -> str:
    bearer = _get_gcp_access_token()
    url, headers, body = _auth_manager_request_args(provider_name, bearer)
    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, headers=headers, json=body)
        response.raise_for_status()
        return _extract_auth_manager_token(response.json(), provider_name)


async def _aretrieve_auth_manager_key(provider_name: str, timeout: float) -> str:
    bearer = await anyio.to_thread.run_sync(_get_gcp_access_token)
    url, headers, body = _auth_manager_request_args(provider_name, bearer)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(url, headers=headers, json=body)
        response.raise_for_status()
        return _extract_auth_manager_token(response.json(), provider_name)


def _resolve_api_key(timeout: float) -> str | None:
    provider = os.getenv("GEMINI_AUTH_PROVIDER", "").strip()
    if provider:
        return _retrieve_auth_manager_key(provider, timeout)
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    return api_key or None


async def _aresolve_api_key(timeout: float) -> str | None:
    provider = os.getenv("GEMINI_AUTH_PROVIDER", "").strip()
    if provider:
        return await _aretrieve_auth_manager_key(provider, timeout)
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    return api_key or None


def _parse_answers(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalizes Decision 1 REST responses, shifting 0-indexed scores to 1-N."""
    raw_answers = payload.get("answers") or {}
    parsed: dict[str, Any] = {}
    for qid, ans in raw_answers.items():
        if not isinstance(ans, dict):
            continue
        qtype = ans.get("type")
        if qtype == "noul":
            parsed[qid] = {
                "type": "noul",
                "noul": float(ans.get("noul", 0.0)),
                "confidence": float(ans.get("confidence", 0.0)),
            }
        elif qtype == "choice":
            parsed[qid] = {
                "type": "choice",
                "choice": str(ans.get("choice", "")),
                "confidence": float(ans.get("confidence", 0.0)),
                "probabilities": dict(ans.get("probabilities") or {}),
            }
        elif qtype == "score":
            raw_score = float(ans.get("score", 0.0))
            parsed[qid] = {
                "type": "score",
                "raw_score": raw_score,
                "score": raw_score + 1.0,
                "confidence": float(ans.get("confidence", 0.0)),
                "probabilities": dict(ans.get("probabilities") or {}),
                "legend": dict(ans.get("legend") or {}),
            }
        else:
            parsed[qid] = dict(ans)
    return {
        "enabled": True,
        "model": DECISION_MODEL,
        "answers": parsed,
        "usage": dict(payload.get("usage") or {}),
    }


def evaluate_decisions(
    input_text: str,
    questions: dict[str, dict[str, Any]],
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Synchronously evaluates `questions` against `input_text` via Decision 1."""
    if not input_text.strip() or not questions:
        return {
            "enabled": False,
            "reason": "empty input or questions",
            "answers": {},
        }

    try:
        api_key = _resolve_api_key(timeout)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Decision 1 credential resolution failed: %s", type(exc).__name__
        )
        return {
            "enabled": True,
            "error": f"{type(exc).__name__}: {exc}",
            "answers": {},
        }

    if not api_key:
        return {
            "enabled": False,
            "reason": "GEMINI_AUTH_PROVIDER and GEMINI_API_KEY are unset",
            "answers": {},
        }

    body = {
        "model": DECISION_MODEL,
        "input": input_text,
        "questions": questions,
    }
    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(DECISIONS_API_URL, headers=headers, json=body)
            response.raise_for_status()
            return _parse_answers(response.json())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Decision 1 request failed: %s", type(exc).__name__)
        return {
            "enabled": True,
            "error": f"{type(exc).__name__}: {exc}",
            "answers": {},
        }


async def aevaluate_decisions(
    input_text: str,
    questions: dict[str, dict[str, Any]],
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Asynchronously evaluates `questions` against `input_text` via Decision 1."""
    if not input_text.strip() or not questions:
        return {
            "enabled": False,
            "reason": "empty input or questions",
            "answers": {},
        }

    try:
        api_key = await _aresolve_api_key(timeout)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Decision 1 credential resolution failed: %s", type(exc).__name__
        )
        return {
            "enabled": True,
            "error": f"{type(exc).__name__}: {exc}",
            "answers": {},
        }

    if not api_key:
        return {
            "enabled": False,
            "reason": "GEMINI_AUTH_PROVIDER and GEMINI_API_KEY are unset",
            "answers": {},
        }

    body = {
        "model": DECISION_MODEL,
        "input": input_text,
        "questions": questions,
    }
    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(DECISIONS_API_URL, headers=headers, json=body)
            response.raise_for_status()
            return _parse_answers(response.json())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Decision 1 async request failed: %s", type(exc).__name__)
        return {
            "enabled": True,
            "error": f"{type(exc).__name__}: {exc}",
            "answers": {},
        }
