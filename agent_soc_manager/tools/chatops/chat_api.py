"""Google Chat REST API client for native Chat App message operations.

Posts and updates cards as the registered Chat App (app auth, chat.bot scope)
instead of an incoming webhook. Webhook-posted messages cannot carry
onClick.action payloads -- only messages posted by the app itself route
CARD_CLICKED interaction events back to it, which is what enables the
zero-tab approval UX (issue #62).

Requires the Chat App to be registered in the same GCP project whose
service account identity runs this code (Agent Engine SA or Cloud Run SA),
or GOOGLE_APPLICATION_CREDENTIALS pointing at the app's service account key.
"""

import logging
import os
from urllib.parse import parse_qs, urlparse

import httpx


logger = logging.getLogger(__name__)

CHAT_API_BASE = "https://chat.googleapis.com/v1"
CHAT_APP_SCOPE = "https://www.googleapis.com/auth/chat.bot"
CHAT_HTTP_TIMEOUT = float(os.environ.get("CHATOPS_HTTP_TIMEOUT", "30"))

# The interaction function name carried by converted action buttons. The
# Cloud Run handler dispatches on this name in /chat/events.
ACTION_FUNCTION = "execute_signed_action"


def _get_app_token() -> str:
    """Mints an OAuth2 access token with the chat.bot scope via ADC.

    google.auth is imported lazily so this module stays importable in
    environments without GCP libraries (e.g., offline unit probes).
    """
    import google.auth
    from google.auth.transport.requests import Request

    credentials, _ = google.auth.default(scopes=[CHAT_APP_SCOPE])
    credentials.refresh(Request())
    return credentials.token


def _is_signed_action_url(url: str) -> bool:
    """True when the URL is a signed ChatOps action link (/action?t=...).

    When CHATOPS_BASE_URL is configured, the host must match it so a
    third-party link that merely resembles an action URL is never rewritten
    into an action button.
    """
    parsed = urlparse(url)
    if not parsed.path.endswith("/action"):
        return False
    if "t" not in parse_qs(parsed.query):
        return False
    base_url = os.environ.get("CHATOPS_BASE_URL")
    if base_url:
        base_host = urlparse(base_url).netloc
        if base_host and parsed.netloc != base_host:
            return False
    return True


def _extract_token(url: str) -> str | None:
    """Extracts the signed token from an action URL's `t` query parameter."""
    values = parse_qs(urlparse(url).query).get("t")
    return values[0] if values else None


def convert_openlink_to_action(card_payload: dict) -> dict:
    """Rewrites signed-action openLink buttons into native Chat App actions.

    This is the one-seam migration for all card templates: every template
    builds Approve/Deny buttons through generate_action_url(), producing
    `onClick: {openLink: {url: <base>/action?t=<signed token>}}`. In
    chat_app mode those buttons become
    `onClick: {action: {function: ACTION_FUNCTION, parameters: [{key:
    "token", value: <signed token>}]}}` so clicks arrive as CARD_CLICKED
    events instead of opening a browser tab.

    Informational openLink buttons (e.g., "View in Chronicle") are left
    untouched. The transform is idempotent and does not mutate its input.
    """
    import copy

    payload = copy.deepcopy(card_payload)

    def walk(node) -> None:
        if isinstance(node, dict):
            on_click = node.get("onClick")
            if isinstance(on_click, dict) and "openLink" in on_click:
                url = on_click["openLink"].get("url", "")
                if _is_signed_action_url(url):
                    token = _extract_token(url)
                    if token:
                        node["onClick"] = {
                            "action": {
                                "function": ACTION_FUNCTION,
                                "parameters": [{"key": "token", "value": token}],
                            }
                        }
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return payload


async def _mint_token() -> str:
    """Non-blocking token mint: credentials.refresh is a sync HTTP call."""
    import asyncio

    return await asyncio.to_thread(_get_app_token)


async def post_card_as_app(space: str, card_payload: dict) -> str:
    """Posts a card message to a space as the Chat App.

    Args:
        space: Space resource name (e.g., "spaces/AAAA1234").
        card_payload: A `{"cardsV2": [...]}` payload (webhook-shaped is fine;
            action-button conversion is the caller's responsibility).

    Returns:
        The created message resource name (e.g., "spaces/X/messages/Y").

    Raises:
        httpx.HTTPStatusError: on non-2xx responses from the Chat API.
    """
    token = await _mint_token()
    async with httpx.AsyncClient(timeout=CHAT_HTTP_TIMEOUT) as client:
        response = await client.post(
            f"{CHAT_API_BASE}/{space}/messages",
            json=card_payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        message_name = response.json().get("name", "")
        logger.info(f"Posted Chat App card: {message_name}")
        return message_name


async def update_card(message_name: str, card_payload: dict) -> None:
    """Replaces the cards of an existing app message (state synchronization).

    Args:
        message_name: Full message resource name ("spaces/X/messages/Y").
        card_payload: The replacement `{"cardsV2": [...]}` payload.
    """
    token = await _mint_token()
    async with httpx.AsyncClient(timeout=CHAT_HTTP_TIMEOUT) as client:
        response = await client.patch(
            f"{CHAT_API_BASE}/{message_name}",
            params={"updateMask": "cardsV2"},
            json={"cardsV2": card_payload.get("cardsV2", [])},
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        logger.info(f"Updated Chat App card: {message_name}")
