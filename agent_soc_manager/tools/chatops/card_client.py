import os
from pathlib import Path

import requests
from dotenv import load_dotenv

from agent_soc_manager.tools.chatops.security import generate_signed_payload


def send_card(card_json: dict, webhook_url: str = None):
    """Sends a card to Google Chat via webhook."""
    if not webhook_url:
        load_dotenv(Path(__file__).parent.parent.parent.parent / ".env")
        webhook_url = os.environ.get("WEBHOOK_URL")

    if not webhook_url:
        raise ValueError("WEBHOOK_URL not found in environment or arguments")

    response = requests.post(
        webhook_url,
        json=card_json,
        headers={"Content-Type": "application/json; charset=UTF-8"},
        timeout=float(os.environ.get("HTTP_REQUEST_TIMEOUT", "30")),
    )
    response.raise_for_status()
    return response.json()


def generate_action_url(
    action: str,
    session_id: str = None,
    agent_engine_id: str = None,
    user_id: str = None,
) -> str:
    """
    Generates a signed action URL for a ChatOps button.

    If context is missing, returns a dummy example.com URL.
    """
    # Fix: Ensure .env is loaded so CHATOPS_BASE_URL can be read
    load_dotenv(Path(__file__).parent.parent.parent.parent / ".env")
    base_url = os.environ.get("CHATOPS_BASE_URL", "https://example.com/chatops")

    if not agent_engine_id:
        # Fallback for manual testing or missing context
        return f"{base_url}/action?action={action}&session=unknown&agent=unknown"

    payload = {
        "action": action,
        "session_id": str(session_id).strip("'\"") if session_id else None,
        "agent_engine_id": str(agent_engine_id).strip("'\"")
        if agent_engine_id
        else None,
        "user_id": user_id,
    }

    token = generate_signed_payload(payload)
    return f"{base_url}/action?t={token}"
