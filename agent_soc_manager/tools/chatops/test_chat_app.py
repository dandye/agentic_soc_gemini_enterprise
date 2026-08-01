"""Offline unit tests for the native Chat App migration (issue #62).

Runs without GCP access: JWT verification is bypassed via
CHATOPS_SKIP_JWT_VERIFY, Cloud Tasks enqueue and the Agent Engine query are
monkeypatched, and the Chat REST API is never called.

Run directly:
    .venv/bin/python agent_soc_manager/tools/chatops/test_chat_app.py
"""

import asyncio
import copy
import os
import sys
import types
from pathlib import Path


os.environ["CHATOPS_SKIP_JWT_VERIFY"] = "true"
os.environ["CHRONICLE_CHATOPS_SECRET"] = "unit-test-secret"
os.environ["CHATOPS_BASE_URL"] = "https://handler.example.com/chatops"

# Offline bootstrap: agent_soc_manager/__init__.py imports the full ADK agent
# stack, which is not installed in a lightweight test environment. Register
# bare parent packages so submodules import without executing that __init__,
# and stub the one ADK symbol chatops_tools needs.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_PKG_ROOT = _REPO_ROOT / "agent_soc_manager"
for _name, _path in (
    ("agent_soc_manager", _PKG_ROOT),
    ("agent_soc_manager.tools", _PKG_ROOT / "tools"),
):
    if _name not in sys.modules:
        _mod = types.ModuleType(_name)
        _mod.__path__ = [str(_path)]
        sys.modules[_name] = _mod

if "google.adk.agents.context" not in sys.modules:
    _adk = types.ModuleType("google.adk")
    _adk_agents = types.ModuleType("google.adk.agents")
    _adk_context = types.ModuleType("google.adk.agents.context")
    _adk_context.Context = object
    sys.modules.setdefault("google.adk", _adk)
    sys.modules.setdefault("google.adk.agents", _adk_agents)
    sys.modules.setdefault("google.adk.agents.context", _adk_context)

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from fastapi.testclient import TestClient

from agent_soc_manager.tools.chatops import chat_app_handler
from agent_soc_manager.tools.chatops.chat_api import (
    ACTION_FUNCTION,
    convert_openlink_to_action,
)
from agent_soc_manager.tools.chatops.security import generate_signed_payload


def _signed_token(action: str = "Approve Block IP") -> str:
    return generate_signed_payload(
        {
            "action": action,
            "session_id": "sess-1",
            "agent_engine_id": "projects/p/locations/l/reasoningEngines/1",
            "user_id": "analyst@example.com",
        }
    )


def _card_with_buttons(action_url: str) -> dict:
    return {
        "cardsV2": [
            {
                "cardId": "test",
                "card": {
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Approve",
                                                "onClick": {
                                                    "openLink": {"url": action_url}
                                                },
                                            },
                                            {
                                                "text": "View in Chronicle",
                                                "onClick": {
                                                    "openLink": {
                                                        "url": "https://chronicle.example.com/case/1"
                                                    }
                                                },
                                            },
                                        ]
                                    }
                                }
                            ]
                        }
                    ]
                },
            }
        ]
    }


def test_transform():
    token = _signed_token()
    url = f"https://handler.example.com/chatops/action?t={token}"
    card = _card_with_buttons(url)
    original = copy.deepcopy(card)

    converted = convert_openlink_to_action(card)

    # Input is not mutated
    assert card == original

    buttons = converted["cardsV2"][0]["card"]["sections"][0]["widgets"][0][
        "buttonList"
    ]["buttons"]

    # Signed action button becomes a native action with the token parameter
    approve = buttons[0]
    assert "openLink" not in approve["onClick"]
    assert approve["onClick"]["action"]["function"] == ACTION_FUNCTION
    assert approve["onClick"]["action"]["parameters"] == [
        {"key": "token", "value": token}
    ]

    # Informational link button is untouched
    chronicle = buttons[1]
    assert chronicle["onClick"]["openLink"]["url"] == (
        "https://chronicle.example.com/case/1"
    )

    # Idempotent: converting again changes nothing
    assert convert_openlink_to_action(converted) == converted
    print("test_transform passed")


def test_events_card_clicked_enqueues_and_acks():
    token = _signed_token("Approve Isolate Host")
    enqueued = []
    chat_app_handler._enqueue_task = lambda payload: enqueued.append(payload) or "task"

    client = TestClient(chat_app_handler.app)
    event = {
        "type": "CARD_CLICKED",
        "common": {
            "invokedFunction": "execute_signed_action",
            "parameters": {"token": token},
        },
        "user": {"displayName": "Dana Analyst"},
        "message": {"name": "spaces/S/messages/M"},
    }
    response = client.post("/chat/events", json=event)

    assert response.status_code == 200
    body = response.json()
    assert body["actionResponse"]["type"] == "UPDATE_MESSAGE"
    card_text = str(body["cardsV2"])
    assert "Processing" in card_text
    assert "Approve Isolate Host" in card_text
    assert "Dana Analyst" in card_text

    assert len(enqueued) == 1
    assert enqueued[0]["token"] == token
    assert enqueued[0]["message_name"] == "spaces/S/messages/M"
    print("test_events_card_clicked_enqueues_and_acks passed")


def test_events_invalid_token_rejected():
    client = TestClient(chat_app_handler.app)
    event = {
        "type": "CARD_CLICKED",
        "common": {
            "invokedFunction": "execute_signed_action",
            "parameters": {"token": "bogus.token"},
        },
    }
    response = client.post("/chat/events", json=event)
    assert response.status_code == 200
    assert "NOT executed" in str(response.json())
    print("test_events_invalid_token_rejected passed")


def test_events_message_and_added_to_space():
    client = TestClient(chat_app_handler.app)
    for event_type in ("MESSAGE", "ADDED_TO_SPACE"):
        response = client.post("/chat/events", json={"type": event_type})
        assert response.status_code == 200
        assert "text" in response.json()
    print("test_events_message_and_added_to_space passed")


def test_events_missing_bearer_rejected_when_verifying():
    os.environ["CHATOPS_SKIP_JWT_VERIFY"] = "false"
    try:
        client = TestClient(chat_app_handler.app)
        response = client.post("/chat/events", json={"type": "MESSAGE"})
        assert response.status_code == 401
    finally:
        os.environ["CHATOPS_SKIP_JWT_VERIFY"] = "true"
    print("test_events_missing_bearer_rejected_when_verifying passed")


def test_worker_executes_and_syncs_card():
    token = _signed_token("Approve Block IP")
    updates = []

    async def fake_query(action, session_id, agent_engine_id, user_id):
        assert session_id == "sess-1"
        assert agent_engine_id.endswith("reasoningEngines/1")
        return f"The action '{action}' was processed by the AI agent."

    async def fake_update(message_name, card):
        updates.append((message_name, card))

    chat_app_handler._run_agent_query = fake_query
    import agent_soc_manager.tools.chatops.chat_api as chat_api_mod

    chat_api_mod.update_card = fake_update

    client = TestClient(chat_app_handler.app)
    response = client.post(
        "/tasks/execute",
        json={
            "token": token,
            "requester": "Dana Analyst",
            "message_name": "spaces/S/messages/M",
        },
    )
    assert response.status_code == 200
    assert len(updates) == 1
    message_name, card = updates[0]
    assert message_name == "spaces/S/messages/M"
    card_text = str(card)
    assert "Processed" in card_text
    assert "Approve Block IP" in card_text
    print("test_worker_executes_and_syncs_card passed")


def test_worker_failure_syncs_honest_failure():
    token = _signed_token("Approve Wipe Host")
    updates = []

    async def failing_query(action, session_id, agent_engine_id, user_id):
        raise RuntimeError("Agent Engine unavailable")

    async def fake_update(message_name, card):
        updates.append(card)

    chat_app_handler._run_agent_query = failing_query
    import agent_soc_manager.tools.chatops.chat_api as chat_api_mod

    chat_api_mod.update_card = fake_update

    client = TestClient(chat_app_handler.app)
    response = client.post(
        "/tasks/execute",
        json={"token": token, "message_name": "spaces/S/messages/M"},
    )
    # 200 by design: retrying would duplicate agent executions; the failure
    # is reported into the card instead.
    assert response.status_code == 200
    card_text = str(updates[0])
    assert "Failed" in card_text
    assert "No state change was confirmed" in card_text
    print("test_worker_failure_syncs_honest_failure passed")


def test_worker_invalid_token_dropped():
    client = TestClient(chat_app_handler.app)
    response = client.post("/tasks/execute", json={"token": "bogus.token"})
    # 200 with a dropped status: a 4xx would make Cloud Tasks retry every
    # queued task to max attempts after a secret rotation.
    assert response.status_code == 200
    assert response.json()["status"] == "dropped"
    print("test_worker_invalid_token_dropped passed")


def test_approver_allowlist_rejects_unlisted_user():
    token = _signed_token("Approve Block IP")
    os.environ["CHATOPS_APPROVER_EMAILS"] = "lead@example.com"
    try:
        client = TestClient(chat_app_handler.app)
        event = {
            "type": "CARD_CLICKED",
            "common": {
                "invokedFunction": "execute_signed_action",
                "parameters": {"token": token},
            },
            "user": {"displayName": "Mallory", "email": "mallory@example.com"},
            "message": {"name": "spaces/S/messages/M"},
        }
        response = client.post("/chat/events", json=event)
        assert response.status_code == 200
        body = response.json()
        assert "not authorized" in str(body)
        # Error responses post a new message so the approval card's buttons
        # survive for an authorized approver.
        assert body["actionResponse"]["type"] == "NEW_MESSAGE"
    finally:
        os.environ.pop("CHATOPS_APPROVER_EMAILS", None)
    print("test_approver_allowlist_rejects_unlisted_user passed")


def test_double_click_dedupes_to_processing_card():
    token = _signed_token("Approve Isolate Host")

    class AlreadyExists(Exception):
        pass

    def raise_already_exists(payload):
        raise AlreadyExists("task exists")

    chat_app_handler._enqueue_task = raise_already_exists
    client = TestClient(chat_app_handler.app)
    event = {
        "type": "CARD_CLICKED",
        "common": {
            "invokedFunction": "execute_signed_action",
            "parameters": {"token": token},
        },
        "user": {"displayName": "Dana Analyst"},
        "message": {"name": "spaces/S/messages/M"},
    }
    response = client.post("/chat/events", json=event)
    assert response.status_code == 200
    body = response.json()
    # The duplicate click is acked with the processing card, not an error:
    # the first click's execution stands.
    assert body["actionResponse"]["type"] == "UPDATE_MESSAGE"
    assert "Processing" in str(body["cardsV2"])
    print("test_double_click_dedupes_to_processing_card passed")


def test_secret_fails_closed_on_cloud_run():
    from agent_soc_manager.tools.chatops import security as security_mod

    real_secret = os.environ.pop("CHRONICLE_CHATOPS_SECRET")
    os.environ["K_SERVICE"] = "chatops-chat-app"
    try:
        try:
            security_mod._get_secret()
            raise AssertionError("expected ValueError for missing secret")
        except ValueError:
            pass
    finally:
        os.environ.pop("K_SERVICE", None)
        os.environ["CHRONICLE_CHATOPS_SECRET"] = real_secret
    print("test_secret_fails_closed_on_cloud_run passed")


def test_dev_flags_blocked_on_cloud_run():
    os.environ["K_SERVICE"] = "chatops-chat-app"
    try:
        assert chat_app_handler._dev_flag("CHATOPS_SKIP_JWT_VERIFY") is False
        assert chat_app_handler._dev_flag("CHATOPS_INLINE_EXECUTION") is False
    finally:
        os.environ.pop("K_SERVICE", None)
    assert chat_app_handler._dev_flag("CHATOPS_SKIP_JWT_VERIFY") is True
    print("test_dev_flags_blocked_on_cloud_run passed")


def test_legacy_action_route_present():
    client = TestClient(chat_app_handler.app)
    response = client.get("/action", params={"t": "bogus.token"})
    # Invalid token yields the legacy HTML failure page, proving the route
    # is served by the new handler app.
    assert response.status_code == 500
    assert "Action Failed" in response.text
    print("test_legacy_action_route_present passed")


def test_dispatch_dual_mode_routing():
    from agent_soc_manager.tools import chatops_tools

    # chat_app mode without CHAT_SPACE: explicit error, no fabricated success
    os.environ["CHATOPS_MODE"] = "chat_app"
    os.environ.pop("CHAT_SPACE", None)
    result = asyncio.run(chatops_tools.send_raw_card({"cardsV2": []}))
    assert result.startswith("Error")
    assert "CHAT_SPACE" in result

    # webhook default: unchanged error path when WEBHOOK_URL is unset
    os.environ["CHATOPS_MODE"] = "webhook"
    os.environ.pop("WEBHOOK_URL", None)
    result = asyncio.run(chatops_tools.send_raw_card({"cardsV2": []}))
    assert "WEBHOOK_URL" in result

    # send_chatops_card routes through the same seam
    os.environ["CHATOPS_MODE"] = "chat_app"
    result = asyncio.run(
        chatops_tools.send_chatops_card(title="T", subtitle="S", sections=[])
    )
    assert "CHAT_SPACE" in result
    os.environ.pop("CHATOPS_MODE", None)
    print("test_dispatch_dual_mode_routing passed")


if __name__ == "__main__":
    test_transform()
    test_events_card_clicked_enqueues_and_acks()
    test_events_invalid_token_rejected()
    test_events_message_and_added_to_space()
    test_events_missing_bearer_rejected_when_verifying()
    test_worker_executes_and_syncs_card()
    test_worker_failure_syncs_honest_failure()
    test_worker_invalid_token_dropped()
    test_approver_allowlist_rejects_unlisted_user()
    test_double_click_dedupes_to_processing_card()
    test_secret_fails_closed_on_cloud_run()
    test_dev_flags_blocked_on_cloud_run()
    test_legacy_action_route_present()
    test_dispatch_dual_mode_routing()
    print("\nAll chat_app tests passed.")
