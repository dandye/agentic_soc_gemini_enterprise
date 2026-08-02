import os

# Import our code
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


sys.path.append(str(Path(__file__).parent))
from decision import build_session_message
from security import generate_signed_payload
from webhook_handler import app


client = TestClient(app)


@pytest.fixture
def mock_env():
    with patch.dict(
        os.environ,
        {
            "CHRONICLE_CHATOPS_SECRET": "test-secret-12345678901234567890123456789012",
            "GCP_PROJECT_ID": "test-project",
            "GCP_LOCATION": "us-central1",
        },
    ):
        yield


@patch("webhook_handler.ReasoningEngine")
@patch("webhook_handler.vertexai.init")
def test_webhook_integration(mock_vertex_init, mock_reasoning_engine, mock_env):
    """
    Simulates a full button click workflow:
    1. Generate a signed token as if created by a card.
    2. Call the webhook with the token.
    3. Verify signature validation and Agent Engine query.
    """
    # Setup mock
    mock_agent_instance = MagicMock()
    mock_reasoning_engine.return_value = mock_agent_instance

    # 1. Create a valid payload
    payload = {
        "action": "Ban Malicious IP",
        "session_id": "test-session-789",
        "agent_engine_id": "projects/test/locations/us/reasoningEngines/123",
    }
    token = generate_signed_payload(payload)

    # 2. Call the webhook
    response = client.get(f"/action?t={token}")

    # 3. Assert success
    assert response.status_code == 200
    assert "Action Confirmed" in response.text
    assert "Ban Malicious IP" in response.text

    # Verify Agent Engine was called correctly
    mock_reasoning_engine.assert_called_with(payload["agent_engine_id"])
    mock_agent_instance.query.assert_called_once_with(
        session_id=payload["session_id"],
        input=build_session_message(payload["action"])[1],
    )


def test_webhook_invalid_token(mock_env):
    """Verifies that an invalid token returns 400."""
    response = client.get("/action?t=invalid-base64-garbage")
    assert response.status_code == 400
    assert "Action Failed" in response.text


@patch("security.time.time")
def test_webhook_expired_token(mock_time, mock_env):
    """Verifies that an expired token returns 400."""
    current_time = 1700000000
    mock_time.return_value = current_time

    payload = {
        "action": "Expired Action",
        "session_id": "abc",
        "agent_engine_id": "123",
    }
    token = generate_signed_payload(payload)

    # Advance time past TTL (default 3600s)
    mock_time.return_value = current_time + 4000

    response = client.get(f"/action?t={token}")
    assert response.status_code == 400
    assert "expired" in response.text.lower()


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__]))
