import os
import sys
from pathlib import Path


# Add project root to sys.path for imports
current_dir = Path(__file__).parent
project_root = current_dir.parent.parent.parent
sys.path.append(str(project_root))

from dotenv import load_dotenv

from agent_soc_manager.tools.chatops.security import generate_signed_payload


def generate_live_test_url():
    # 1. Load your local .env
    load_dotenv()

    # 2. Get configuration from environment
    # Use the specific secret from .env if it exists
    secret = os.getenv("CHRONICLE_CHATOPS_SECRET")
    if secret:
        os.environ["CHRONICLE_CHATOPS_SECRET"] = secret
    else:
        print("WARNING: CHRONICLE_CHATOPS_SECRET not found in .env, using default.")
        os.environ["CHRONICLE_CHATOPS_SECRET"] = (
            "test-secret-12345678901234567890123456789012"
        )

    session_id = os.getenv("CHATOPS_TEST_SESSION_ID", "soc-agent-live-test-session")
    agent_engine_id = os.getenv(
        "AGENT_ENGINE_RESOURCE_NAME",
        "projects/secops/locations/us/reasoningEngines/unknown",
    )

    # 3. Add user_id to match Playground session ownership
    user_id = "vais-query-reasoning-engine"

    payload = {
        "action": "Ban Malicious IP",
        "session_id": session_id,
        "agent_engine_id": agent_engine_id,
        "user_id": user_id,
    }

    token = generate_signed_payload(payload)
    # Use the live Cloud Run URL from .env
    base_url = os.getenv(
        "CHATOPS_BASE_URL", "https://chatops-webhook-813924125873.us-east4.run.app"
    )
    url = f"{base_url}/action?t={token}"

    print("-" * 60)
    print("LIVE CHATOPS TEST LINK GENERATED (CLOUD RUN)")
    print("-" * 60)
    print(f"Action: {payload['action']}")
    print(f"Session: {payload['session_id']}")
    print(f"Agent: {payload['agent_engine_id']}")
    print(f"URL: {url}")
    print("-" * 60)


if __name__ == "__main__":
    generate_live_test_url()
