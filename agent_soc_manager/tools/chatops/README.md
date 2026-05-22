# SOC ChatOps Webhook Handler

This component provides a secure bridge between Google Chat interactive cards and the Google Vertex AI Agent Engine. It enables "Human-in-the-loop" decisions by injecting validated user actions directly into a running AI session's memory.

## Architecture

1.  **Card Generator (`card_client.py`)**: Signs a JSON payload containing `session_id`, `agent_engine_id`, and `action` using HMAC-SHA256.
2.  **Webhook Handler (`webhook_handler.py`)**: A Cloud Run-compatible FastAPI application that decrypts and verifies the token.
3.  **Agent Engine Integration**: The handler impersonates the Playground user (`vais-query-reasoning-engine`) to inject the confirmed action into the AI session via `async_stream_query`.

## Setup & Configuration

Configure these values in your root `.env` file:

```bash
# Core Security
CHRONICLE_CHATOPS_SECRET="your-uuid-here"  # Match with Cloud Run Secret

# Deployment URLs
WEBHOOK_URL="https://chat.googleapis.com/v1/spaces/..." # Destination Chat Space
CHATOPS_BASE_URL="https://chatops-webhook-....run.app"     # Your Cloud Run Service URL

# Vertex AI Settings
GCP_PROJECT_ID="your-project-id"
GCP_LOCATION="us-east4"
```

## Local Testing

### 1. Run the Webhook Locally
```bash
./agent_soc_manager/tools/chatops/run_local.sh
```
This starts the server on `http://localhost:8080`.

### 2. Generate a Test URL
```bash
export PYTHONPATH=$(pwd)
venv/bin/python agent_soc_manager/tools/chatops/generate_test_url.py
```
This generates a live test link using your `.env` configuration.

## Cloud Deployment

### Google Cloud Run (Recommended)
Deployment is fully automated via the provided script:
```bash
./agent_soc_manager/tools/chatops/cloud_run_deploy.sh
```
This script builds a lean container using a dedicated `requirements.txt` and only relevant Python files.

## Modernizing Card Templates

A checklist of all modernized cards is available in [modernization_checklist.md](modernization_checklist.md). 

All card templates (`ai_*.py` and operational cards) have been refactored to use the secure signing logic. When creating new cards, ensure the `get_card` function accepts:

1. `session_id`: `str`
2. `agent_engine_id`: `str`
3. `user_id`: `str` (Optional, defaults to `None`)

Use `generate_action_url` for all interactive buttons:
```python
from card_client import generate_action_url

button_url = generate_action_url(
    "Your Action Name",
    session_id=session_id,
    agent_engine_id=agent_engine_id,
    user_id=user_id
)
```

## New Security Workflows

The following specialized cards have been added to support high-fidelity human-in-the-loop flows:

- **`traveler_confirmation.py`**: A user-facing card that asks "Are you traveling?" and provides a text input for the traveler to explain their activity (e.g., flight number, VPN use).
- **`impossible_travel_verification.py`**: A VPN-aware travel verification card that compares locations side-by-side.
- **`triage_report_ready.py`**: An analyst-facing card that summarizes findings (e.g., "12 hosts scanned / 4 malicious") and provides a secure download link for the triage report.

## Critical Notes on Session Ownership

When testing in the **Google Cloud Console (Playground)**, the reasoning engine session belongs to a system user. 
- **Required User ID**: `vais-query-reasoning-engine`.
- The `generate_test_url.py` script and all card template manual test blocks (`if __name__ == "__main__":`) are pre-configured to use this ID. 
- In production, [chatops_tools.py](../chatops_tools.py) automatically extracts the calling user's ID from the ADK context to maintain proper session ownership.

## Debugging

If the webhook fails:
1.  **400 Error**: Check if `AGENT_ENGINE_RESOURCE_NAME` in your `.env` contains single quotes (`'`). Stripping them is REQUIRED.
2.  **Signature Mismatch**: Ensure the `CHRONICLE_CHATOPS_SECRET` in Cloud Run matches your local one.
3.  **Session Error**: Ensure the `user_id` passed matches the identity that created the session (e.g., `vais-query-reasoning-engine` for Cloud Console Playground sessions).
