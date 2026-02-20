# A2UI Client Demo

This is a demonstration of an A2UI (Agent-to-UI) client interacting with the SOC Agent.

## Overview

The client is a simple HTML/JS application that communicates with a backend server (`server.py`). The server acts as a proxy to the SOC Agent (or a mock agent if credentials are unavailable) and streams A2UI JSONL messages back to the client.

The client renders these A2UI components (`Card`, `Column`, `Row`, `Text`, `Button`) into a native HTML interface.

## Prerequisites

- Python 3.10+
- Dependencies installed via `pip install -r requirements.txt` (specifically `fastapi`, `uvicorn`, `google-adk`).

## Running the Demo

1. Navigate to the root of the repository.
2. Run the server:
   ```bash
   python a2ui_demo/server.py
   ```
3. Open your browser to [http://localhost:8000](http://localhost:8000).

## Usage

- Type "Triage alert" to see a Security Triage Card.
- Type "Hunt for threats" to see a Threat Hunting Card.
- Type "Investigate case" to see a Case Investigation Card.

## Architecture

- `index.html`: The frontend client. It parses JSONL streams and renders components.
- `server.py`: The backend server. It hosts the frontend and simulates the agent stream.
- `soc_agent_a2ui/agent.py`: The agent definition with A2UI-specific system instructions.

## Notes

If `GCP_PROJECT_ID` is not set in the environment, the server defaults to `MOCK_AGENT=true` to ensure the demo works without cloud credentials.
