import os
import json
import logging
import asyncio
import sys
from typing import AsyncGenerator

# Ensure we can import soc_agent_a2ui
sys.path.append(os.getcwd())

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Constants
MOCK_AGENT = os.environ.get("MOCK_AGENT", "true").lower() == "true"

# Mock Responses
MOCK_RESPONSES = {
    "default": [
         {"surfaceUpdate": {"surfaceId": "main", "components": [{"id": "root", "component": {"Card": {"child": "msg"}}}]}},
         {"surfaceUpdate": {"surfaceId": "main", "components": [{"id": "msg", "component": {"Text": {"text": {"literalString": "I am the SOC Agent. Ask me to 'triage alert', 'hunt for threats', or 'investigate case'."}}}} ]}},
         {"beginRendering": {"root": "root", "surfaceId": "main"}}
    ]
}

@app.get("/")
async def get_index():
    with open("a2ui_demo/index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.post("/chat")
async def chat(request: Request):
    data = await request.json()
    user_message = data.get("message", "")
    logger.info(f"Received message: {user_message}")

    async def event_generator():
        if MOCK_AGENT:
            logger.info("Using Mock Agent")
            await asyncio.sleep(0.5) # Simulate latency
            key = "default"
            # Logic to select other keys would go here, but I removed them for now to fix syntax

            for msg in MOCK_RESPONSES.get(key, MOCK_RESPONSES["default"]):
                yield json.dumps(msg) + "\n"
                await asyncio.sleep(0.05)
        else:
            yield json.dumps({"error": "Real agent not configured."}) + "\n"

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")

if __name__ == "__main__":
    import uvicorn
    if os.environ.get("GCP_PROJECT_ID"):
        logger.info("GCP_PROJECT_ID found")

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
