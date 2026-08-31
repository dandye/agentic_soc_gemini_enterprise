import logging
import os

import vertexai
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from security import verify_signed_payload


try:  # Flat layout (container); package layout for local runs
    from decision import build_session_message
except ImportError:
    from agent_soc_manager.tools.chatops.decision import build_session_message


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ChatOps Action Handler")


@app.get("/action", response_class=HTMLResponse)
async def handle_action(t: str = Query(..., description="Signed action token")):
    """
    Handles a ChatOps button click by verifying the token and notifying the Agent Engine.
    """
    if os.environ.get("CHATOPS_ENABLED", "").strip().lower() not in (
        "1",
        "true",
        "yes",
    ):
        return HTMLResponse(
            content="<html><body><h1>ChatOps is disabled</h1>"
            "<p>This feature is turned off (CHATOPS_ENABLED is not set). "
            "No action was executed.</p></body></html>",
            status_code=503,
        )
    agent_engine_id = None
    session_id = None
    user_id = None
    try:
        # 1. Verify and decode payload
        payload = verify_signed_payload(t)
        action = payload.get("action")
        session_id = payload.get("session_id")
        agent_engine_id = payload.get("agent_engine_id")
        user_id = payload.get("user_id")

        if not action or not session_id or not agent_engine_id:
            raise ValueError("Incomplete payload inside token")

        logger.info(f"Processing action: {action} for session {session_id}")

        # 2. Initialize Vertex AI
        project = os.environ.get("GCP_PROJECT_ID")
        location = os.environ.get("GCP_LOCATION", "us-central1")
        if not project:
            return (
                "<h1>Configuration Error</h1><p>GCP_PROJECT_ID not set on server.</p>"
            )

        vertexai.init(project=project, location=location)

        # 3. Notify Agent Engine
        # We send a message into the session context so the AI knows the user took action.
        # Based on project patterns in manage_agent_engine.py:
        from vertexai import agent_engines

        remote_app = agent_engines.get(agent_engine_id)
        # Rigid decision template (issue #83): a Deny click must never be
        # injected as a confirmation.
        _decision, user_input = build_session_message(action)

        # Note: session ownership is tied to user_id
        # For Playground sessions, this is often 'vais-query-reasoning-engine'
        user_id = payload.get("user_id") or "vais-query-reasoning-engine"

        # Since this is an async FastAPI handler, we can use async iteration
        # In this project, 'async_stream_query' is the confirmed method for interaction
        logger.info(f"Initiating stream query for action: {action} (User: {user_id})")
        async for event in remote_app.async_stream_query(
            user_id=user_id, session_id=session_id, message=user_input
        ):
            # We just need to consume the stream to ensure the action is processed
            logger.debug(f"Event received: {event}")

        logger.info(f"Agent Engine query completed for session {session_id}")

        # 4. Return success page
        return f"""
        <html>
            <head>
                <title>Action Confirmed</title>
                <style>
                    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background-color: #f4f7f9; }}
                    .card {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; max-width: 400px; }}
                    h1 {{ color: #2c3e50; }}
                    p {{ color: #7f8c8d; line-height: 1.6; }}
                    .icon {{ font-size: 3rem; color: #27ae60; margin-bottom: 1rem; }}
                </style>
            </head>
            <body>
                <div class="card">
                    <div class="icon">OK</div>
                    <h1>Action Confirmed</h1>
                    <p>The action <b>{action}</b> has been successfully processed by the AI Agent.</p>
                    <p>You can close this tab and return to Google Chat.</p>
                </div>
            </body>
        </html>
        """

    except Exception as e:
        logger.error(f"Error handling action: {str(e)}")
        # Debugging information to help identify the 400 error
        # Ensure IDs are strings and strip any quotes if they exist in the value
        agent_engine_id_str = (
            str(agent_engine_id).strip("\"'") if agent_engine_id else "N/A"
        )
        session_id_str = str(session_id).strip("\"'") if session_id else "N/A"
        user_id_str = str(user_id).strip("\"'") if user_id else "N/A"

        debug_info = f"""
        <div style="background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; border-radius: 5px; text-align: left; margin-top: 20px;">
            <p><strong>Resource Details:</strong></p>
            <ul style="font-family: monospace; font-size: 13px;">
                <li>Agent ID: "{agent_engine_id_str}"</li>
                <li>Session ID: "{session_id_str}"</li>
                <li>User ID: "{user_id_str}"</li>
                <li>Error: {str(e)}</li>
            </ul>
        </div>
        """
        status_code = (
            400 if isinstance(e, ValueError) or "token" in str(e).lower() else 500
        )
        return HTMLResponse(
            content=f"""
            <html>
                <body style="font-family: Arial; text-align: center; padding-top: 50px;">
                    <h1 style="color: #d93025;">Action Failed</h1>
                    <p>There was an error processing your request: {str(e)}</p>
                    {debug_info}
                    <p>Check the Cloud Run logs for more details.</p>
                </body>
            </html>
        """,
            status_code=status_code,
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
