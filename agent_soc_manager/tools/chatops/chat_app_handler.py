"""Native Google Chat App handler for ChatOps (issue #62).

Replaces the openLink/empty-tab flow with background action execution:

    POST /chat/events   Chat interaction events (CARD_CLICKED, MESSAGE,
                        ADDED_TO_SPACE). Verifies the Google-issued bearer
                        JWT, HMAC-verifies the signed action token, enqueues
                        a Cloud Tasks task, and immediately returns an
                        in-place "Processing" card update -- well inside
                        Google Chat's 30-second response deadline.
    POST /tasks/execute Cloud Tasks worker. Verifies the OIDC bearer token,
                        re-verifies the HMAC token, runs the Agent Engine
                        query (which may take minutes), then patches the
                        original card with the confirmed outcome.
    GET  /action        Legacy signed-URL route kept for in-flight openLink
                        tokens during cutover (1 hour TTL).

GCP-only libraries (google-auth verification, Cloud Tasks, Vertex AI) are
imported lazily inside functions so the module imports cleanly in offline
unit-test environments.
"""

import hashlib
import json
import logging
import os

from fastapi import BackgroundTasks, FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse


try:  # Package layout (local dev, Agent Engine extra_packages)
    from agent_soc_manager.tools.chatops.security import verify_signed_payload
except ImportError:  # Flat layout (Cloud Run container copies files into /app)
    from security import verify_signed_payload

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ChatOps Chat App Handler")

CHAT_ISSUER = "chat@system.gserviceaccount.com"
CHAT_CERTS_URL = (
    "https://www.googleapis.com/service_accounts/v1/metadata/x509/"
    "chat@system.gserviceaccount.com"
)


def _bearer_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :]
    return None


def _verify_chat_jwt(token: str) -> dict:
    """Verifies a Google Chat interaction event bearer JWT.

    Chat signs events with the chat@system.gserviceaccount.com identity;
    the audience is this app's GCP project number.
    """
    from google.auth.transport.requests import Request as AuthRequest
    from google.oauth2 import id_token

    audience = os.environ.get("GCP_PROJECT_NUMBER")
    if not audience:
        raise ValueError("GCP_PROJECT_NUMBER is not set on the server")

    claims = id_token.verify_token(
        token, AuthRequest(), audience=audience, certs_url=CHAT_CERTS_URL
    )
    if claims.get("iss") != CHAT_ISSUER:
        raise ValueError(f"Unexpected JWT issuer: {claims.get('iss')}")
    return claims


def _verify_tasks_oidc(token: str) -> dict:
    """Verifies the OIDC bearer token Cloud Tasks attaches to worker calls."""
    from google.auth.transport.requests import Request as AuthRequest
    from google.oauth2 import id_token

    audience = os.environ.get("CHATOPS_SERVICE_URL")
    if not audience:
        raise ValueError("CHATOPS_SERVICE_URL is not set on the server")
    return id_token.verify_oauth2_token(token, AuthRequest(), audience=audience)


def _extract_invoked_function(event: dict) -> tuple[str | None, dict]:
    """Returns (function_name, parameters) from either event schema.

    Chat delivers card clicks as `common.invokedFunction` + `common.parameters`
    (newer schema) or `action.actionMethodName` + `action.parameters` (older
    schema). Parameters normalize to a plain dict.
    """
    common = event.get("common") or {}
    action = event.get("action") or {}

    function = common.get("invokedFunction") or action.get("actionMethodName")

    parameters: dict = {}
    raw_common = common.get("parameters")
    if isinstance(raw_common, dict):
        parameters.update(raw_common)
    raw_action = action.get("parameters")
    if isinstance(raw_action, list):
        for item in raw_action:
            if isinstance(item, dict) and "key" in item:
                parameters[item["key"]] = item.get("value")

    return function, parameters


def _processing_card(action: str, requester: str) -> dict:
    return {
        "cardsV2": [
            {
                "cardId": "chatops-processing",
                "card": {
                    "header": {
                        "title": "Action In Progress",
                        "subtitle": f"Requested by {requester}",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "decoratedText": {
                                        "topLabel": "Action",
                                        "text": action,
                                        "startIcon": {"knownIcon": "CLOCK"},
                                    }
                                },
                                {
                                    "textParagraph": {
                                        "text": (
                                            "Processing... The AI agent is executing "
                                            "this action. This card will update "
                                            "automatically when it completes."
                                        )
                                    }
                                },
                            ]
                        }
                    ],
                },
            }
        ]
    }


def _outcome_card(action: str, requester: str, succeeded: bool, detail: str) -> dict:
    status = "Confirmed" if succeeded else "Failed"
    icon = "STAR" if succeeded else "DESCRIPTION"
    return {
        "cardsV2": [
            {
                "cardId": "chatops-outcome",
                "card": {
                    "header": {
                        "title": f"Action {status}",
                        "subtitle": f"Requested by {requester}",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "decoratedText": {
                                        "topLabel": "Action",
                                        "text": action,
                                        "startIcon": {"knownIcon": icon},
                                    }
                                },
                                {"textParagraph": {"text": detail}},
                            ]
                        }
                    ],
                },
            }
        ]
    }


def _error_card(message: str) -> dict:
    return {
        "actionResponse": {"type": "UPDATE_MESSAGE"},
        "cardsV2": [
            {
                "cardId": "chatops-error",
                "card": {
                    "header": {"title": "Action Rejected"},
                    "sections": [{"widgets": [{"textParagraph": {"text": message}}]}],
                },
            }
        ],
    }


def _enqueue_task(payload: dict) -> str:
    """Enqueues the action for background execution via Cloud Tasks.

    The task name is derived from the token hash, so an analyst
    double-clicking a button dedupes to a single execution (Cloud Tasks
    rejects duplicate task names for roughly the token's 1 hour TTL).
    """
    from google.cloud import tasks_v2

    project = os.environ.get("GCP_PROJECT_ID")
    location = os.environ.get("CHATOPS_TASKS_LOCATION") or os.environ.get(
        "GCP_LOCATION", "us-central1"
    )
    queue = os.environ.get("CHATOPS_TASKS_QUEUE", "chatops-actions")
    service_url = os.environ.get("CHATOPS_SERVICE_URL")
    invoker_sa = os.environ.get("CHATOPS_INVOKER_SA")

    if not project or not service_url:
        raise ValueError("GCP_PROJECT_ID and CHATOPS_SERVICE_URL must be set")

    client = tasks_v2.CloudTasksClient()
    parent = client.queue_path(project, location, queue)
    digest = hashlib.sha256(payload["token"].encode("utf-8")).hexdigest()[:32]

    http_request = {
        "http_method": tasks_v2.HttpMethod.POST,
        "url": f"{service_url.rstrip('/')}/tasks/execute",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload).encode("utf-8"),
    }
    if invoker_sa:
        http_request["oidc_token"] = {
            "service_account_email": invoker_sa,
            "audience": service_url,
        }

    task = client.create_task(
        request={
            "parent": parent,
            "task": {
                "name": f"{parent}/tasks/act-{digest}",
                "http_request": http_request,
            },
        }
    )
    logger.info(f"Enqueued ChatOps task: {task.name}")
    return task.name


async def _run_agent_query(
    action: str, session_id: str, agent_engine_id: str, user_id: str
) -> str:
    """Runs the Agent Engine query for a confirmed action (may take minutes)."""
    import vertexai
    from vertexai import agent_engines

    project = os.environ.get("GCP_PROJECT_ID")
    location = os.environ.get("GCP_LOCATION", "us-central1")
    if not project:
        raise ValueError("GCP_PROJECT_ID not set on server")

    vertexai.init(project=project, location=location)
    remote_app = agent_engines.get(agent_engine_id)
    user_input = f"USER ACTION CONFIRMED via ChatOps: {action}"

    logger.info(f"Querying Agent Engine for action: {action} (user: {user_id})")
    async for event in remote_app.async_stream_query(
        user_id=user_id, session_id=session_id, message=user_input
    ):
        logger.debug(f"Agent event: {event}")
    logger.info(f"Agent Engine query completed for session {session_id}")
    return f"The action '{action}' was processed by the AI agent."


async def _execute_and_sync(payload: dict) -> None:
    """Worker body: run the agent query, then sync state into the card."""
    try:  # Package vs flat layout, mirroring the module-level import
        from agent_soc_manager.tools.chatops.chat_api import update_card
    except ImportError:
        from chat_api import update_card

    action = payload.get("action", "unknown action")
    requester = payload.get("requester", "unknown user")
    message_name = payload.get("message_name")

    try:
        detail = await _run_agent_query(
            action=action,
            session_id=payload["session_id"],
            agent_engine_id=payload["agent_engine_id"],
            user_id=payload.get("user_id") or "vais-query-reasoning-engine",
        )
        card = _outcome_card(action, requester, succeeded=True, detail=detail)
    except Exception as e:
        logger.error(f"Agent execution failed for action '{action}': {e}")
        card = _outcome_card(
            action,
            requester,
            succeeded=False,
            detail=(
                f"The agent failed to execute this action: {e}. "
                "No state change was confirmed."
            ),
        )

    if message_name:
        try:
            await update_card(message_name, card)
        except Exception as e:
            logger.error(f"Failed to update card {message_name}: {e}")


@app.post("/chat/events")
async def chat_events(request: Request, background_tasks: BackgroundTasks):
    """Handles Google Chat interaction events for the registered Chat App."""
    skip_verify = os.environ.get("CHATOPS_SKIP_JWT_VERIFY", "").lower() in (
        "1",
        "true",
        "yes",
    )
    if not skip_verify:
        token = _bearer_token(request)
        if not token:
            return JSONResponse({"error": "Missing bearer token"}, status_code=401)
        try:
            _verify_chat_jwt(token)
        except Exception as e:
            logger.warning(f"Rejected Chat event with invalid JWT: {e}")
            return JSONResponse({"error": "Invalid bearer token"}, status_code=401)

    event = await request.json()
    event_type = event.get("type")

    if event_type == "ADDED_TO_SPACE":
        return {
            "text": (
                "SOC Agent ChatOps connected. Approval cards posted here will "
                "execute actions in the background when clicked."
            )
        }

    if event_type == "MESSAGE":
        return {
            "text": (
                "This app handles SOC approval cards. Interact with the "
                "buttons on incident cards; direct messages are not processed."
            )
        }

    if event_type == "CARD_CLICKED":
        function, parameters = _extract_invoked_function(event)
        if function != "execute_signed_action":
            return _error_card(f"Unknown action function: {function}")

        signed_token = parameters.get("token")
        if not signed_token:
            return _error_card("Missing action token. The card may be malformed.")

        try:
            payload = verify_signed_payload(signed_token)
        except ValueError as e:
            logger.warning(f"Rejected card click with invalid token: {e}")
            return _error_card(
                f"This action could not be verified and was NOT executed: {e}"
            )

        action = payload.get("action", "unknown action")
        requester = (event.get("user") or {}).get("displayName", "unknown user")
        message_name = (event.get("message") or {}).get("name")

        task_payload = {
            "token": signed_token,
            "action": action,
            "session_id": payload.get("session_id"),
            "agent_engine_id": payload.get("agent_engine_id"),
            "user_id": payload.get("user_id"),
            "requester": requester,
            "message_name": message_name,
        }

        inline = os.environ.get("CHATOPS_INLINE_EXECUTION", "").lower() in (
            "1",
            "true",
            "yes",
        )
        if inline:
            # Dev-only fallback: execute within this instance after responding.
            # Cloud Run may throttle CPU post-response; use Cloud Tasks in prod.
            background_tasks.add_task(_execute_and_sync, task_payload)
        else:
            try:
                _enqueue_task(task_payload)
            except Exception as e:
                logger.error(f"Failed to enqueue ChatOps task: {e}")
                return _error_card(
                    f"Could not queue this action for execution: {e}. "
                    "The action was NOT executed."
                )

        processing = _processing_card(action, requester)
        return {
            "actionResponse": {"type": "UPDATE_MESSAGE"},
            "cardsV2": processing["cardsV2"],
        }

    logger.info(f"Ignoring unhandled Chat event type: {event_type}")
    return {}


@app.post("/tasks/execute")
async def tasks_execute(request: Request):
    """Cloud Tasks worker endpoint: executes the agent query and syncs state."""
    skip_verify = os.environ.get("CHATOPS_SKIP_JWT_VERIFY", "").lower() in (
        "1",
        "true",
        "yes",
    )
    if not skip_verify:
        token = _bearer_token(request)
        if not token:
            return JSONResponse({"error": "Missing bearer token"}, status_code=401)
        try:
            _verify_tasks_oidc(token)
        except Exception as e:
            logger.warning(f"Rejected worker call with invalid OIDC token: {e}")
            return JSONResponse({"error": "Invalid bearer token"}, status_code=401)

    body = await request.json()
    signed_token = body.get("token")
    if not signed_token:
        return JSONResponse({"error": "Missing token"}, status_code=400)

    try:
        # Defense in depth: never trust the queue payload's IDs without
        # re-verifying the HMAC signature that minted them.
        payload = verify_signed_payload(signed_token)
    except ValueError as e:
        logger.error(f"Worker rejected invalid token: {e}")
        return JSONResponse({"error": f"Invalid token: {e}"}, status_code=400)

    body["session_id"] = payload.get("session_id")
    body["agent_engine_id"] = payload.get("agent_engine_id")
    body["user_id"] = payload.get("user_id")
    body["action"] = payload.get("action", body.get("action", "unknown action"))

    # Always 200 after this point: the outcome (success or failure) is
    # reported into the card itself. Non-2xx here would trigger Cloud Tasks
    # retries and duplicate agent executions.
    await _execute_and_sync(body)
    return {"status": "done"}


@app.get("/action", response_class=HTMLResponse)
async def legacy_action(t: str = Query(..., description="Signed action token")):
    """Legacy openLink route: kept so in-flight signed URLs work during cutover."""
    try:
        payload = verify_signed_payload(t)
        action = payload.get("action")
        session_id = payload.get("session_id")
        agent_engine_id = payload.get("agent_engine_id")
        if not action or not session_id or not agent_engine_id:
            raise ValueError("Incomplete payload inside token")

        detail = await _run_agent_query(
            action=action,
            session_id=session_id,
            agent_engine_id=agent_engine_id,
            user_id=payload.get("user_id") or "vais-query-reasoning-engine",
        )
        return f"""
        <html>
            <head><title>Action Confirmed</title></head>
            <body style="font-family: Arial; text-align: center; padding-top: 50px;">
                <h1>Action Confirmed</h1>
                <p>{detail}</p>
                <p>You can close this tab and return to Google Chat.</p>
            </body>
        </html>
        """
    except Exception as e:
        logger.error(f"Legacy action failed: {e}")
        return HTMLResponse(
            content=f"""
            <html>
                <body style="font-family: Arial; text-align: center; padding-top: 50px;">
                    <h1>Action Failed</h1>
                    <p>There was an error processing your request: {e}</p>
                </body>
            </html>
            """,
            status_code=500,
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
