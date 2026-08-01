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

import asyncio
import hashlib
import html
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


# Per-turn budget for the Agent Engine query; also sizes the Cloud Tasks
# dispatch deadline so the queue never redelivers a still-running task
# (redelivery would double-execute an approved action).
AGENT_QUERY_TIMEOUT = float(os.environ.get("CHATOPS_AGENT_TIMEOUT", "540"))


def _dev_flag(name: str) -> bool:
    """Reads a dev-only toggle, hard-blocked on Cloud Run.

    CHATOPS_SKIP_JWT_VERIFY and CHATOPS_INLINE_EXECUTION must never weaken a
    deployed service; K_SERVICE is set by Cloud Run.
    """
    if os.environ.get("K_SERVICE"):
        return False
    return os.environ.get(name, "").lower() in ("1", "true", "yes")


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
    claims = id_token.verify_oauth2_token(token, AuthRequest(), audience=audience)

    # Audience alone proves any Google principal minted a token for this URL;
    # pin the caller to the configured invoker service account when set.
    invoker = os.environ.get("CHATOPS_INVOKER_SA")
    if invoker and claims.get("email") != invoker:
        raise ValueError(f"OIDC caller {claims.get('email')} is not {invoker}")
    return claims


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
    elif isinstance(raw_action, dict):
        parameters.update(raw_action)

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
    # "Processed", not "Confirmed": the detail carries the agent's actual
    # response, and the agent may have declined or partially completed the
    # action even when the query itself succeeded.
    status = "Processed" if succeeded else "Failed"
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
    # NEW_MESSAGE, not UPDATE_MESSAGE: replacing the approval card on a
    # transient failure would destroy its buttons and leave the analyst no
    # way to retry.
    return {
        "actionResponse": {"type": "NEW_MESSAGE"},
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
                # Outlive the agent-query budget: Cloud Tasks redelivers on
                # dispatch-deadline expiry, which would double-execute an
                # approved action.
                "dispatch_deadline": {"seconds": int(AGENT_QUERY_TIMEOUT) + 60},
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
    # Capture the agent's actual response instead of fabricating success:
    # the agent may decline or report a partial failure, and the outcome
    # card must reflect what it said.
    texts: list[str] = []
    async for event in remote_app.async_stream_query(
        user_id=user_id, session_id=session_id, message=user_input
    ):
        logger.debug(f"Agent event: {event}")
        try:
            for part in (event.get("content") or {}).get("parts") or []:
                text = part.get("text")
                if text:
                    texts.append(text)
        except AttributeError:
            continue
    logger.info(f"Agent Engine query completed for session {session_id}")
    if texts:
        agent_reply = texts[-1].strip()
        if len(agent_reply) > 1500:
            agent_reply = agent_reply[:1500] + "..."
        return f"Agent response: {agent_reply}"
    return (
        f"The agent processed '{action}' but returned no text response. "
        "Check the session transcript to confirm the outcome."
    )


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
        detail = await asyncio.wait_for(
            _run_agent_query(
                action=action,
                session_id=payload["session_id"],
                agent_engine_id=payload["agent_engine_id"],
                user_id=payload.get("user_id") or "vais-query-reasoning-engine",
            ),
            timeout=AGENT_QUERY_TIMEOUT,
        )
        card = _outcome_card(action, requester, succeeded=True, detail=detail)
    except TimeoutError:
        logger.error(f"Agent query timed out for action '{action}'")
        card = _outcome_card(
            action,
            requester,
            succeeded=False,
            detail=(
                f"The agent did not complete within {int(AGENT_QUERY_TIMEOUT)}s. "
                "The action may still be running; check the session transcript "
                "before retrying."
            ),
        )
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

    if not message_name:
        logger.warning(
            f"No message_name for action '{action}'; outcome not rendered to Chat."
        )
        return

    # The outcome must reach the human: a swallowed patch failure leaves the
    # card on "Processing" forever for an action that already ran. Retry
    # locally (returning non-2xx instead would re-execute the agent query).
    for attempt in range(3):
        try:
            await update_card(message_name, card)
            return
        except Exception as e:
            logger.error(
                f"Failed to update card {message_name} "
                f"(attempt {attempt + 1}/3): {e}"
            )
            await asyncio.sleep(2 * (attempt + 1))
    logger.error(
        f"Giving up updating card {message_name}; outcome for '{action}' "
        "was not rendered to Chat."
    )


@app.post("/chat/events")
async def chat_events(request: Request, background_tasks: BackgroundTasks):
    """Handles Google Chat interaction events for the registered Chat App."""
    if not _dev_flag("CHATOPS_SKIP_JWT_VERIFY"):
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
            return _error_card(f"Unknown action function: {html.escape(str(function))}")

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

        user = event.get("user") or {}
        # Optional approver allowlist: without it, any member of the space
        # can approve state-changing actions.
        allowlist = [
            entry.strip().lower()
            for entry in os.environ.get("CHATOPS_APPROVER_EMAILS", "").split(",")
            if entry.strip()
        ]
        if allowlist and (user.get("email") or "").lower() not in allowlist:
            logger.warning(f"Rejected click from unauthorized user {user.get('email')}")
            return _error_card(
                "You are not authorized to approve this action. It was NOT "
                "executed. (CHATOPS_APPROVER_EMAILS)"
            )

        action = payload.get("action", "unknown action")
        requester = html.escape(user.get("displayName", "unknown user"))
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

        if _dev_flag("CHATOPS_INLINE_EXECUTION"):
            # Dev-only fallback (hard-blocked on Cloud Run): execute within
            # this instance after responding.
            background_tasks.add_task(_execute_and_sync, task_payload)
        else:
            try:
                # to_thread: the Cloud Tasks client is sync/gRPC; blocking the
                # event loop here would stall every concurrent /chat/events
                # request against the 30-second Chat deadline.
                await asyncio.to_thread(_enqueue_task, task_payload)
            except Exception as e:
                if type(e).__name__ == "AlreadyExists":
                    # Deterministic task name collision: this exact token is
                    # already queued or ran recently (analyst double-click).
                    # The first click's execution stands; just re-ack.
                    logger.info(f"Duplicate click for action '{action}'; deduped.")
                    processing = _processing_card(action, requester)
                    return {
                        "actionResponse": {"type": "UPDATE_MESSAGE"},
                        "cardsV2": processing["cardsV2"],
                    }
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
    if not _dev_flag("CHATOPS_SKIP_JWT_VERIFY"):
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
        # 200, not 4xx: after a secret rotation every queued token fails
        # verification, and a non-2xx would make Cloud Tasks retry each one
        # to max attempts. The task is terminally dropped either way.
        logger.error(f"Worker dropped task with invalid token: {e}")
        return {"status": "dropped", "error": f"Invalid token: {e}"}

    body["session_id"] = payload.get("session_id")
    body["agent_engine_id"] = payload.get("agent_engine_id")
    body["user_id"] = payload.get("user_id")
    # Only token-verified fields drive execution; the queue body's action is
    # never trusted.
    body["action"] = payload.get("action", "unknown action")

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
                <p>{html.escape(detail)}</p>
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
                    <p>There was an error processing your request: {html.escape(str(e))}</p>
                </body>
            </html>
            """,
            status_code=500,
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
