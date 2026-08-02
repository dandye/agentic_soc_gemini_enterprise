---
type: "Documentation"
title: "ChatOps Native Chat App Migration"
description: "Architecture and setup for the native Google Chat App ChatOps integration: background action execution, Cloud Tasks decoupling, and in-card state synchronization."
resource: "docs/chatops_chat_app.md"
timestamp: "2026-08-01T23:30:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Claude Code"
  timestamp: "2026-08-01T23:30:00Z"
---

# ChatOps Native Chat App Migration

This document covers the migration from Google Chat incoming webhooks to a
registered Google Chat App (issue #62), which delivers three UX and
reliability upgrades:

1. **Background execution (zero-tab UX).** Card buttons use native
   `onClick.action` payloads. Clicking Approve or Deny executes the action
   in the background instead of opening an empty browser tab.
2. **Decoupled latency.** Google Chat requires a response to interaction
   events within 30 seconds, but Agent Engine queries can take minutes. A
   Cloud Tasks queue separates the immediate acknowledgment from the agent
   execution.
3. **State synchronization.** The original card updates itself: first to a
   "Processing" state on click, then to the confirmed (or honestly failed)
   outcome once the agent completes.

## Why a Chat App is required

Messages posted through an incoming webhook cannot carry `onClick.action`
buttons -- Google Chat only routes `CARD_CLICKED` interaction events to the
app that posted the message. That structural constraint is why the legacy
flow used `openLink` buttons pointing at a signed URL, and why fixing the
empty-tab UX requires migrating message posting to the Chat REST API.

## Architecture

```
Agent Engine (chatops_tools.py)
    |  CHATOPS_MODE=chat_app
    v
chat_api.post_card_as_app()  --- Chat REST API --->  Google Chat space
    (openLink buttons auto-converted to action buttons at this seam)

Analyst clicks Approve
    |
    v
POST /chat/events  (Cloud Run: chat_app_handler.py)
    1. Verify Google-issued bearer JWT (issuer chat@system.gserviceaccount.com,
       audience GCP_PROJECT_NUMBER)
    2. HMAC-verify the signed action token (security.py, defense in depth)
    3. Enqueue Cloud Tasks task (task name = token hash, so double-clicks dedupe)
    4. Return an in-place "Processing" card update -- well inside 30 seconds
    |
    v
Cloud Tasks queue (chatops-actions)
    |  OIDC-authenticated HTTP push
    v
POST /tasks/execute  (same Cloud Run service)
    1. Verify the Cloud Tasks OIDC token (audience CHATOPS_SERVICE_URL)
    2. Re-verify the HMAC token
    3. Run the Agent Engine query (may take minutes)
    4. PATCH the original card with the confirmed or failed outcome
```

The legacy `GET /action` route is still served by the new handler so signed
`openLink` URLs generated before the cutover (1 hour TTL) keep working.

### The one-seam template migration

All 55 card templates build their buttons through
`card_client.generate_action_url()`, producing
`onClick: {openLink: {url: <base>/action?t=<signed token>}}`. In `chat_app`
mode, `chat_api.convert_openlink_to_action()` rewrites exactly those buttons
into native action payloads at dispatch time
(`chatops_tools.send_raw_card`). No template file changes; informational
links (for example "View in Chronicle") are left as `openLink`.

### Failure semantics

- If the queue is unavailable, the click is rejected with an explicit
  "action was NOT executed" message posted alongside the card (the approval
  card and its buttons survive for a retry). Delivery success is never
  fabricated.
- The outcome card renders the agent's actual response ("Action
  Processed"), not a fabricated confirmation -- the agent may decline or
  report partial failure, and the human sees what it said.
- The agent query is bounded by `CHATOPS_AGENT_TIMEOUT` (default 540s), and
  the Cloud Tasks dispatch deadline is set above it so the queue never
  redelivers a still-running task (redelivery would double-execute).
- If the agent query fails or times out, the card is updated with the
  failure and the worker still returns HTTP 200 -- retrying would duplicate
  agent executions; the failure is surfaced to the human instead. Card
  updates themselves retry three times before giving up loudly in logs.
- Analyst double-clicks dedupe via deterministic Cloud Tasks task names
  derived from the token hash; the duplicate click re-acks with the
  Processing card.
- Tokens that fail HMAC verification at the worker are dropped with HTTP
  200 (a 4xx would retry every queued task to max attempts after a secret
  rotation).

### Security posture

- Interaction events require a valid Google-issued JWT; the worker requires
  a Cloud Tasks OIDC token, pinned to `CHATOPS_INVOKER_SA` when set.
- The HMAC layer fails closed on Cloud Run: a missing
  `CHRONICLE_CHATOPS_SECRET` raises instead of falling back to the public
  development secret.
- `CHATOPS_SKIP_JWT_VERIFY` and `CHATOPS_INLINE_EXECUTION` are hard-blocked
  when running on Cloud Run (`K_SERVICE` present).
- `CHATOPS_APPROVER_EMAILS` (optional, comma-separated) restricts who may
  click Approve/Deny; unset means any member of the space can approve.
- User-supplied event text (display names, function names) is HTML-escaped
  before rendering into cards or the legacy HTML pages.
- Known residual gaps tracked for follow-up: legacy `/action` tokens are
  replayable within their 1 hour TTL (no consumed-token store), and tokens
  are not bound to a specific space or message.

## Setup

### 1. Deploy the handler and queue

```bash
just chatops-deploy-app      # Cloud Run: /chat/events, /tasks/execute, /action
just chatops-create-queue    # Cloud Tasks queue (default: chatops-actions)
```

On the first deploy, copy the service URL into `.env` as
`CHATOPS_SERVICE_URL` and redeploy so the worker's OIDC audience matches.

### 2. Register the Chat App (manual, one-time)

```bash
just chatops-registration-guide
```

This prints the console steps: enable `chat.googleapis.com`, configure the
app's interactive features with the HTTP endpoint URL
`<CHATOPS_SERVICE_URL>/chat/events`, set visibility, and add the app to the
SOC space.

### 3. Configure the environment

```bash
# .env
CHATOPS_MODE=chat_app
CHAT_SPACE=spaces/<space id>
GCP_PROJECT_NUMBER=<project number>
CHATOPS_SERVICE_URL=https://<service>.a.run.app
CHATOPS_INVOKER_SA=<sa with run.invoker on the handler>
```

Validate with:

```bash
just chatops-verify
```

Then redeploy the agents so the new mode reaches Agent Engine.

### Migration and rollback

`CHATOPS_MODE` defaults to `webhook`; the legacy path is untouched until you
opt in. Rolling back is removing `CHATOPS_MODE=chat_app` from the
environment and redeploying -- no code changes involved.

### IAM summary

| Identity | Role | Why |
|---|---|---|
| Cloud Run service SA | `roles/cloudtasks.enqueuer` | enqueue action tasks |
| Cloud Run service SA | `chat.bot` scope (app auth) | patch cards as the app |
| `CHATOPS_INVOKER_SA` | `roles/run.invoker` on the handler | Cloud Tasks push auth |
| Agent Engine SA | `chat.bot` scope (app auth) | post cards as the app |

App auth requires the Chat App to be registered in the same GCP project as
the identities above (or `GOOGLE_APPLICATION_CREDENTIALS` pointing at the
app project's service account key).

## Human decision semantics

Button clicks reach the agent session as a rigid template, never free
text: `HUMAN DECISION via ChatOps [decision=APPROVED|DENIED|UNSPECIFIED]
action="..."`. A Deny explicitly instructs the agent NOT to execute and to
record the denial; an unparseable decision demands fresh confirmation
before any state change. The action name is sanitized (single-line,
bounded, control phrases redacted) before it may appear in the session --
the approval channel writes into a tool-bearing agent and must not be an
injection path. Raw values are preserved in the audit trail instead.

## Audit trail

Every approval lifecycle transition emits a single-line JSON event
(marker `CHATOPS_AUDIT`, versioned schema) via the `chatops.audit`
logger: click accepted/rejected (invalid token, unauthorized approver),
enqueued/deduped/enqueue-failed, worker start, decision injected into the
session, outcome (success/failure/timeout), and legacy `/action`
executions. Events carry approver display name and email, action (raw --
this is how an auditor detects injection attempts), decision, session and
message correlation, and outcome detail.

On Cloud Run these land in Cloud Logging automatically. For durable,
queryable, append-only evidence, export them to BigQuery once:

```bash
bq mk --dataset "${GCP_PROJECT_ID}:chatops_audit"
gcloud logging sinks create chatops-audit-sink \
  "bigquery.googleapis.com/projects/${GCP_PROJECT_ID}/datasets/chatops_audit" \
  --log-filter='resource.type="cloud_run_revision" AND jsonPayload.marker="CHATOPS_AUDIT" OR textPayload:"CHATOPS_AUDIT"'
# Grant the sink's writer identity (printed by the previous command)
# BigQuery Data Editor on the dataset.
```

Audit emission never raises into the request path; a serialization
failure degrades to a minimal `audit_emit_error` event.

## Development

- `CHATOPS_INLINE_EXECUTION=true` executes actions with FastAPI background
  tasks instead of Cloud Tasks (dev only: Cloud Run may throttle CPU after
  the response).
- `CHATOPS_SKIP_JWT_VERIFY=true` disables bearer verification for local
  testing (never in production).
- Offline unit tests: `python agent_soc_manager/tools/chatops/test_chat_app.py`
