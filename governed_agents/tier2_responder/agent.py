"""Tier-2 Incident Responder — SIEM alert response & governed containment.

Governed by TWO independent Agent Gateway controls:
  1. IAM v3 CEL tool allowlist (`terraform/50-policies-egress.tf`): permits SIEM
     alert triage/updates and reference-list containment (`list_security_alerts`,
     `get_security_alert`, `update_security_alert`, `fetch_alert_data`,
     `search_entity`, `summarize_entity`, `get_ioc_match`, `udm_search`,
     `get_reference_list`, `create_reference_list`, `update_reference_list`),
     while refusing ingestion admin tools (`delete_feed`, `activate_parser`).
  2. Vertex AI Semantic Governance (`terraform/65-semantic-governance.tf`):
     evaluates natural-language intent on `:generateContent` and blocks Tier-0
     Crown Jewel containment (`DC-*` / `PROD-DC-*` Domain Controllers and
     `admin@*` / `krbtgt` accounts) unless an approved `CHG-<digits>` emergency
     change-control ticket is supplied.

Deployed with `entrypoint_module = "agent"` / `entrypoint_object = "root_agent"`.
"""

from __future__ import annotations

import os

from a2a.types import AgentSkill
from google.adk.a2a.executor.a2a_agent_executor import A2aAgentExecutor
from google.adk.agents import LlmAgent
from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
from google.adk.models.google_llm import Gemini
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from response_tools import disable_compromised_account, isolate_endpoint_host
from secops_mcp import build_chronicle_toolset, chronicle_before_model_callback
from vertexai.agent_engines.templates.a2a import A2aAgent, create_agent_card


APP_NAME = "tier2_responder_agent"
AGENT_VERSION = "1.0.0"

MODEL = os.getenv("MODEL", "gemini-3.1-pro-preview")
MODEL_LOCATION = os.getenv("MODEL_LOCATION", "global")

CHRONICLE_PROJECT_ID = os.environ["CHRONICLE_PROJECT_ID"]
CHRONICLE_CUSTOMER_ID = os.environ["CHRONICLE_CUSTOMER_ID"]
CHRONICLE_REGION = os.getenv("CHRONICLE_REGION", "us")

ALLOWED_TOOLS = [
    "list_security_alerts",
    "get_security_alert",
    "update_security_alert",
    "fetch_alert_data",
    "search_entity",
    "summarize_entity",
    "get_ioc_match",
    "udm_search",
    "get_reference_list",
    "create_reference_list",
    "update_reference_list",
]

ADVERTISED_DENIED_TOOLS = [
    "delete_feed",
    "activate_parser",
]

chronicle_tools = build_chronicle_toolset(
    project_id=CHRONICLE_PROJECT_ID,
    tool_filter=ALLOWED_TOOLS + ADVERTISED_DENIED_TOOLS,
)

DESCRIPTION = (
    "Tier-2 Incident Responder specialist that updates Chronicle SIEM alerts, "
    "manages containment reference lists, isolates compromised hosts, and "
    "disables compromised accounts under Semantic Governance change control."
)

INSTRUCTION = f"""\
You are the Tier-2 Incident Responder specialist in a governed Security
Operations Center (SOC).

Default Chronicle SIEM tenant parameters:
  * `project_id`: `{CHRONICLE_PROJECT_ID}`
  * `customer_id`: `{CHRONICLE_CUSTOMER_ID}`
  * `region`: `{CHRONICLE_REGION}`

Select the tool matching the requested response action:
  * Endpoint host network isolation / quarantine (any hostname, including
    workstations `WKSTN-*` or Domain Controllers `DC-*`): call
    `isolate_endpoint_host(hostname=..., reason=..., change_ticket=...)`. Pass
    `change_ticket` ONLY when the caller explicitly provided a ticket ID; pass
    `""` otherwise. Never invent a `CHG-` ticket ID.
  * Account disablement / session revocation (any username, including standard
    users or privileged `admin@*` / `krbtgt` accounts): call
    `disable_compromised_account(username=..., reason=..., change_ticket=...)`.
    Pass `change_ticket` ONLY when explicitly provided by the caller.
  * SIEM alert status/verdict updates or reference-list IOC containment:
    `list_security_alerts`, `get_security_alert`, `update_security_alert`,
    `get_reference_list`, `create_reference_list`, `update_reference_list`,
    `search_entity`, `summarize_entity`, `udm_search`.
  * Feed deletion (`delete_feed`) or parser activation (`activate_parser`):
    call the requested tool directly.

CRITICAL GOVERNANCE RULE:
You refuse NOTHING yourself. Every authorization and Tier-0 Crown Jewel
change-control check lives outside you at the Agent Gateway (IAM v3 tool
allowlists and the Vertex AI Semantic Governance Policy Engine). If an operator
asks to isolate `DC-PROD-01` or disable `admin@example.com` without a `CHG-*`
ticket, you MUST still emit the `isolate_endpoint_host` or
`disable_compromised_account` tool call so Semantic Governance evaluates and
blocks the action at the gateway. Self-refusing in prose hides the security
control. Do not use emojis.
"""

tier2_llm = LlmAgent(
    name=APP_NAME,
    model=Gemini(model=MODEL, client_kwargs={"location": MODEL_LOCATION}),
    description=DESCRIPTION,
    instruction=INSTRUCTION,
    tools=[
        chronicle_tools,
        isolate_endpoint_host,
        disable_compromised_account,
    ],
    before_model_callback=chronicle_before_model_callback,
)


def _build_executor() -> A2aAgentExecutor:
    runner = Runner(
        app_name=APP_NAME,
        agent=tier2_llm,
        artifact_service=InMemoryArtifactService(),
        session_service=InMemorySessionService(),
        memory_service=InMemoryMemoryService(),
    )
    return A2aAgentExecutor(runner=runner)


agent_card = create_agent_card(
    agent_name=APP_NAME,
    description=DESCRIPTION,
    skills=[
        AgentSkill(
            id="endpoint_and_account_containment",
            name="Endpoint host isolation and compromised account disablement",
            description=(
                "Isolates compromised endpoint hosts (`isolate_endpoint_host`) "
                "and disables compromised accounts (`disable_compromised_account`), "
                "passing optional `CHG-*` change tickets for Tier-0 assets."
            ),
            tags=["containment", "edr", "iam", "incident-response"],
            examples=[
                "Isolate workstation WKSTN-FIN-042 due to active C2 beacon",
                "Isolate domain controller DC-PROD-01 immediately",
                "Isolate DC-PROD-01 under emergency change ticket CHG-20261105",
            ],
        ),
        AgentSkill(
            id="siem_alert_and_reference_list_response",
            name="Chronicle SIEM alert triage update and IOC reference lists",
            description=(
                "Updates Chronicle SIEM security alert status and manages "
                "containment reference lists."
            ),
            tags=["chronicle", "siem", "alerts", "reference-lists"],
            examples=[
                "Inspect and summarize security alerts for Tier-2 escalation"
            ],
        ),
    ],
)
agent_card.version = AGENT_VERSION

root_agent = A2aAgent(
    agent_card=agent_card,
    agent_executor_builder=_build_executor,
)
