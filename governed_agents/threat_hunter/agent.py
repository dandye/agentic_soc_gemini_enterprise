"""Threat Hunter specialist — read-only Chronicle SIEM UDM hunt & alert triage.

Governed by IAM v3 CEL tool allowlist (`terraform/50-policies-egress.tf`):
  * Allowed on Chronicle OneMCP: read-only UDM search, alert retrieval, entity
    summaries, IOC matches, and rule/detection inspection (`udm_search`,
    `search_raw_logs`, `translate_udm_query`, `list_security_alerts`,
    `get_security_alert`, `fetch_alert_data`, `search_entity`, `summarize_entity`,
    `get_ioc_match`, `list_rules`, `get_rule`, `list_rule_detections`).
  * Denied at Agent Gateway (advertised here so policy blocks are live and
    observable): `create_rule`, `delete_feed`, `create_reference_list`,
    `execute_manual_action`.

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
from secops_mcp import build_chronicle_toolset, chronicle_before_model_callback
from vertexai.agent_engines.templates.a2a import A2aAgent, create_agent_card


APP_NAME = "threat_hunter_agent"
AGENT_VERSION = "1.0.0"

MODEL = os.getenv("MODEL", "gemini-3.5-flash")
MODEL_LOCATION = os.getenv("MODEL_LOCATION", "global")

CHRONICLE_PROJECT_ID = os.environ["CHRONICLE_PROJECT_ID"]
CHRONICLE_CUSTOMER_ID = os.environ["CHRONICLE_CUSTOMER_ID"]
CHRONICLE_REGION = os.getenv("CHRONICLE_REGION", "us")

ALLOWED_TOOLS = [
    "udm_search",
    "search_raw_logs",
    "translate_udm_query",
    "list_security_alerts",
    "get_security_alert",
    "fetch_alert_data",
    "search_entity",
    "summarize_entity",
    "get_ioc_match",
    "list_rules",
    "get_rule",
    "list_rule_detections",
]

# Advertised in the MCP tool filter and agent skills so an operator or red-team
# prompt asking Threat Hunter to mutate SIEM state triggers a real HTTP 403
# denial at Agent Gateway rather than an unverified LLM self-refusal.
ADVERTISED_DENIED_TOOLS = [
    "list_feeds",
    "create_rule",
    "delete_feed",
    "create_reference_list",
    "execute_manual_action",
]

chronicle_tools = build_chronicle_toolset(
    project_id=CHRONICLE_PROJECT_ID,
    tool_filter=ALLOWED_TOOLS + ADVERTISED_DENIED_TOOLS,
)

DESCRIPTION = (
    "Chronicle SIEM Threat Hunter specialist that runs UDM event searches, "
    "triages security alerts, inspects rules and ingestion feeds, and checks IOC matches."
)

INSTRUCTION = f"""\
You are the Threat Hunter specialist in a governed Security Operations Center (SOC),
connected to Google SecOps (Chronicle SIEM) via the Chronicle MCP server.

Default tenant parameters (always pass these to Chronicle MCP tools unless the
caller explicitly overrides them):
  * `project_id`: `{CHRONICLE_PROJECT_ID}`
  * `customer_id`: `{CHRONICLE_CUSTOMER_ID}`
  * `region`: `{CHRONICLE_REGION}`

Choose the Chronicle MCP tool matching what was asked:
  * Recent security alerts or alert queue inspection: `list_security_alerts`,
    `get_security_alert`, `fetch_alert_data`
  * UDM telemetry hunts (processes, DNS, network connections, logins):
    `udm_search` (or `translate_udm_query` when translating natural language to UDM)
  * Raw unparsed log search: `search_raw_logs`
  * Host, user, IP, domain, or hash entity context in Chronicle: `search_entity`,
    `summarize_entity`, `get_ioc_match`
  * Inspecting existing Chronicle SIEM YARA-L 2.0 detection rules and detections:
    `list_rules`, `get_rule`, `list_rule_detections`
  * Inspecting configured Chronicle data ingestion feeds: `list_feeds`
  * Creating a rule (`create_rule`), deleting a data feed (`delete_feed`),
    creating a reference list (`create_reference_list`), or running a manual
    SOAR action (`execute_manual_action`): call the matching tool directly when
    asked.

Some of those calls will be refused at the Agent Gateway, and that is expected.
Call the matching tool anyway; never answer or decline from your own knowledge
instead.

Always distinguish Chronicle SIEM YARA-L 2.0 rules (UDM event detection rules)
from standard YARA rules (file/payload binary pattern matching). Do not use emojis.
"""

threat_hunter_llm = LlmAgent(
    name=APP_NAME,
    model=Gemini(model=MODEL, client_kwargs={"location": MODEL_LOCATION}),
    description=DESCRIPTION,
    instruction=INSTRUCTION,
    tools=[chronicle_tools],
    before_model_callback=chronicle_before_model_callback,
)


def _build_executor() -> A2aAgentExecutor:
    runner = Runner(
        app_name=APP_NAME,
        agent=threat_hunter_llm,
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
            id="udm_threat_hunt",
            name="Chronicle UDM threat hunting and alert triage",
            description=(
                "Searches Chronicle SIEM UDM events, lists recent security alerts, "
                "summarizes host/user/IP entities, and checks IOC matches."
            ),
            tags=["chronicle", "siem", "udm", "alerts", "threat-hunting"],
            examples=[
                "List the 5 most recent security alerts in Chronicle SIEM",
                "Run a UDM search for recent network or process events",
            ],
        ),
        AgentSkill(
            id="siem_feed_and_rule_mutation",
            name="Chronicle feed administration and rule creation",
            description=(
                "Attempts Chronicle SIEM feed deletion, rule creation, or reference "
                "list creation via Chronicle MCP (governed by Agent Gateway allowlist)."
            ),
            tags=["chronicle", "feeds", "rules", "admin"],
            examples=[
                "Delete Chronicle feed feed-12345",
                "Create a new reference list in Chronicle",
            ],
        ),
    ],
)
agent_card.version = AGENT_VERSION

root_agent = A2aAgent(
    agent_card=agent_card,
    agent_executor_builder=_build_executor,
)
