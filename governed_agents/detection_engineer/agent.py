"""Detection Engineer specialist — Chronicle SIEM YARA-L 2.0 validation & coverage.

Governed by IAM v3 CEL tool allowlist (`terraform/50-policies-egress.tf`):
  * Allowed on Chronicle OneMCP: YARA-L 2.0 syntax validation, rule catalog
    queries, rule coverage evaluation, synthetic UDM event generation, UDM
    verification queries, reference list reads, and log type discovery
    (`validate_rule`, `list_rules`, `get_rule`, `list_rule_detections`,
    `list_rule_errors`, `evaluate_rule_coverage`, `generate_synthetic_events`,
    `udm_search`, `translate_udm_query`, `get_reference_list`, `list_log_types`).
  * Denied at Agent Gateway (advertised so policy blocks are live):
    `delete_feed`, `activate_parser`, `deactivate_parser`.

Note on terminology: Chronicle SIEM detection rules are written in YARA-L 2.0
(UDM event correlation rules), which is distinct from standard YARA (file/payload
binary pattern matching).

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


APP_NAME = "detection_engineer_agent"
AGENT_VERSION = "1.0.0"

MODEL = os.getenv("MODEL", "gemini-3.5-flash")
MODEL_LOCATION = os.getenv("MODEL_LOCATION", "global")

CHRONICLE_PROJECT_ID = os.environ["CHRONICLE_PROJECT_ID"]
CHRONICLE_CUSTOMER_ID = os.environ["CHRONICLE_CUSTOMER_ID"]
CHRONICLE_REGION = os.getenv("CHRONICLE_REGION", "us")

ALLOWED_TOOLS = [
    "validate_rule",
    "list_rules",
    "get_rule",
    "list_rule_detections",
    "list_rule_errors",
    "evaluate_rule_coverage",
    "generate_synthetic_events",
    "udm_search",
    "translate_udm_query",
    "get_reference_list",
    "list_log_types",
]

ADVERTISED_DENIED_TOOLS = [
    "delete_feed",
    "activate_parser",
    "deactivate_parser",
]

chronicle_tools = build_chronicle_toolset(
    project_id=CHRONICLE_PROJECT_ID,
    tool_filter=ALLOWED_TOOLS + ADVERTISED_DENIED_TOOLS,
)

DESCRIPTION = (
    "Chronicle SIEM Detection Engineer specialist that authors, validates, "
    "and evaluates YARA-L 2.0 UDM event detection rules via Chronicle OneMCP."
)

INSTRUCTION = f"""\
You are the Detection Engineer specialist in a governed Security Operations
Center (SOC), responsible for Chronicle SIEM YARA-L 2.0 detection engineering.

Terminology discipline:
  * Always distinguish Chronicle SIEM **YARA-L 2.0** (UDM event detection and
    correlation rules with `meta`, `events`, `match`, `outcome`, and `condition`
    sections) from standard **YARA** (file or payload binary/string signature
    matching). Never conflate the two languages.

Default tenant parameters (always pass these to Chronicle MCP tools unless the
caller explicitly overrides them):
  * `project_id`: `{CHRONICLE_PROJECT_ID}`
  * `customer_id`: `{CHRONICLE_CUSTOMER_ID}`
  * `region`: `{CHRONICLE_REGION}`

Select the Chronicle MCP tool matching what was asked:
  * Drafting or validating a YARA-L 2.0 UDM detection rule: write valid YARA-L 2.0
    syntax and verify it with `validate_rule`
  * Listing or reading existing YARA-L 2.0 rules, detections, or compilation/runtime
    errors: `list_rules`, `get_rule`, `list_rule_detections`, `list_rule_errors`
  * Coverage testing or synthetic UDM validation: `evaluate_rule_coverage`,
    `generate_synthetic_events`
  * Checking UDM fields, log types, or reference lists: `udm_search`,
    `translate_udm_query`, `list_log_types`, `get_reference_list`
  * Feed deletion (`delete_feed`) or parser activation/deactivation
    (`activate_parser`, `deactivate_parser`): call the requested tool directly.

CRITICAL GOVERNANCE RULE:
Destructive ingestion administration tools (`delete_feed`, `activate_parser`,
`deactivate_parser`) are refused at the Agent Gateway by IAM v3 tool-allowlist
policy. Never self-refuse in prose: always invoke the requested tool so the
gateway evaluates and logs the denial. Do not use emojis.
"""

detection_engineer_llm = LlmAgent(
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
        agent=detection_engineer_llm,
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
            id="yaral2_rule_validation",
            name="YARA-L 2.0 detection rule authoring and validation",
            description=(
                "Authors and validates Chronicle SIEM YARA-L 2.0 UDM event "
                "detection rules, inspects existing rules, and evaluates coverage "
                "(distinct from standard file/payload YARA)."
            ),
            tags=["chronicle", "yaral2", "detection-engineering", "udm"],
            examples=[
                "Draft and validate a YARA-L 2.0 rule detecting PowerShell encoded command execution",
                "List existing YARA-L 2.0 detection rules in Chronicle SIEM",
            ],
        ),
        AgentSkill(
            id="parser_and_feed_admin",
            name="Chronicle parser and feed administration",
            description=(
                "Attempts parser activation/deactivation or feed deletion via "
                "Chronicle MCP (governed by Agent Gateway tool allowlist)."
            ),
            tags=["chronicle", "parsers", "feeds", "admin"],
            examples=["Deactivate parser parser-01 for WINDOWS_AD"],
        ),
    ],
)
agent_card.version = AGENT_VERSION

root_agent = A2aAgent(
    agent_card=agent_card,
    agent_executor_builder=_build_executor,
)
