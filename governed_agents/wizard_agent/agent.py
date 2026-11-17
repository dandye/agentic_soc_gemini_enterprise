"""Wizard Agent specialist: read-only Wiz Cloud Graph and Attack Path MCP agent.

Lateral isolation by design:
  * IAM v3 access policy (`terraform/52b-policies-wiz.tf`) grants this agent's
    SPIFFE workload principal access ONLY to the Wiz Remote MCP server in Agent
    Registry (`discover`, `execute`, and `tools/list`).
  * Auth Manager (`terraform/20-authmanager.tf`) grants `roles/agentidentity.user`
    on the Wiz OAuth provider ONLY to `wizard_agent`'s SPIFFE principal.
  * `enforce_wiz_readonly_callback` blocks mutating `wiz_execute` operations
    before network dispatch, keeping cloud posture and graph queries read-only.
  * Zero access to Chronicle SIEM, SOAR, GTI credentials, or host containment.

Deployed with `entrypoint_module = "agent"` / `entrypoint_object = "root_agent"`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from a2a.types import AgentSkill
from google.adk.a2a.executor.a2a_agent_executor import A2aAgentExecutor
from google.adk.agents import LlmAgent
from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService
from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
from google.adk.models.google_llm import Gemini
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.genai import types
from vertexai.agent_engines.templates.a2a import A2aAgent, create_agent_card
from wiz_mcp import (
    build_wiz_toolset,
    enforce_wiz_readonly_callback,
    wiz_before_model_callback,
)


try:
    from shared_decision_guards.prompt_injection_guard import (
        screen_tool_output_after_tool_callback,
    )
except ImportError:
    _REPO_ROOT = str(Path(__file__).resolve().parents[2])
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)
    from governed_agents.shared_decision_guards.prompt_injection_guard import (  # noqa: E402
        screen_tool_output_after_tool_callback,
    )


APP_NAME = "wizard_agent"
AGENT_VERSION = "1.0.0"

MODEL = os.getenv("MODEL", "gemini-3.8-flash")
MODEL_LOCATION = os.getenv("MODEL_LOCATION", "global")

# Fail fast at container startup if the Wiz Auth Manager provider is omitted.
WIZ_AUTH_PROVIDER = os.environ["WIZ_AUTH_PROVIDER"].strip()
if not WIZ_AUTH_PROVIDER:
    raise RuntimeError("WIZ_AUTH_PROVIDER must be set for wizard_agent")

WIZ_MCP_URL = os.getenv("WIZ_MCP_URL", "https://mcp.app.wiz.io/").strip()
WIZ_ALLOWED_TOOLS = [
    t.strip()
    for t in os.getenv("WIZ_ALLOWED_TOOLS", "discover,execute").split(",")
    if t.strip()
]

wiz_tools = build_wiz_toolset(
    mcp_url=WIZ_MCP_URL,
    auth_provider=WIZ_AUTH_PROVIDER,
    tool_filter=WIZ_ALLOWED_TOOLS,
    user_id=APP_NAME,
)

DESCRIPTION = (
    "Wiz Cloud Security Graph and Attack Path specialist (Wizard_Agent) that "
    "correlates cloud exposure, Toxic Combinations, IAM privilege paths, CVEs, "
    "AI-SPM findings, and Terraform root-cause remediations via Wiz Remote MCP."
)

INSTRUCTION = """\
You are Wizard_Agent, the dedicated cloud security posture, Attack Path, and
AI-SPM specialist in a governed Security Operations Center (SOC), connected to
Wiz Remote MCP (`wiz_discover` and read-only `wiz_execute`).

Domain workflow (`secops-wiz-cloud-security` runbook guidance):
1. Schema-first discovery and read-only execution:
   * Inspect available Wiz MCP domains and parameter schemas with `wiz_discover`
     first whenever tool arguments are uncertain.
   * Execute read-only queries with `wiz_execute` across:
     - `issues` (`list_issues`, `get_issue`) for Toxic Combinations, Attack Paths,
       and Wiz Green Agent IaC / Terraform remediation guidance.
     - `detections` (`list_detections`, `get_threat`) for Wiz Defend runtime
       threats, process lineage, and Blue Agent verdicts.
     - `vulnerabilities` (`list_vulnerability_findings`) for exploitable CVEs,
       container image owners, and Dockerfile provenance.
     - `network_exposure` (`list_network_exposure`) for public internet ingress,
       load balancers, and firewall exposure.
     - `iam_and_graph` (`list_service_account_paths`) for overly broad OAuth
       scopes (`cloud-platform`), `serviceAccountTokenCreator` hops, and lateral
       blast radius across cloud resources.
     - `ai_spm` (`list_ai_spm_findings`) for exposed AI agents, model endpoints,
       and sensitive training or database bindings.
2. Benign scanner and CI/CD discrimination:
   * Flag when Wiz context (`RESOLVED`, `DAST_ATTACKER`, or `ci-deployer` /
     `terraform` automation principals) indicates authorized red-team scanning or
     infrastructure-as-code deployment rather than active adversary compromise,
     so the orchestrator can cross-verify in Chronicle SIEM before containment.
3. Actionable remediation synthesis:
   * Report affected cloud resource IDs, internet-to-data attack hops, OAuth/IAM
     scope over-privilege, and concrete least-privilege Terraform or IaC fixes.

Operating boundaries:
1. You are strictly read-only on Wiz (`enforce_wiz_readonly_callback` blocks
   issue closure, status edits, comments, and GraphQL mutations).
2. You have zero access to Chronicle SIEM UDM telemetry, SOAR cases, external
   GTI credentials, or endpoint containment tools by architectural design. Return
   structured cloud exposure context so `SOC_Orchestrator` can correlate it with
   `Threat_Hunter`, `CTI_Researcher`, `Detection_Engineer`, and `Tier2_Responder`.
3. Distinguish Chronicle SIEM YARA-L 2.0 rules (UDM event detection rules) from
   standard YARA rules (file/payload binary pattern matching) whenever detection
   formats are discussed. Do not use emojis.
"""

wizard_llm = LlmAgent(
    name=APP_NAME,
    model=Gemini(model=MODEL, client_kwargs={"location": MODEL_LOCATION}),
    description=DESCRIPTION,
    instruction=INSTRUCTION,
    tools=[wiz_tools],
    generate_content_config=types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_budget=0)
    ),
    before_model_callback=wiz_before_model_callback,
    before_tool_callback=enforce_wiz_readonly_callback,
    after_tool_callback=screen_tool_output_after_tool_callback,
)


def _build_executor() -> A2aAgentExecutor:
    runner = Runner(
        app_name=APP_NAME,
        agent=wizard_llm,
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
            id="wiz_cloud_graph_and_attack_path",
            name="Wiz Cloud Graph, Attack Path, and Toxic Combination analysis",
            description=(
                "Queries Wiz Remote MCP (wiz_discover and read-only wiz_execute) "
                "for internet exposure, IAM service-account privilege paths, "
                "vulnerabilities, runtime threats, and Toxic Combinations."
            ),
            tags=[
                "wiz",
                "cloud-security",
                "attack-path",
                "iam",
                "vulnerabilities",
            ],
            examples=[
                "Inspect the Wiz Attack Path and OAuth scope exposure for the DataBot GCP Compute Instance",
                "List open CRITICAL Toxic Combination issues and internet-exposed cloud assets in Wiz",
            ],
        ),
        AgentSkill(
            id="wiz_ai_spm_and_terraform_remediation",
            name="Wiz AI-SPM posture and least-privilege Terraform remediation",
            description=(
                "Retrieves Wiz AI Security Posture Management (AI-SPM) findings, "
                "DAST scanner dispositions, and least-privilege Terraform fixes."
            ),
            tags=[
                "wiz",
                "ai-spm",
                "terraform",
                "remediation",
                "posture",
            ],
            examples=[
                "Retrieve Wiz AI security findings and Green Agent Terraform remediation for DataBot",
            ],
        ),
    ],
)
agent_card.version = AGENT_VERSION

root_agent = A2aAgent(
    agent_card=agent_card,
    agent_executor_builder=_build_executor,
)
