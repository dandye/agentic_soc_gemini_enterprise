"""CTI Researcher specialist — ADK LlmAgent served over A2A with Auth Manager.

Lateral isolation by design:
  * Egress policy (`terraform/50-policies-egress.tf`) grants this agent's SPIFFE
    principal access ONLY to `https://www.virustotal.com` and shared Google API
    infrastructure (`agentidentitycredentials.googleapis.com`, Vertex AI).
  * Auth Manager (`terraform/20-authmanager.tf`) grants `roles/agentidentity.user`
    on the GTI API key provider ONLY to this agent's SPIFFE principal.
  * It has zero access to Chronicle SIEM/SOAR MCP endpoints or containment tools.

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
from gti_tools import (
    get_threat_collection,
    lookup_domain_reputation,
    lookup_file_hash_reputation,
    lookup_ip_reputation,
    triage_unstructured_cti_artifact,
)
from vertexai.agent_engines.templates.a2a import A2aAgent, create_agent_card


APP_NAME = "cti_researcher_agent"
AGENT_VERSION = "1.0.0"

MODEL = os.getenv("MODEL", "gemini-3.5-flash")
MODEL_LOCATION = os.getenv("MODEL_LOCATION", "global")

# Fail fast at container startup if the Auth Manager provider resource name was omitted.
GTI_AUTH_PROVIDER = os.environ["GTI_AUTH_PROVIDER"]

DESCRIPTION = (
    "Cyber Threat Intelligence (CTI) specialist that enriches file hashes, "
    "domains, IP addresses, and threat collections via Google Threat Intelligence "
    "(VirusTotal v3) using credentials retrieved at call time from Auth Manager."
)

INSTRUCTION = """\
You are the Cyber Threat Intelligence (CTI) Researcher specialist in a governed
Security Operations Center (SOC).

Your sole responsibility is external indicator enrichment using Google Threat
Intelligence (VirusTotal v3):
  * File hashes (SHA256, SHA1, MD5): call `lookup_file_hash_reputation`
  * Domains and FQDNs: call `lookup_domain_reputation`
  * IPv4 and IPv6 addresses: call `lookup_ip_reputation`
  * Threat collections, campaigns, or actor IDs: call `get_threat_collection`
  * Unstructured CTI artifacts (OSINT prose, threat reports, PDFs, or
    screenshots): call `triage_unstructured_cti_artifact(content, mime_type)`
    to classify actionability, threat category, 1-5 severity, immediate hunt
    urgency, and 1-5 confidence in a single zero-output-token pass (pass base64
    for non-text `mime_type` such as `application/pdf` or `image/png`).

Operating rules:
1. Always call the matching GTI tool for every structured indicator in the
   request. Never invent detection counts, reputation scores, ASN owners, or
   threat labels from memory.
2. When given unstructured threat reports, OSINT prose, PDFs, or screenshots,
   call `triage_unstructured_cti_artifact` instead of manually scoring them.
   Do not call it on structured GTI/VirusTotal v3 integer vote counts.
3. You have zero access to internal Chronicle SIEM telemetry, UDM logs, YARA-L 2.0
   detection rules, or endpoint containment tools by architectural design. If asked
   for internal log searches or host containment, state clearly that CTI Researcher
   is laterally isolated to external threat intelligence only.
4. Distinguish standard YARA (file/payload binary pattern matching rules used in
   malware sandboxes and threat intelligence) from Chronicle SIEM YARA-L 2.0 (UDM
   event correlation rules) whenever detection formats are mentioned.
5. Report exact malicious/suspicious/harmless engine counts, threat labels, ASN
   ownership, and tags returned by the tool. Do not use emojis.
"""

cti_llm = LlmAgent(
    name=APP_NAME,
    model=Gemini(model=MODEL, client_kwargs={"location": MODEL_LOCATION}),
    description=DESCRIPTION,
    instruction=INSTRUCTION,
    tools=[
        lookup_file_hash_reputation,
        lookup_domain_reputation,
        lookup_ip_reputation,
        get_threat_collection,
        triage_unstructured_cti_artifact,
    ],
)


def _build_executor() -> A2aAgentExecutor:
    runner = Runner(
        app_name=APP_NAME,
        agent=cti_llm,
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
            id="enrich_file_hash",
            name="File hash GTI reputation",
            description=(
                "Queries Google Threat Intelligence (VirusTotal v3) for engine "
                "detections, threat classification, and tags on a SHA256, SHA1, "
                "or MD5 file hash."
            ),
            tags=["cti", "hash", "virustotal", "gti"],
            examples=[
                "Look up GTI reputation for SHA256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            ],
        ),
        AgentSkill(
            id="enrich_network_ioc",
            name="Domain and IP GTI reputation",
            description=(
                "Queries Google Threat Intelligence (VirusTotal v3) for domain "
                "and IP address reputation, categories, ASN owner, and detections."
            ),
            tags=["cti", "domain", "ip", "virustotal", "gti"],
            examples=["Check GTI reputation for domain google.com and IP 8.8.8.8"],
        ),
        AgentSkill(
            id="inspect_threat_collection",
            name="GTI threat collection lookup",
            description=(
                "Retrieves campaign, threat actor, or malware collection context "
                "from Google Threat Intelligence."
            ),
            tags=["cti", "collection", "campaign", "gti"],
            examples=["Fetch GTI collection details for a threat report ID"],
        ),
        AgentSkill(
            id="triage_unstructured_cti_artifact",
            name="Unstructured CTI artifact triage",
            description=(
                "Evaluates unstructured threat reports, OSINT prose, PDFs, or "
                "screenshots in a single zero-output-token pass to extract "
                "actionability, threat category, 1-5 severity, immediate hunt "
                "urgency, and 1-5 confidence."
            ),
            tags=["cti", "osint", "triage", "multimodal", "decision", "gti"],
            examples=[
                "Triage this unstructured OSINT threat report for actionability and hunt urgency",
                "Evaluate this base64 threat advisory PDF or screenshot",
            ],
        ),
    ],
)
agent_card.version = AGENT_VERSION

root_agent = A2aAgent(
    agent_card=agent_card,
    agent_executor_builder=_build_executor,
)
