"""
SOC Agent Module - Threat Hunter Configuration

This module configures a proactive Threat Hunter Agent with specific persona,
responsibilities, and MCP/RAG tools for hunting anomalies and threat detection.

ARCHITECTURAL DECISION: Intentional Code Duplication
======================================================
This module intentionally duplicates code from other agent_* modules
rather than using shared utilities or inheritance. This is a deliberate
architectural choice that prioritizes clarity, stability, explicitness,
and independence of deployment.
"""

import json
import logging
import mimetypes
import os
import re
from pathlib import Path

import google.adk.apps.app as adk_app
import google.adk.sessions.in_memory_session_service as im_session
import vertexai
from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.agents.callback_context import CallbackContext
from google.adk.agents.context import Context
from google.adk.models import LlmRequest, LlmResponse
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.genai.types import Part
from vertexai.preview import rag


# Add text/markdown mimetype for .md files
mimetypes.add_type("text/markdown", ".md")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# Framework Monkey-Patches (Prevent ADK 2.0 bugs and noisy warnings)
# -------------------------------------------------------------------------

# Silence the harmless but noisy InMemorySessionService warning inside sub-agents
original_append_event = im_session.InMemorySessionService.append_event


async def _patched_append_event(self, session, event):
    app_name = session.app_name
    user_id = session.user_id
    session_id = session.id

    # Auto-initialize the session in the in-memory dict to prevent the warning
    if app_name not in self.sessions:
        self.sessions[app_name] = {}
    if user_id not in self.sessions[app_name]:
        self.sessions[app_name][user_id] = {}
    if session_id not in self.sessions[app_name][user_id]:
        self.sessions[app_name][user_id][session_id] = session

    return await original_append_event(self, session, event)


im_session.InMemorySessionService.append_event = _patched_append_event


# Monkey-patch validate_app_name to prevent ADK 2.0 serialization errors
original_validate_app_name = adk_app.validate_app_name


def _patched_validate_app_name(name: str) -> None:
    if re.match(r"^\d+$", name):
        return
    return original_validate_app_name(name)


adk_app.validate_app_name = _patched_validate_app_name
# -------------------------------------------------------------------------


# ========================================================================
# Threat Hunter Persona Definition
# ========================================================================
THREAT_HUNTER_PERSONA = """
## Threat Hunter

### Overview
The Threat Hunter proactively and iteratively searches through networks and datasets to detect and isolate advanced threats that evade existing security solutions. Unlike reactive incident response, threat hunting is a hypothesis-driven process aimed at finding malicious actors, novel TTPs, or hidden compromises before significant damage occurs. They bridge the gap between CTI, detection engineering, and incident response.

### Primary Responsibilities
- **Hypothesis Development:** Formulate hunting hypotheses based on threat intelligence, knowledge of attacker TTPs, environmental context, and security tool telemetry.
- **Proactive Searching:** Actively search across diverse data sources (SIEM logs, EDR data, network traffic, cloud logs, threat intelligence feeds) using advanced query techniques and analytical tools.
- **Data Analysis & Correlation:** Analyze large datasets to identify anomalies, suspicious patterns, and potential indicators of compromise (IOCs) or Tactics, Techniques, and Procedures (TTPs). Correlate findings across different data sources.
- **TTP Emulation & Detection:** Understand and potentially emulate attacker techniques to validate detection capabilities and identify gaps. Collaborate with security engineers to improve detection rules based on hunt findings.
- **Investigation & Contextualization:** Investigate potential findings, enrich indicators using threat intelligence and internal context, and determine the scope of the activity.
- **Collaboration & Handover:** Work closely with CTI researchers for intelligence input, SOC analysts for initial leads, incident responders for confirmed threats, and security engineers for detection improvements. Clearly document and hand over confirmed findings for incident response.
- **Tooling & Automation:** Utilize specialized hunting tools and platforms. Develop scripts or queries to automate repetitive hunting tasks.

### Core Skills and Knowledge
- Deep understanding of attacker methodologies, TTPs, and frameworks (MITRE ATT&CK).
- Expertise in advanced SIEM query languages (e.g., UDM for Chronicle) and log analysis.
- Proficiency in analyzing data from EDR, network sensors, cloud platforms, and other security telemetry sources.
- Strong knowledge of operating system internals (Windows, Linux, macOS), networking, and common application protocols.
- Ability to interpret and apply threat intelligence effectively.
- Strong analytical, pattern recognition, and critical thinking skills.

### Tool Usage Patterns
**Primary MCP & Custom Tools:**
- **secops-mcp (Chronicle SIEM):**
  - search_security_events: Core tool for querying SIEM logs based on hypotheses.
  - lookup_entity: For quick context on entities discovered during hunts.
  - get_ioc_matches: To check hunt findings against known bad indicators.
  - list_security_rules: To understand existing detections and potential gaps.
  - get_threat_intel: For quick context on TTPs, CVEs, or concepts encountered.
- **gti-mcp (Google Threat Intelligence):**
  - search_threats, search_campaigns, search_threat_actors, search_malware_families, search_vulnerabilities: To research TTPs, actors, or malware relevant to hypotheses.
  - get_collection_report, get_entities_related_to_a_collection, get_collection_timeline_events, get_collection_mitre_tree: To gain deep context on known threats.
  - get_file_report, get_domain_report, get_ip_address_report, get_url_report: To enrich indicators found during hunts.
  - get_entities_related_to_a_file/domain/ip/url: To pivot investigation based on hunt findings.
  - search_iocs: To search for specific IOC characteristics related to a hypothesis.
- **secops-soar (SOAR Platform):**
  - list_cases, get_case_full_details, list_alerts_by_case: To understand if hunt findings relate to existing cases or alerts.
  - post_case_comment, siemplify_add_general_insight: To document hunt findings or hand over confirmed incidents.
- **scc-mcp (SCC):**
  - top_vulnerability_findings, get_finding_remediation: To understand cloud posture and potential attack surface related to hunts.
"""

THREAT_HUNTER_CONFIG = {
    "primary_runbooks": [
        "apt_threat_hunt",
        "proactive_threat_hunting_based_on_gti_campaign_or_actor",
        "ioc_threat_hunt",
        "advanced_threat_hunting",
        "guided_ttp_hunt_credential_access",
        "lateral_movement_hunt_psexec_wmi",
    ],
}


class DynamicMcpToolset(McpToolset):
    mcp_module: str = ""
    target_env: dict = {}
    _is_dynamic_initialized: bool = False

    def __init__(self, mcp_module: str, target_env: dict, **kwargs):
        from mcp.client.stdio import StdioServerParameters

        # Deploy a placeholder structure that the ADK will serialize natively
        dummy_params = StdioConnectionParams(
            server_params=StdioServerParameters(
                command="python3", args=["-m", mcp_module], env={}
            ),
            timeout=60000,
        )
        # CRITICAL: Suppress errlog default injection (`sys.stderr` Stream) to permit serialization
        super().__init__(connection_params=dummy_params, errlog=None, **kwargs)
        self.mcp_module = mcp_module
        self.target_env = target_env
        self._is_dynamic_initialized = False

    async def get_tools(self, readonly_context=None) -> list:
        if not getattr(self, "_is_dynamic_initialized", False):
            import os
            import sys

            from mcp.client.stdio import StdioServerParameters

            # The exact container execution environment
            container_env = dict(os.environ)
            container_env["PYTHONPATH"] = (
                ":".join(sys.path)
                + ":external/mcp-security/server/secops:external/mcp-security/server/secops-soar:external/mcp-security/server/gti:external/mcp-security/server/scc"
            )

            for k, v in self.target_env.items():
                if v is not None:
                    container_env[k] = v

            # Overwrite the payload natively substituting the explicit system binary path
            self._connection_params.server_params = StdioServerParameters(
                command=sys.executable, args=["-m", self.mcp_module], env=container_env
            )
            # CRITICAL: Overwrite the privately cached copy housed inside the Session Manager
            self._mcp_session_manager._connection_params = self._connection_params

            self._is_dynamic_initialized = True
        return await super().get_tools(readonly_context)


async def log_usage_metadata(ctx: Context):
    """Logs the usage metadata from the most recent event to Cloud Logging."""
    try:
        if (
            not ctx
            or not hasattr(ctx, "session")
            or getattr(ctx.session, "events", None) is None
        ):
            return

        # Look for the last event with usage_metadata (usually the model's response)
        for event in reversed(ctx.session.events):
            if hasattr(event, "usage_metadata") and event.usage_metadata:
                usage = event.usage_metadata
                log_data = {
                    "event_type": "agent_token_usage",
                    "session_id": getattr(ctx.session, "id", "unknown"),
                    "invocation_id": getattr(event, "invocation_id", "unknown"),
                    "author": getattr(event, "author", "unknown"),
                    "prompt_token_count": getattr(usage, "prompt_token_count", 0),
                    "candidates_token_count": getattr(
                        usage, "candidates_token_count", 0
                    ),
                    "total_token_count": getattr(usage, "total_token_count", 0),
                }
                # Emit a structured message for Cloud Logging
                logger.info(f"USAGE_METADATA: {json.dumps(log_data)}")
                break

    except Exception as e:
        logger.warning(f"Failed to log usage metadata: {e}")


async def generate_memory(
    ctx: Context = None, callback_context: Context = None, **kwargs
):
    """
    Triggers memory generation for the current session.
    This saves the conversation to memory at the end of each interaction.
    """
    ctx = ctx or callback_context
    if not ctx:
        logger.warning("No context provided to generate_memory")
        return

    # Log usage metadata to Cloud Logging
    await log_usage_metadata(ctx)

    try:
        # SHARED MEMORY SCOPE OVERRIDE
        if hasattr(ctx, "_invocation_context") and getattr(
            ctx._invocation_context, "memory_service", None
        ):
            session_events = (
                ctx._invocation_context.session.events
                if getattr(ctx._invocation_context, "session", None)
                else []
            )

            logger.info(
                "MEMORY_GENERATION: Triggering Vertex AI Memory Bank generation."
            )
            await ctx._invocation_context.memory_service.add_events_to_memory(
                app_name=ctx._invocation_context.app_name,
                user_id="global_soc_team",
                events=session_events,
                custom_metadata=memory_bank_config,
            )
            logger.info(
                "MEMORY_GENERATION: Successfully submitted events to Vertex AI memory service."
            )
        else:
            if hasattr(ctx, "add_session_to_memory"):
                await ctx.add_session_to_memory()
    except Exception as e:
        logger.error(
            f"MEMORY_GENERATION_ERROR: Failed to generate memory: {e}", exc_info=True
        )


async def before_tool_cache(tool, args, tool_context: Context, **kwargs):
    """Checks for a cached result before executing a tool."""
    try:
        if (
            tool.name == "load_memory"
            and hasattr(tool_context, "_invocation_context")
            and getattr(tool_context._invocation_context, "memory_service", None)
        ):

            async def _shared_search_memory(self, query: str):
                return await self._invocation_context.memory_service.search_memory(
                    app_name=self._invocation_context.app_name,
                    user_id="global_soc_team",
                    query=query,
                )

            import types

            tool_context.search_memory = types.MethodType(
                _shared_search_memory, tool_context
            )

        cache_key = f"{tool.name}:{json.dumps(args, sort_keys=True)}"
        cache = tool_context.state.get("tool_result_cache", {})
        if cache_key in cache:
            logger.info(f"CACHE_HIT: Returning cached result for tool '{tool.name}'")
            return cache[cache_key]
    except Exception as e:
        logger.warning(f"CACHE_ERROR: Failed to check tool cache: {e}")

    return None


async def after_tool_cache(tool, args, tool_context: Context, tool_response, **kwargs):
    """Caches the tool result for deduplication within the same session."""
    try:
        cache_key = f"{tool.name}:{json.dumps(args, sort_keys=True)}"
        if "tool_result_cache" not in tool_context.state:
            tool_context.state["tool_result_cache"] = {}

        tool_context.state["tool_result_cache"][cache_key] = tool_response
        logger.info(f"CACHE_SAVE: Cached result for tool '{tool.name}'")

    except Exception as e:
        logger.warning(f"CACHE_ERROR: Failed to update tool cache: {e}")

    return tool_response


def prevent_runaway_loop_callback(
    callback_context: CallbackContext, llm_request: LlmRequest
) -> LlmResponse | None:
    """Prevents runaway sessions by incrementing a turn counter and injecting warnings."""
    current_state = callback_context.state.to_dict()
    turn_count = current_state.get("turn_count", 0) + 1
    callback_context.state.update({"turn_count": turn_count})
    try:
        max_turns = int(os.environ.get("MAX_SESSION_TURNS", "25"))
    except ValueError:
        max_turns = 25
    remaining = max_turns - turn_count

    instruction = f"Current turn counter is {turn_count}. There are {remaining} turns before exit. You MUST conclude the session and exit if the turn reaches {max_turns}. Prevent runaway sessions or endless loops."
    llm_request.append_instructions([instruction])
    return None


async def save_report_artifact(filename: str, report_content: str, ctx: Context) -> str:
    """
    Saves a generated containment, analysis, or mitigation report finding as an artifact.
    MUST be called by the agent whenever you finalize a detailed containment report to formally save it.

    Args:
        filename: A logical filename for the report ending in .md (e.g. 'MALWARETEST-WIN_Containment_Report.md').
        report_content: The complete markdown content of the report you generated.
    """
    logger.info(f"SAVE_REPORT_ARTIFACT: Attempting to save {filename}")
    try:
        report_bytes = report_content.encode("utf-8")
        mime_type, _ = mimetypes.guess_type(filename)
        report_artifact = Part.from_bytes(
            data=report_bytes, mime_type=mime_type or "text/markdown"
        )
        version = await ctx.save_artifact(filename=filename, artifact=report_artifact)
        link_to_provide = f"[{filename}](artifact://{filename})"

        try:
            if (
                hasattr(ctx, "_invocation_context")
                and ctx._invocation_context.artifact_service
            ):
                art_svc = ctx._invocation_context.artifact_service
                while (
                    hasattr(art_svc, "_invocation_context")
                    and hasattr(art_svc._invocation_context, "artifact_service")
                    and art_svc._invocation_context.artifact_service is not art_svc
                ):
                    art_svc = art_svc._invocation_context.artifact_service

                if hasattr(art_svc, "bucket_name"):
                    bucket = art_svc.bucket_name
                    root_ctx = (
                        art_svc._invocation_context
                        if hasattr(art_svc, "_invocation_context")
                        else ctx._invocation_context
                    )

                    app_name = getattr(root_ctx, "app_name", "unknown_app")
                    user_id = getattr(root_ctx, "user_id", "unknown_user")
                    session_id = "unknown_session"
                    if hasattr(root_ctx, "session") and hasattr(root_ctx.session, "id"):
                        session_id = root_ctx.session.id

                    blob_name = (
                        f"{app_name}/{user_id}/{session_id}/{filename}/{version}"
                    )

                    try:
                        from datetime import timedelta

                        from google.cloud import storage

                        storage_client = storage.Client()
                        bucket_obj = storage_client.bucket(bucket)
                        blob_obj = bucket_obj.blob(blob_name)

                        signed_url = blob_obj.generate_signed_url(
                            version="v4", expiration=timedelta(hours=24), method="GET"
                        )
                        link_to_provide = f"[{filename}]({signed_url})"
                    except Exception as sign_e:
                        logger.warning(f"Could not generate signed url: {sign_e}")
                        gcs_url = (
                            f"https://storage.cloud.google.com/{bucket}/{blob_name}"
                        )
                        link_to_provide = f"[{filename}]({gcs_url})"
        except Exception as link_e:
            logger.warning(
                f"Could not construct direct GCS link, falling back to artifact schema: {link_e}"
            )

        logger.info(
            f"SAVE_REPORT_ARTIFACT_SUCCESS: Saved {filename} as version {version}"
        )
        return f"Successfully saved report '{filename}'. You MUST provide this exact link to the user in your final response: {link_to_provide}"
    except Exception as e:
        logger.error(f"SAVE_REPORT_ARTIFACT_ERROR: Failed to save report: {e}")
        return f"Error saving report: {e}"


def get_secret(secret_name: str, project_id: str | None) -> str:
    """Retrieve a secret from Google Cloud Secret Manager with local env fallback."""
    val = os.environ.get(secret_name, "")
    if not project_id:
        return val

    try:
        from google.cloud import secretmanager

        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
        response = client.access_secret_version(name=name)
        secret_val = response.payload.data.decode("UTF-8").strip()
        if secret_val:
            logger.info(
                f"Successfully loaded secret '{secret_name}' from Secret Manager."
            )
            return secret_val
    except Exception as e:
        logger.debug(
            f"Secret Manager lookup failed for '{secret_name}': {e}. Using environment fallback."
        )

    return val


def create_agent():
    """
    Create the standalone Threat Hunter Agent with MCP and log analysis tools.
    """
    # Load environment variables from .env file
    load_dotenv(Path(".env"), override=True)

    # Model Configuration
    THREAT_HUNTER_MODEL = os.environ.get("THREAT_HUNTER_MODEL", "gemini-3.5-flash")

    # Get all required environment variables
    GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")
    GCP_LOCATION = os.environ.get("GCP_LOCATION", "us-central1")
    GCP_STAGING_BUCKET = os.environ.get("GCP_STAGING_BUCKET")
    GCP_VERTEXAI_ENABLED = os.environ.get("GCP_VERTEXAI_ENABLED", "True")

    # Chronicle/SIEM configuration
    CHRONICLE_CUSTOMER_ID = os.environ.get("CHRONICLE_CUSTOMER_ID")
    CHRONICLE_PROJECT_ID = os.environ.get("CHRONICLE_PROJECT_ID")
    CHRONICLE_REGION = os.environ.get("CHRONICLE_REGION", "us")
    CHRONICLE_SERVICE_ACCOUNT_PATH = os.environ.get("CHRONICLE_SERVICE_ACCOUNT_PATH")

    if not CHRONICLE_PROJECT_ID:
        raise ValueError(
            "CHRONICLE_PROJECT_ID is required. Please set it in your .env file."
        )
    if not CHRONICLE_SERVICE_ACCOUNT_PATH:
        raise ValueError(
            "CHRONICLE_SERVICE_ACCOUNT_PATH is required. Please set it in your .env file."
        )

    # Verify service account file exists
    service_account_path = Path(CHRONICLE_SERVICE_ACCOUNT_PATH)
    if not service_account_path.exists():
        raise FileNotFoundError(
            f"Chronicle service account file not found: {CHRONICLE_SERVICE_ACCOUNT_PATH}"
        )

    # Initialize Vertex AI for the agent to work with Gemini models and RAG
    if GCP_PROJECT_ID and GCP_VERTEXAI_ENABLED == "True":
        logger.info(
            f"Initializing Vertex AI with project: {GCP_PROJECT_ID}, location: {GCP_LOCATION}"
        )
        vertexai.init(
            project=GCP_PROJECT_ID,
            location=GCP_LOCATION,
            staging_bucket=GCP_STAGING_BUCKET,
        )

    # SOAR configuration
    SOAR_URL = os.environ.get("SOAR_URL")
    SOAR_APP_KEY = get_secret("SOAR_APP_KEY", GCP_PROJECT_ID)

    # Google Threat Intelligence configuration
    GTI_API_KEY = get_secret("GTI_API_KEY", GCP_PROJECT_ID)

    # RAG configuration
    RAG_CORPUS_ID = os.environ.get("RAG_CORPUS_ID")

    try:
        RAG_SIMILARITY_TOP_K = int(os.environ.get("RAG_SIMILARITY_TOP_K", "10"))
    except ValueError:
        RAG_SIMILARITY_TOP_K = 10

    try:
        RAG_DISTANCE_THRESHOLD = float(os.environ.get("RAG_DISTANCE_THRESHOLD", "0.6"))
    except ValueError:
        RAG_DISTANCE_THRESHOLD = 0.6

    # Get service account filename for MCP servers
    service_account_filename = service_account_path.name

    # Initialize list to collect all tools
    tools = []

    # ========================================================================
    # Configure Chronicle/SIEM MCP Tool
    # ========================================================================
    logger.info("Configuring Chronicle/SIEM tools...")
    secops_siem_tools = DynamicMcpToolset(
        mcp_module="secops_mcp.server",
        target_env={
            "CHRONICLE_PROJECT_ID": CHRONICLE_PROJECT_ID,
            "CHRONICLE_CUSTOMER_ID": CHRONICLE_CUSTOMER_ID,
            "CHRONICLE_REGION": CHRONICLE_REGION,
            "SECOPS_SA_PATH": service_account_filename,
        },
    )
    tools.append(secops_siem_tools)

    # ========================================================================
    # Configure SOAR MCP Tool
    # ========================================================================
    logger.info("Configuring SOAR tools...")
    secops_soar_tools = DynamicMcpToolset(
        mcp_module="secops_soar_mcp.server",
        target_env={
            "SOAR_URL": SOAR_URL,
            "SOAR_APP_KEY": SOAR_APP_KEY,
        },
    )
    tools.append(secops_soar_tools)

    # ========================================================================
    # Configure Google Threat Intelligence (GTI) MCP Tool
    # ========================================================================
    logger.info("Configuring GTI tools...")
    gti_tools = DynamicMcpToolset(
        mcp_module="gti_mcp.server",
        target_env={
            "VT_APIKEY": GTI_API_KEY,
        },
    )
    tools.append(gti_tools)

    # ========================================================================
    # Configure Security Command Center (SCC) MCP Tool
    # ========================================================================
    logger.info("Configuring SCC tools...")
    scc_tools = DynamicMcpToolset(mcp_module="scc_mcp", target_env={})
    tools.append(scc_tools)

    # ========================================================================
    # Configure RAG Retrieval Tool (if RAG corpus is configured)
    # ========================================================================
    if RAG_CORPUS_ID:
        logger.info(f"Configuring RAG retrieval with corpus: {RAG_CORPUS_ID}")

        def retrieve_agentic_soc_runbooks(query: str) -> str:
            """Use this tool to retrieve IRPs, Runbooks, Common Steps, Procedure, guidelines, and Personas for the Agentic SOC.

            Args:
                query: The search query to find relevant documentation in the RAG corpus.
            """
            try:
                response = rag.retrieval_query(
                    rag_resources=[rag.RagResource(rag_corpus=RAG_CORPUS_ID)],
                    text=query,
                    similarity_top_k=RAG_SIMILARITY_TOP_K,
                    vector_distance_threshold=RAG_DISTANCE_THRESHOLD,
                )
                if not response.contexts or not response.contexts.contexts:
                    return "No relevant documentation found in RAG corpus."

                result_parts = []
                for index, context in enumerate(response.contexts.contexts):
                    result_parts.append(f"--- Document {index+1} ---\n{context.text}\n")
                return "\n".join(result_parts)
            except Exception as e:
                return f"Error retrieving from RAG corpus: {str(e)}"

        tools.append(retrieve_agentic_soc_runbooks)

    # ========================================================================
    # Add save_report_artifact as a standalone tool
    # ========================================================================
    tools.append(save_report_artifact)

    # ========================================================================
    # Create the Agent with all configured tools
    # ========================================================================
    logger.info(f"Creating Threat Hunter Agent with {len(tools)} tools...")

    agent = Agent(
        model=THREAT_HUNTER_MODEL,
        name="soc_analyst_threat_hunter",
        description=THREAT_HUNTER_PERSONA,
        instruction="""You are a Threat Hunter - a proactive security operations engineer responsible for hypothesis-driven threat hunting, anomaly detection, and tactical security investigation.

ROLE & FOCUS:
- You formulate and validate hunting hypotheses based on threat intelligence and attacker TTPs.
- You proactively search SIEM/Chronicle logs, GTI, and cloud security telemetry to find indicators of compromise (IOCs) or suspicious behaviors.
- You analyze telemetry and document your findings, providing clear logs, UDM queries, and actor profiles.
- When an active threat is confirmed, document your findings and clearly outline containment recommendations for the Tier 2 Incident Responder.

WORKFLOW APPROACH:
1. **Hypothesis Formulation:** Retrieve relevant runbooks (e.g., `apt_threat_hunt.md`, `proactive_threat_hunting_based_on_gti_campaign_or_actor.md`, `ioc_threat_hunt.md`) using `retrieve_agentic_soc_runbooks`.
2. **Telemetry Querying:** Construct and run UDM queries using Chronicle/SIEM (`search_security_events` or similar) to query for specific attacker activities, anomalies, or IOC matches.
3. **Indicator Enrichment:** Perform threat intelligence research using Google Threat Intelligence (`gti-mcp`) tools to obtain context on campaigns, actor groups, reputation scores, and related IOCs.
4. **Behavior Analysis & Correlation:** Correlate events across multiple logs (network, endpoint, cloud) to trace the scope of any potential breach or compromise.
5. **Detection Validation:** Understand if current SIEM rules cover the technique. If not, suggest detection improvements.
6. **Documentation & Artifacts:** Document the results of your hunt. Call `save_report_artifact` to save a detailed Markdown report summarizing the hypothesis, query parameters, findings, and next steps/remediation recommendations.

TRANSPARENCY IN RESPONSES:
When reporting results, ALWAYS include:
1. Which tools you called and why.
2. The exact UDM queries used when querying Chronicle SIEM.
3. A clear breakdown of the analysis, including any findings or "no results found" context.

Remember: Proactive hunting requires deep analytical thinking, persistence, and thorough documentation. Never assume telemetry is clean without verifying it.""",
        tools=tools,
        before_model_callback=prevent_runaway_loop_callback,
        before_tool_callback=before_tool_cache,
        after_tool_callback=after_tool_cache,
        after_agent_callback=generate_memory,
    )

    logger.info("Threat Hunter Agent created successfully!")
    return agent


# ========================================================================
# Memory Bank Configuration
# ========================================================================
memory_bank_config = {
    "customization_configs": [
        {
            "memory_topics": [
                {
                    "custom_memory_topic": {
                        "label": "analyst_notes",
                        "description": "Important insights and tactical notes provided by human security analysts during incident investigations.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "investigation_patterns",
                        "description": "Recurring tactical patterns, known false positive indicators, or commonly encountered genuine threats in alerts.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "approved_exceptions",
                        "description": "Authorized administrative tools, routine scanner IP address ranges, VIP user context, and explicitly documented baseline configurations that should be ignored during triage.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "active_campaign_intelligence",
                        "description": "Ongoing context regarding active Advanced Persistent Threat (APT) campaigns, recurring indicators of compromise (IOCs), or malware families actively targeting the organization that span across multiple investigations.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "asset_context",
                        "description": "Structural information about the internal network topology, mappings of specific IP schemas to business units, and identification of business-critical servers or databases.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "siem_query_snippets",
                        "description": "Successful, highly-optimized Chronicle/UDM search query strings and syntactic workarounds developed by analysts or the agent during iterative log hunting.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "containment_strategies",
                        "description": "Historical records of specific remediation or containment actions (e.g., endpoint isolation, firewall blocking) that were successful against recurring infrastructure or malware.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "escalation_preferences",
                        "description": "Organizational context regarding the specific individuals, departments, or Tier 2/3 analysts that need to be engaged or escalated to for particular alert categories.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "detection_rule_feedback",
                        "description": "Feedback on overly noisy or poorly calibrated detection rules within the SIEM, including documented conditions that frequently trigger false positives.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "incident_response_status",
                        "description": "The ongoing lifecycle status, assigned owners, and recent developments of active Incident Response Plans (IRPs) that bridge multiple days or shifts.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "threat_actor_profiles",
                        "description": "Synthesized context about the specific Tactics, Techniques, and Procedures (TTPs) and behaviors of threat groups that have historically affected or are currently threatening the environment.",
                    }
                },
                {
                    "custom_memory_topic": {
                        "label": "tool_execution_quirks",
                        "description": "Known API limitations, syntax requirements, or workarounds for specific SOAR, SIEM, or GTI tools to prevent the agent from repeatedly making the same syntax errors across sessions.",
                    }
                },
            ]
        }
    ]
}


try:
    root_agent = create_agent()
    logger.info("Root agent created and exported as 'root_agent'")
except Exception as e:
    logger.warning(f"Could not create root agent at import time: {e}")
    logger.info("Use create_agent() to create the agent")
    root_agent = None


__all__ = [
    "create_agent",
    "root_agent",
    "memory_bank_config",
]
