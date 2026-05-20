"""
SOC Agent Module - Tier 1 SOC Analyst Configuration

This module configures a Tier 1 SOC Analyst Agent with specific persona,
responsibilities, and MCP tools for security operations.

ARCHITECTURAL DECISION: Intentional Code Duplication
======================================================
This module intentionally duplicates code from other soc_agent_* modules
rather than using shared utilities or inheritance. This is a deliberate
architectural choice that prioritizes:

1. CLARITY: Each agent module is completely self-contained and can be
   understood without navigating to other files or understanding complex
   inheritance hierarchies.

2. INDEPENDENCE: Each agent can be modified, deployed, and debugged
   independently without risk of breaking other agents through shared
   code changes.

3. EXPLICITNESS: All configuration and behavior is visible in a single
   file, making it easier for new team members to understand and modify.

4. STABILITY: Changes to one agent cannot inadvertently affect others,
   reducing the risk of regression bugs in production.

This approach trades code duplication for reduced complexity and improved
maintainability in a security-critical environment where reliability and
clarity are paramount. For this project, we explicitly value clarity over DRY.

See PR #25 discussion for additional context on this architectural decision.
"""

import json
import logging
import mimetypes
import os
from pathlib import Path

import vertexai
from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.agents.context import Context
from google.adk.tools import google_search
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from vertexai.preview import rag


# Add text/markdown mimetype for .md files
mimetypes.add_type("text/markdown", ".md")


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========================================================================
# Tier 1 SOC Analyst Persona Definition
# Copied from ai-runbooks/rules_bank/personas/soc_analyst_tier_1.md
# ========================================================================
TIER1_PERSONA = """
## Tier 1 SOC Analyst

### Overview
The Tier 1 Security Operations Center (SOC) Analyst is the first line of defense, responsible for monitoring security alerts, performing initial triage, and escalating incidents based on predefined procedures. They focus on quickly assessing incoming alerts, gathering initial context, and determining the appropriate next steps, whether it's closing false positives/duplicates or escalating potentially real threats to Tier 2/3 analysts.

### Primary Responsibilities
- **Alert Monitoring & Triage:** Actively monitor alert queues in SOAR platform, perform initial assessment based on severity, type, and initial indicators
- **Basic Investigation:** Gather preliminary information about alerts and associated entities (IPs, domains, hashes, users) using basic lookup tools
- **Case Management:** Create new cases in SOAR for alerts requiring investigation, add comments, tag appropriately, manage priority based on findings
- **Duplicate/False Positive Handling:** Identify and close duplicate cases or false positives based on runbook criteria
- **Escalation:** Escalate complex or confirmed incidents to Tier 2/3 analysts with initial findings and context
- **Documentation:** Maintain clear and concise documentation within SOAR cases regarding actions taken and findings
- **Runbook Execution:** Follow documented procedures (runbooks) for common alert types and investigation steps

### Core Skills and Knowledge
- Understanding of fundamental cybersecurity concepts (common attack vectors, IOC types, event vs. alert)
- Ability to perform basic entity enrichment using SIEM (secops-mcp)
- Strong attention to detail and ability to follow procedures accurately
- Good communication skills for documenting findings and escalating incidents

### Tool Usage Patterns
**Primary MCP Tools:**
- **secops-mcp (Chronicle SIEM):**
  - lookup_entity: For quick context on IPs, domains, users, hashes from SIEM data
  - get_security_alerts: To check for recent SIEM alerts
  - get_ioc_matches: To check for known bad indicators in SIEM (Explicitly ALLOWED for Tier 1)
  - search_udm / search_security_events: To perform fleet-wide searches for multiple indicators over extended periods (e.g., up to 168 hours) to scope an alert's impact. This is considered acceptable Tier 1 triage, NOT advanced threat hunting.
  - get_threat_intel: For basic questions about CVEs or concepts

- **secops-soar (SOAR Platform):**
  - Case creation and management
  - Alert investigation and documentation
  - Adding artifacts and comments to cases
  - Managing case priority and status

- **gti-mcp (Google Threat Intelligence):**
  - Basic IOC reputation checks
  - Threat intelligence enrichment for suspicious indicators

### Escalation Criteria
**Escalate to Tier 2/3 when:**
- Confirmed malicious activity detected
- Multiple correlated alerts indicate campaign
- Threat actor TTPs identified
- User compromise confirmed
- Lateral movement detected
- Data exfiltration suspected
- Complex forensic analysis required
- Incident requires containment or remediation actions

### Scope Limitations
**Tier 1 analysts DO NOT:**
- Perform deep forensic analysis
- Make containment or remediation decisions
- Directly interact with threat actors
- Conduct advanced threat hunting
- Create or modify detection rules
- Perform vulnerability assessments
- Execute incident response beyond initial triage

### Relevant Runbooks
Primary runbooks for Tier 1 operations:
- triage_alerts.md
- basic_ioc_enrichment.md
- close_duplicate_or_similar_cases.md
- prioritize_and_investigate_a_case.md (initial steps only)
- suspicious_login_triage.md
- report_writing.md (for basic case documentation)
"""

# Optional: Tier 1 specific configuration
TIER1_CONFIG = {
    "max_investigation_depth": 2,  # Don't go beyond 2 levels of IOC pivoting
    "auto_escalate_indicators": [
        "ransomware",
        "apt",
        "data_exfiltration",
        "privilege_escalation",
        "lateral_movement",
    ],
    "primary_runbooks": [
        "triage_alerts",
        "basic_ioc_enrichment",
        "close_duplicate_or_similar_cases",
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
                + ":mcp-security/server/secops:mcp-security/server/secops-soar:mcp-security/server/gti:mcp-security/server/scc"
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
        # We explicitly call the memory service with a global user_id
        # instead of mutating the session, which breaks ADK's SessionService.
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
            logger.info(
                f"MEMORY_GENERATION_TOPICS: Passing {len(memory_bank_config.get('customization_configs', [{}])[0].get('memory_topics', []))} custom memory topics."
            )
            logger.debug(f"MEMORY_GENERATION_CONFIG: {json.dumps(memory_bank_config)}")

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
                logger.info(
                    "MEMORY_GENERATION: Triggering session memory via ctx.add_session_to_memory (Default ADK)."
                )
                await ctx.add_session_to_memory()
            else:
                logger.warning(
                    "MEMORY_GENERATION_SKIP: No memory service or add_session_to_memory method available on context."
                )
    except Exception as e:
        logger.error(
            f"MEMORY_GENERATION_ERROR: Failed to generate memory: {e}", exc_info=True
        )


async def before_tool_cache(tool, args, tool_context: Context, **kwargs):
    """
    Checks for a cached result before executing a tool.
    This prevents redundant API calls and saves execution time/tokens.
    """
    try:
        # SHARED MEMORY SCOPE OVERRIDE
        # Override the search_memory method on this specific context instance
        # to force LoadMemoryTool to retrieve from the global team scope.
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

        # Create a stable cache key from tool name and sorted arguments
        cache_key = f"{tool.name}:{json.dumps(args, sort_keys=True)}"

        # Access cache from the unified Context state
        cache = tool_context.state.get("tool_result_cache", {})
        if cache_key in cache:
            logger.info(f"CACHE_HIT: Returning cached result for tool '{tool.name}'")
            return cache[cache_key]
    except Exception as e:
        logger.warning(f"CACHE_ERROR: Failed to check tool cache: {e}")

    return None  # Proceed to actual tool execution


async def after_tool_cache(tool, args, tool_context: Context, tool_response, **kwargs):
    """
    Caches the tool result for deduplication within the same session.
    Memory generation is handled by after_agent_callback (generate_memory)
    at the end of each agent turn — not per tool call.
    """
    try:
        # Save to cache
        cache_key = f"{tool.name}:{json.dumps(args, sort_keys=True)}"
        if "tool_result_cache" not in tool_context.state:
            tool_context.state["tool_result_cache"] = {}

        tool_context.state["tool_result_cache"][cache_key] = tool_response
        logger.info(f"CACHE_SAVE: Cached result for tool '{tool.name}'")

    except Exception as e:
        logger.warning(f"CACHE_ERROR: Failed to update tool cache: {e}")

    return tool_response  # Return result to the model


def create_agent():
    """
    Create the SOC Agent with all MCP tools and RAG retrieval configured.

    This function explicitly shows how to:
    1. Load environment variables
    2. Configure each MCP tool
    3. Set up RAG retrieval
    4. Create the agent with all tools

    Returns:
        Configured Agent instance
    """
    # Load environment variables from .env file
    load_dotenv(Path(".env"), override=True)

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

    # Validate required Chronicle environment variables before Vertex AI initialization.
    # Note: Comprehensive validation of all required variables happens in
    # manage_agent_engine.py before deployment. This validates only Chronicle-specific
    # variables to fail fast before expensive Vertex AI initialization.
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
            f"Chronicle service account file not found: {CHRONICLE_SERVICE_ACCOUNT_PATH}\n"
            f"Please verify the path in your .env file points to a valid service account JSON file."
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
    SOAR_APP_KEY = os.environ.get("SOAR_APP_KEY")

    # Google Threat Intelligence configuration
    GTI_API_KEY = os.environ.get("GTI_API_KEY")

    # RAG configuration
    RAG_CORPUS_ID = os.environ.get("RAG_CORPUS_ID")

    # Parse RAG numeric configuration with error handling
    try:
        RAG_SIMILARITY_TOP_K = int(os.environ.get("RAG_SIMILARITY_TOP_K", "10"))
    except ValueError as e:
        raise ValueError(
            f"Invalid RAG_SIMILARITY_TOP_K value. Must be an integer. Error: {e}"
        )

    try:
        RAG_DISTANCE_THRESHOLD = float(os.environ.get("RAG_DISTANCE_THRESHOLD", "0.6"))
    except ValueError as e:
        raise ValueError(
            f"Invalid RAG_DISTANCE_THRESHOLD value. Must be a float. Error: {e}"
        )

    # Debug mode
    DEBUG = os.environ.get("DEBUG", "False") == "True"
    if DEBUG:
        os.environ["GRPC_VERBOSITY"] = "DEBUG"
        os.environ["GRPC_TRACE"] = "all"
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger("google").setLevel(logging.DEBUG)
        logging.getLogger("google.auth").setLevel(logging.DEBUG)
        logging.getLogger("google.api_core").setLevel(logging.DEBUG)

    # Get service account filename for MCP servers (already validated above)
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

                # Format contexts into a single string
                result_parts = []
                for index, context in enumerate(response.contexts.contexts):
                    result_parts.append(f"--- Document {index+1} ---\n{context.text}\n")
                return "\n".join(result_parts)
            except Exception as e:
                return f"Error retrieving from RAG corpus: {str(e)}"

        tools.append(retrieve_agentic_soc_runbooks)
    else:
        logger.warning("RAG_CORPUS_ID not configured, skipping RAG retrieval tool")

    # ========================================================================
    # Add google_search as a standalone tool
    # ========================================================================
    tools.append(google_search)

    # ========================================================================
    # Create the Agent with all configured tools
    # ========================================================================
    logger.info(f"Creating SOC Agent with {len(tools)} tools...")

    agent = Agent(
        model="gemini-2.5-flash",
        name="soc_analyst_tier1_flash",
        description=TIER1_PERSONA,  # Use the embedded Tier 1 persona
        instruction="""You are a Tier 1 SOC Analyst - the first line of defense in security operations. Follow your defined responsibilities and scope limitations strictly.

ROLE & FOCUS:
- You are a Tier 1 SOC Analyst focused on alert triage and initial investigation
- Your primary mission is rapid assessment, basic enrichment, and appropriate escalation
- Follow established runbooks and procedures - do not improvise beyond your scope

WORKFLOW APPROACH:
1. **Alert Triage:** When presented with alerts, perform initial assessment using basic lookups
2. **Runbook Retrieval:** Use retrieve_agentic_soc_runbooks tool to access specific procedures for alert types
3. **Basic Investigation:** Gather context using Chronicle SIEM and GTI for IOC enrichment (max 2 levels deep)
4. **Documentation:** Document all findings clearly in SOAR cases with proper comments
5. **Escalation Decision:** Identify when issues exceed Tier 1 scope and recommend escalation

ESCALATION PROTOCOL:
When you encounter any of the following, inform the user that escalation to Tier 2/3 is required:
- Confirmed malicious activity or compromise
- Indicators: ransomware, APT, data exfiltration, privilege escalation, lateral movement
- Need for forensic analysis, containment, or remediation
- Complex investigations beyond basic triage

TOOL USAGE GUIDELINES:
- **Chronicle (secops-mcp):** Use for entity lookups, alert queries, get_ioc_matches, and broad fleet-wide searches (e.g., search_udm up to 168 hours) to scope the impact of an alert. This is acceptable Tier 1 triage.
- **SOAR (secops-soar):** Create/update cases, add findings, manage status
- **GTI (gti-mcp):** Basic reputation checks for suspicious indicators
- **RAG Retrieval:** Access runbooks especially: triage_alerts, basic_ioc_enrichment, close_duplicate_or_similar_cases

IMPORTANT LIMITATIONS:
- Do NOT perform deep forensic analysis or advanced threat hunting (NOTE: fleet-wide searches for multiple indicators up to 168 hours and get_ioc_matches are explicitly ALLOWED for Tier 1 triage and are NOT considered advanced threat hunting).
- Do NOT make containment/remediation decisions - only recommend them
- Do NOT create or modify detection rules
- Stay within 2 levels of IOC pivoting/investigation depth

When unsure about procedures, ALWAYS retrieve the relevant runbook first. Your RAG corpus contains detailed step-by-step procedures optimized for Tier 1 operations.

CRITICAL INSTRUCTION - USER CONSENT FOR EXECUTION:
When you retrieve a runbook or formulate a plan, you MUST summarize the standard operating procedure for the user, and then EXPLICITLY ask for their permission before executing the associated MCP tools. Do NOT execute the tools autonomously without asking first. End your response with a clear question like "Would you like for me to execute this playbook after your review?"

CRITICAL INSTRUCTION - TOOL INTROSPECTION:
If the user asks for a list of your tools, capabilities, or functions, you MUST introspect your own native function calling schema directly to answer. DO NOT query the RAG corpus for information about your own tools. You already have a native understanding of your `tools` array; rely strictly on that literal schema to describe what actions you can take.""",
        tools=tools,
        before_tool_callback=before_tool_cache,
        after_tool_callback=after_tool_cache,
        after_agent_callback=generate_memory,
    )

    logger.info("SOC Agent created successfully!")
    return agent


# ========================================================================
# Memory Bank Configuration
# ========================================================================
# Defines custom memory topics to instruct the Vertex AI Memory Bank on
# what specific information is meaningful to persist across conversations.
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


# ========================================================================
# Create root_agent for ADK compatibility
# This is the standard ADK pattern - export a root_agent at module level
# ========================================================================
try:
    root_agent = create_agent()
    logger.info("Root agent created and exported as 'root_agent'")
except Exception as e:
    logger.warning(f"Could not create root agent at import time: {e}")
    logger.info("Use create_agent() to create the agent")
    root_agent = None


# Export key functions and the root agent
__all__ = [
    "create_agent",
    "root_agent",
    "memory_bank_config",
]
