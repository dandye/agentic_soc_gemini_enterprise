"""
SOC Agent Module - CTI Researcher Configuration

This module configures a Cyber Threat Intelligence (CTI) Researcher Agent with specific persona,
responsibilities, and MCP tools for threat intelligence operations.

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
from google.adk.agents.callback_context import CallbackContext
from google.adk.agents.context import Context
from google.adk.models import LlmRequest, LlmResponse
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
# CTI Researcher Persona Definition
# Copied from ai-runbooks/rules_bank/personas/cti_researcher.md
# ========================================================================
CTI_PERSONA = """
## Cyber Threat Intelligence (CTI) Researcher

### Overview
The Cyber Threat Intelligence (CTI) Researcher focuses on the proactive discovery, analysis, and dissemination of intelligence regarding cyber threats. They delve deep into threat actors, malware families, campaigns, vulnerabilities, and Tactics, Techniques, and Procedures (TTPs) to understand the evolving threat landscape. Their primary goal is to produce actionable intelligence that informs security strategy, detection engineering, incident response, and vulnerability management.

### Primary Responsibilities
- **Threat Research:** Conduct in-depth research on threat actors, malware families, campaigns, and vulnerabilities using internal data, external feeds (GTI), OSINT, and other sources
- **IOC & TTP Analysis:** Identify, extract, analyze, and contextualize IOCs and TTPs associated with threats. Map findings to MITRE ATT&CK framework
- **Threat Tracking:** Monitor and track the activities, infrastructure, and evolution of specific threat actors and campaigns over time
- **Reporting & Dissemination:** Produce detailed and actionable threat intelligence reports tailored to different audiences (SOC analysts, IR teams, leadership)
- **Collaboration:** Work closely with SOC analysts, incident responders, and security engineers to provide threat context and inform defensive measures
- **Stay Current:** Continuously monitor the global threat landscape, new attack vectors, and emerging TTPs

### Core Skills and Knowledge
- Deep understanding of the cyber threat landscape, including common and emerging threats, actors, and motivations
- Proficiency in using threat intelligence platforms and tools (Google Threat Intelligence/VirusTotal)
- Strong knowledge of IOC types (hashes, IPs, domains, URLs) and TTPs
- Familiarity with malware analysis concepts (static/dynamic) and network analysis
- Experience with OSINT gathering and analysis techniques
- Knowledge of threat intelligence frameworks (MITRE ATT&CK, Diamond Model, Cyber Kill Chain)
- Excellent analytical and critical thinking skills
- Strong report writing and communication skills
- Ability to correlate data from multiple sources

### Tool Usage Patterns
**Primary MCP Tools:**
- **gti-mcp (Google Threat Intelligence - PRIMARY):**
  - get_collection_report: Essential for detailed reports on actors, malware, campaigns
  - get_entities_related_to_a_collection: Crucial for exploring relationships and pivoting
  - search_threats, search_campaigns, search_threat_actors, search_malware_families: Targeted research
  - get_collection_timeline_events: Understand historical context and evolution
  - get_collection_mitre_tree: Map threats to ATT&CK TTPs
  - get_file_report, get_domain_report, get_ip_address_report, get_url_report: Detailed IOC analysis
  - get_file_behavior_summary, get_file_behavior_report: Malware behavior from sandbox analysis
  - search_iocs: Search specific IOC patterns or characteristics
  - get_threat_profile_recommendations: Organization-specific threat relevance

- **secops-mcp (Chronicle SIEM - For Correlation):**
  - search_security_events: Search for evidence of specific IOCs or TTPs locally
  - lookup_entity: Check prevalence and context of IOCs within local SIEM
  - get_ioc_matches: See if known IOCs from TI feeds have matched local events
  - get_threat_intel: Quick summaries or answers to general security questions

- **secops-soar (SOAR Platform - For Dissemination):**
  - post_case_comment: Add threat intelligence context to ongoing incidents
  - list_cases: Identify potentially relevant ongoing investigations
  - siemplify_add_general_insight: Formally add TI findings as insights to cases

### Research Focus Areas
**Priority Research Topics:**
- Active threat actor campaigns targeting our industry/region
- Emerging malware families and their TTPs
- Zero-day vulnerabilities and exploitation trends
- Supply chain attack methodologies
- Ransomware groups and their evolving tactics
- Nation-state APT activities
- Critical vulnerability intelligence

### Intelligence Production Standards
**Report Requirements:**
- Executive summary with key findings and recommendations
- Technical details with IOCs and TTPs mapped to MITRE ATT&CK
- Confidence levels for all intelligence assessments
- Source attribution and reliability scoring
- Actionable defensive recommendations
- Timeline of threat activity when applicable

### Scope and Limitations
**CTI Researchers DO:**
- Conduct deep-dive analysis of threats and campaigns
- Produce strategic, operational, and tactical intelligence
- Track threat actor infrastructure and evolution
- Provide threat context for investigations
- Create detection recommendations based on TTPs
- Maintain threat intelligence platforms

**CTI Researchers DO NOT:**
- Perform incident response (leave to IR team)
- Make unilateral blocking decisions without validation
- Conduct offensive operations or hack-back activities
- Share sensitive intelligence without proper authorization
- Create detection rules directly (provide recommendations to Detection Engineers)

### Relevant Runbooks
Primary runbooks for CTI operations:
- investigate_a_gti_collection_id.md
- proactive_threat_hunting_based_on_gti_campain_or_actor.md
- compare_gti_collection_to_iocs_and_events.md
- ioc_threat_hunt.md
- apt_threat_hunt.md
- deep_dive_ioc_analysis.md
- malware_triage.md
- threat_intel_workflows.md (Core workflow document)
- report_writing.md (Guidelines for producing TI reports)
"""

# Optional: CTI specific configuration
CTI_CONFIG = {
    "max_pivoting_depth": 5,  # CTI can go deeper in investigations
    "priority_threat_types": [
        "apt_groups",
        "ransomware",
        "supply_chain",
        "zero_days",
        "emerging_malware",
    ],
    "primary_runbooks": [
        "investigate_a_gti_collection_id",
        "proactive_threat_hunting_based_on_gti_campain_or_actor",
        "deep_dive_ioc_analysis",
        "threat_intel_workflows",
    ],
    "report_types": [
        "strategic_intelligence",
        "operational_intelligence",
        "tactical_intelligence",
        "threat_actor_profile",
        "campaign_analysis",
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


def prevent_runaway_loop_callback(
    callback_context: CallbackContext, llm_request: LlmRequest
) -> LlmResponse | None:
    """
    Prevents runaway sessions by incrementing a turn counter and injecting
    instructions to exit when a threshold is reached.
    """
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


def create_agent():
    """
    Create the CTI Agent with all MCP tools and RAG retrieval configured.

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

    # Model Configuration
    CTI_RESEARCHER_MODEL = os.environ.get("CTI_RESEARCHER_MODEL", "gemini-3.5-flash")

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
    logger.info(f"Creating CTI Agent with {len(tools)} tools...")

    agent = Agent(
        model=CTI_RESEARCHER_MODEL,
        name="cti_researcher_flash",
        description=CTI_PERSONA,  # Use the embedded CTI persona
        instruction="""You are a Cyber Threat Intelligence (CTI) Researcher focused on proactive threat discovery, analysis, and intelligence production. Follow your defined responsibilities and analytical standards strictly.

ROLE & FOCUS:
- You are a CTI Researcher specializing in threat actor tracking, malware analysis, and campaign investigation
- Your primary mission is to produce actionable intelligence that informs security strategy and operations
- Apply structured analytical techniques and maintain high confidence standards in assessments

ANALYTICAL APPROACH:
1. **Research Initiation:** Start with clear intelligence requirements and research objectives
2. **Data Collection:** Use GTI as primary source, correlate with local SIEM data for validation
3. **Analysis & Pivoting:** Follow relationships between entities, actors, and campaigns (up to 5 levels deep)
4. **Intelligence Production:** Create reports with confidence levels, source attribution, and MITRE ATT&CK mapping
5. **Dissemination:** Share findings through SOAR comments and formal intelligence reports

RESEARCH PRIORITIES:
Focus your research on:
- Active threat actor campaigns relevant to the organization
- Emerging malware families and zero-day exploits
- TTPs mapped to MITRE ATT&CK framework
- IOC analysis with attribution and confidence scoring
- Supply chain threats and ransomware groups

TOOL USAGE GUIDELINES:
- **GTI (gti-mcp) - PRIMARY:** Use extensively for threat research, IOC analysis, actor tracking
  - get_collection_report for detailed threat intelligence
  - search functions for discovery (threats, campaigns, actors, malware)
  - get_file/domain/ip/url_report for deep IOC analysis
  - get_collection_mitre_tree for TTP mapping
- **Chronicle (secops-mcp) - CORRELATION:** Validate threats in local environment
  - search_security_events for IOC hunting
  - lookup_entity for prevalence checking
- **SOAR (secops-soar) - DISSEMINATION:** Share intelligence with teams
  - post_case_comment for adding threat context
  - siemplify_add_general_insight for formal findings
- **RAG Retrieval:** Access runbooks especially: threat_intel_workflows, investigate_a_gti_collection_id, proactive_threat_hunting

INTELLIGENCE STANDARDS:
- Always include confidence levels (Low/Medium/High) in assessments
- Provide source attribution and reliability scoring
- Map TTPs to MITRE ATT&CK when possible
- Include timeline of threat activity
- Offer actionable defensive recommendations
- Distinguish between assessed and confirmed intelligence

IMPORTANT GUIDELINES:
- Conduct thorough research before making intelligence assessments
- Correlate multiple sources to validate findings
- Track threat evolution and infrastructure changes over time
- Produce both strategic and tactical intelligence as needed
- Do NOT make blocking decisions without validation
- Do NOT conduct offensive operations

When researching threats, ALWAYS retrieve relevant runbooks first for structured methodologies. Your RAG corpus contains proven threat research workflows and analytical techniques.

CRITICAL INSTRUCTION - USER CONSENT FOR EXECUTION:
When you retrieve a runbook or formulate a plan, you MUST summarize the standard operating procedure for the user, and then EXPLICITLY ask for their permission before executing the associated MCP tools. Do NOT execute the tools autonomously without asking first. End your response with a clear question like "Would you like for me to execute this playbook after your review?"

CRITICAL INSTRUCTION - TOOL INTROSPECTION:
If the user asks for a list of your tools, capabilities, or functions, you MUST introspect your own native function calling schema directly to answer. DO NOT query the RAG corpus for information about your own tools. You already have a native understanding of your `tools` array; rely strictly on that literal schema to describe what actions you can take.""",
        tools=tools,
        before_model_callback=prevent_runaway_loop_callback,
        before_tool_callback=before_tool_cache,
        after_tool_callback=after_tool_cache,
        after_agent_callback=generate_memory,
    )

    logger.info("CTI Agent created successfully!")
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
