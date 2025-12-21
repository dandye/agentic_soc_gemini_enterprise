"""
SOC Agent Flash Module - Gemini 2.5 Flash Configuration

This module configures a Security Operations Agent using the Gemini 2.5 Flash model
for faster response times and lower cost, with MCP tools and RAG retrieval.

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

import logging
import os
from pathlib import Path

import vertexai
from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.tools import AgentTool, google_search
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.preload_memory_tool import PreloadMemoryTool
from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval
from mcp import StdioServerParameters
from vertexai.preview import rag


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def auto_save_session_to_memory_callback(callback_context):
    """
    Callback to automatically save the session to memory at the end of a turn.

    This ensures that all interactions are preserved in the configured memory service
    (InMemory or Vertex AI Memory Bank) for future recall.
    """
    if callback_context._invocation_context.memory_service:
        await callback_context._invocation_context.memory_service.add_session_to_memory(
            callback_context._invocation_context.session
        )


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
    SOAR_API_KEY = os.environ.get("SOAR_API_KEY")

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
    secops_siem_tools = McpToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="uv",
                args=[
                    "--directory",
                    "./mcp-security/server/secops/secops_mcp",
                    "run",
                    "server.py",
                ],
                env={
                    "CHRONICLE_PROJECT_ID": CHRONICLE_PROJECT_ID,
                    "CHRONICLE_CUSTOMER_ID": CHRONICLE_CUSTOMER_ID,
                    "CHRONICLE_REGION": CHRONICLE_REGION,
                    "SECOPS_SA_PATH": service_account_filename,
                },
            ),
            timeout=60000,
        ),
        errlog=None,
    )
    tools.append(secops_siem_tools)

    # ========================================================================
    # Configure SOAR MCP Tool
    # ========================================================================
    logger.info("Configuring SOAR tools...")
    secops_soar_tools = McpToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="uv",
                args=[
                    "--directory",
                    "./mcp-security/server/secops-soar/secops_soar_mcp",
                    "run",
                    "server.py",
                ],
                env={
                    "SOAR_URL": SOAR_URL,
                    "SOAR_APP_KEY": SOAR_API_KEY,  # MCP server expects SOAR_APP_KEY
                },
            ),
            timeout=60000,
        ),
        errlog=None,
    )
    tools.append(secops_soar_tools)

    # ========================================================================
    # Configure Google Threat Intelligence (GTI) MCP Tool
    # ========================================================================
    logger.info("Configuring GTI tools...")
    gti_tools = McpToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="uv",
                args=[
                    "--directory",
                    "./mcp-security/server/gti/gti_mcp",
                    "run",
                    "server.py",
                ],
                env={"VT_APIKEY": GTI_API_KEY},  # MCP server expects VT_APIKEY
            ),
            timeout=60000,
        ),
        errlog=None,
    )
    tools.append(gti_tools)

    # ========================================================================
    # Configure Security Command Center (SCC) MCP Tool
    # ========================================================================
    logger.info("Configuring SCC tools...")
    scc_tools = McpToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="uv",
                args=["--directory", "./mcp-security/server/scc", "run", "scc_mcp.py"],
                env={},
            ),
            timeout=60000,
        ),
        errlog=None,
    )
    tools.append(scc_tools)

    # ========================================================================
    # Configure RAG Retrieval Tool (if RAG corpus is configured)
    # ========================================================================
    if RAG_CORPUS_ID:
        logger.info(f"Configuring RAG retrieval with corpus: {RAG_CORPUS_ID}")
        ask_vertex_retrieval = VertexAiRagRetrieval(
            name="retrieve_agentic_soc_runbooks",
            description=(
                "Use this tool to retrieve IRPs, Runbooks, Common Steps, and Personas for the Agentic SOC."
            ),
            rag_resources=[rag.RagResource(rag_corpus=RAG_CORPUS_ID)],
            similarity_top_k=RAG_SIMILARITY_TOP_K,
            vector_distance_threshold=RAG_DISTANCE_THRESHOLD,
        )
        tools.append(ask_vertex_retrieval)
    else:
        logger.warning("RAG_CORPUS_ID not configured, skipping RAG retrieval tool")

    # ========================================================================
    # Add google_search as an AgentTool
    # ========================================================================
    tools.append(AgentTool(agent=google_search))

    # ========================================================================
    # Configure Memory Tools
    # ========================================================================
    logger.info("Configuring Memory tools...")
    # Add PreloadMemoryTool to automatically load relevant memories at the start of each turn
    tools.append(PreloadMemoryTool())

    # ========================================================================
    # Create the Agent with all configured tools
    # ========================================================================
    logger.info(f"Creating SOC Agent with {len(tools)} tools...")

    agent = Agent(
        model="gemini-3.0-flash",
        name="soc_assistant_flash_3",
        description="Security Operations reasoning agent with access to Agentic SOC MCP tools and runbook search.",
        instruction="""You are a Security Operations assistant with comprehensive access to MCP security tools including RAG-based runbook and documentation retrieval.

YOUR CAPABILITIES:
- Retrieve security Runbooks, IRPs, Common Steps, Procedures, guidelines, and personas using retrieve_agentic_soc_runbooks tool
- Query Chronicle/SIEM for security events and detections
- Manage SOAR cases and incidents
- Access threat intelligence through GTI tools
- Retrieve SCC findings and cloud security posture
- Use list_tools to get full MCP Tool list

WORKFLOW:
1. When users ask about runbooks or procedures, use the retrieve_agentic_soc_runbooks tool to retrieve relevant documentation from the RAG corpus
2. For security investigations, combine runbook guidance with live data from Chronicle, GTI, and SOAR
3. Provide comprehensive responses that integrate procedural knowledge with real-time security data

KEY TOOLS:
- retrieve_agentic_soc_runbooks: Retrieve security procedures and documentation from the RAG corpus
- Chronicle tools: Query SIEM for security events
- SOAR tools: Manage cases and incidents
- GTI tools: Get threat intelligence
- SCC tools: Cloud security findings

Always provide actionable guidance combining documented procedures with live security data.""",
        tools=tools,
        after_agent_callback=auto_save_session_to_memory_callback,
    )

    logger.info("SOC Agent created successfully!")
    return agent


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
]
