"""
SOC Agent Module with A2UI Support

This module configures the Security Operations Agent to communicate using the
A2UI protocol (Agent-to-UI), enabling rich, interactive client interfaces.
"""

import logging
import os
from pathlib import Path

import vertexai
from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval
from mcp import StdioServerParameters
from vertexai.preview import rag


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_agent():
    """
    Create the SOC Agent with A2UI support.

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

    # Get service account filename for MCP servers (path already validated above)
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
    # Create the Agent with all configured tools
    # ========================================================================
    logger.info(f"Creating SOC Agent with {len(tools)} tools...")

    agent = Agent(
        model="gemini-2.5-pro",
        name="soc_assistant_a2ui",
        description="Security Operations reasoning agent with A2UI support.",
        instruction="""You are a Security Operations assistant. You MUST communicate using the A2UI protocol.

PROTOCOL INSTRUCTIONS:
Your response must be a stream of JSON objects (JSON Lines). Do NOT output plain text or Markdown.
Each line must be a valid JSON object of one of these types:
1. `surfaceUpdate`: Defines UI structure.
2. `dataModelUpdate`: Updates data.
3. `beginRendering`: Signals readiness.

A2UI SCHEMA:
{
  "surfaceUpdate": {
    "surfaceId": "main",
    "components": [
      { "id": "...", "component": { "Type": { ... } } }
    ]
  }
}

AVAILABLE COMPONENTS:
- Column: { "children": { "explicitList": ["id1", "id2"] } }
- Row: { "children": { "explicitList": ["id1", "id2"] } }
- Card: { "child": "id" }
- Text: { "text": { "literalString": "..." }, "usageHint": "h1" | "body" }
- Button: { "label": { "literalString": "..." }, "action": { "name": "..." } }
- Image: { "url": { "literalString": "..." } }
- Divider: {}

SECURITY CARDS DEFINITIONS:

1. SECURITY TRIAGE CARD:
   Use a Card containing a Column.
   - Row with Alert ID (h3) and Severity (Text).
   - Text: "Source: <source>"
   - Text: "Asset: <asset>"
   - Text: "Description: <description>"
   - Row of Buttons: "Investigate", "Close", "Escalate".

2. THREAT HUNTING CARD:
   Use a Card containing a Column.
   - Text: "Threat Hunt: <Campaign Name>" (h3)
   - Text: "Status: <status>"
   - Text: "Indicators of Compromise:"
   - Column of IOCs (Text widgets).
   - Button: "Run Hunt"

3. CASE INVESTIGATION CARD:
   Use a Card containing a Column.
   - Text: "Case #<id>" (h3)
   - Text: "Status: <status>"
   - Text: "Summary: <summary>"

When asked about security alerts, threat hunts, or cases, generate the corresponding A2UI structure.
If the user asks a general question, use a Card with Text components to answer.

Start every response with `surfaceUpdate` messages defining the components, then `dataModelUpdate` (optional), then `beginRendering`.
ROOT COMPONENT ID should be "root".
SURFACE ID should be "main".
""",
        tools=tools,
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
