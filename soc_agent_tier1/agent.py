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

import logging
import os
from pathlib import Path

import vertexai
from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.tools import AgentTool, google_search
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval
from mcp import StdioServerParameters
from vertexai.preview import rag

from soc_agent.tools.vertex_ai_rag_tool import VertexAiRagRetrievalWithDocs


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
  - get_ioc_matches: To check for known bad indicators in SIEM
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
    RESULT_MODE = os.environ.get("RESULT_MODE", "chunks")

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
        ask_vertex_retrieval = VertexAiRagRetrievalWithDocs(
            name="retrieve_agentic_soc_runbooks",
            description=(
                "Use this tool to retrieve IRPs, Runbooks, Common Steps, and Personas for the Agentic SOC. "
                "As a Tier 1 analyst, prioritize retrieving: triage_alerts, basic_ioc_enrichment, "
                "close_duplicate_or_similar_cases, and other basic investigation procedures. "
                "The corpus contains step-by-step procedures optimized for your Tier 1 responsibilities."
            ),
            rag_resources=[rag.RagResource(rag_corpus=RAG_CORPUS_ID)],
            similarity_top_k=RAG_SIMILARITY_TOP_K,
            vector_distance_threshold=RAG_DISTANCE_THRESHOLD,
            result_mode=RESULT_MODE,
        )
        tools.append(ask_vertex_retrieval)
    else:
        logger.warning("RAG_CORPUS_ID not configured, skipping RAG retrieval tool")

    # ========================================================================
    # Add google_search as an AgentTool
    # ========================================================================
    tools.append(AgentTool(agent=google_search))

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
- **Chronicle (secops-mcp):** Use for basic entity lookups and alert queries only
- **SOAR (secops-soar):** Create/update cases, add findings, manage status
- **GTI (gti-mcp):** Basic reputation checks for suspicious indicators
- **RAG Retrieval:** Access runbooks especially: triage_alerts, basic_ioc_enrichment, close_duplicate_or_similar_cases

IMPORTANT LIMITATIONS:
- Do NOT perform deep forensic analysis or advanced threat hunting
- Do NOT make containment/remediation decisions - only recommend them
- Do NOT create or modify detection rules
- Stay within 2 levels of IOC pivoting/investigation depth

When unsure about procedures, ALWAYS retrieve the relevant runbook first. Your RAG corpus contains detailed step-by-step procedures optimized for Tier 1 operations.""",
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
