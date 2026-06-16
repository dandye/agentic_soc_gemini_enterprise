"""
SOC Agent Module - Tier 2 Incident Responder Configuration

This module configures a Tier 2 Incident Responder Agent with specific persona,
responsibilities, and MCP/ChatOps tools for threat containment and active mitigation.

ARCHITECTURAL DECISION: Intentional Code Duplication
======================================================
This module intentionally duplicates code from other agent_soc_manager_* modules
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


from collections.abc import AsyncGenerator  # noqa: E402

from google.adk.agents.invocation_context import InvocationContext  # noqa: E402
from google.adk.agents.sequential_agent import Event  # noqa: E402


_runtime_patches_applied = False


def _apply_runtime_patches():
    global _runtime_patches_applied
    if _runtime_patches_applied:
        return

    import logging

    logger = logging.getLogger(__name__)
    logger.warning(
        "[RUNTIME_PATCH_DEBUG] Applying runtime framework monkeypatches inside Reasoning Engine process..."
    )

    # 1. Monkeypatch validation function to prevent 400 INVALID_ARGUMENT when removing function call IDs
    try:
        import google.adk.flows.llm_flows.contents as adk_contents
        import google.adk.flows.llm_flows.functions as adk_funcs

        def _patched_remove_client_function_call_id(content) -> None:
            pass

        adk_funcs.remove_client_function_call_id = (
            _patched_remove_client_function_call_id
        )
        adk_contents.remove_client_function_call_id = (
            _patched_remove_client_function_call_id
        )
        logger.warning(
            "[RUNTIME_PATCH_DEBUG] Successfully patched remove_client_function_call_id"
        )
    except Exception as e:
        logger.warning(
            f"[RUNTIME_PATCH_DEBUG] Failed to patch remove_client_function_call_id: {e}"
        )

    # 2. Monkeypatch McpTool._get_declaration to strip response_json_schema
    try:
        from google.adk.tools.mcp_tool.mcp_tool import McpTool
        from google.genai.types import FunctionDeclaration

        def _patched_get_declaration(self) -> FunctionDeclaration:
            input_schema = self._mcp_tool.inputSchema
            return FunctionDeclaration(
                name=self.name,
                description=self.description,
                parameters_json_schema=input_schema,
                response_json_schema=None,
            )

        McpTool._get_declaration = _patched_get_declaration
        logger.warning(
            "[RUNTIME_PATCH_DEBUG] Successfully patched McpTool._get_declaration"
        )
    except Exception as e:
        logger.warning(
            f"[RUNTIME_PATCH_DEBUG] Failed to patch McpTool._get_declaration: {e}"
        )

    # 3. Monkeypatch encode_unserializable_types to preserve standard base64 encoding for thought_signature bytes
    try:
        import base64

        import google.genai._common as genai_common

        original_encode = genai_common.encode_unserializable_types

        def _patched_encode_unserializable_types(data):
            if isinstance(data, dict):
                processed = {}
                for k, v in data.items():
                    if k in ("thought_signature", "thoughtSignature") and isinstance(
                        v, bytes
                    ):
                        processed[k] = base64.b64encode(v).decode("ascii")
                    elif isinstance(v, dict):
                        processed[k] = _patched_encode_unserializable_types(v)
                    elif isinstance(v, list):
                        processed[k] = [
                            _patched_encode_unserializable_types(item)
                            if isinstance(item, dict)
                            else item
                            for item in v
                        ]
                    else:
                        processed[k] = v
                return original_encode(processed)
            return original_encode(data)

        genai_common.encode_unserializable_types = _patched_encode_unserializable_types
        logger.warning(
            "[RUNTIME_PATCH_DEBUG] Successfully patched encode_unserializable_types"
        )
    except Exception as e:
        logger.warning(
            f"[RUNTIME_PATCH_DEBUG] Failed to patch encode_unserializable_types: {e}"
        )

    # 4. Monkeypatch lite_llm._decode_thought_signature to normalize URL-safe base64 strings
    try:
        import google.adk.models.lite_llm as adk_lite_llm

        def _patched_decode_thought_signature(value):
            if isinstance(value, bytes):
                return value
            if isinstance(value, str):
                normalized = value.replace("-", "+").replace("_", "/")
                padding_needed = (4 - len(normalized) % 4) % 4
                normalized += "=" * padding_needed
                try:
                    return base64.b64decode(normalized, validate=True)
                except Exception as e:
                    logger.debug("Failed to decode thought signature in patch: %s", e)
            return None

        adk_lite_llm._decode_thought_signature = _patched_decode_thought_signature
        logger.warning(
            "[RUNTIME_PATCH_DEBUG] Successfully patched lite_llm._decode_thought_signature"
        )
    except Exception as e:
        logger.warning(
            f"[RUNTIME_PATCH_DEBUG] Failed to patch lite_llm._decode_thought_signature: {e}"
        )

    # 5. Monkeypatch part_converter base64.b64decode to normalize URL-safe base64 strings
    try:
        import google.adk.a2a.converters.part_converter as part_converter

        original_part_b64decode = part_converter.base64.b64decode

        def _patched_part_b64decode(s, *args, **kwargs):
            if isinstance(s, str):
                normalized = s.replace("-", "+").replace("_", "/")
                padding_needed = (4 - len(normalized) % 4) % 4
                normalized += "=" * padding_needed
                return original_part_b64decode(normalized, *args, **kwargs)
            return original_part_b64decode(s, *args, **kwargs)

        part_converter.base64.b64decode = _patched_part_b64decode
        logger.warning(
            "[RUNTIME_PATCH_DEBUG] Successfully patched part_converter base64.b64decode"
        )
    except Exception as e:
        logger.warning(
            f"[RUNTIME_PATCH_DEBUG] Failed to patch part_converter base64.b64decode: {e}"
        )

    # 6. Monkeypatch interactions_utils base64.b64decode to normalize URL-safe base64 strings
    try:
        import google.adk.models.interactions_utils as interactions_utils

        original_utils_b64decode = interactions_utils.base64.b64decode

        def _patched_utils_b64decode(s, *args, **kwargs):
            if isinstance(s, str):
                normalized = s.replace("-", "+").replace("_", "/")
                padding_needed = (4 - len(normalized) % 4) % 4
                normalized += "=" * padding_needed
                return original_utils_b64decode(normalized, *args, **kwargs)
            return original_utils_b64decode(s, *args, **kwargs)

        interactions_utils.base64.b64decode = _patched_utils_b64decode
        logger.warning(
            "[RUNTIME_PATCH_DEBUG] Successfully patched interactions_utils base64.b64decode"
        )
    except Exception as e:
        logger.warning(
            f"[RUNTIME_PATCH_DEBUG] Failed to patch interactions_utils base64.b64decode: {e}"
        )

    _runtime_patches_applied = True
    logger.warning("[RUNTIME_PATCH_DEBUG] All runtime patches applied successfully!")


class PatchedAgent(Agent):

    async def run_async(
        self,
        parent_context: InvocationContext,
    ) -> AsyncGenerator[Event, None]:
        _apply_runtime_patches()
        async for event in super().run_async(parent_context):
            yield event


# -------------------------------------------------------------------------


# ========================================================================
# Tier 2 Incident Responder Persona Definition
# ========================================================================
TIER2_PERSONA = """
## Tier 2 Incident Responder

### Overview
The Tier 2 Incident Responder is a senior security analyst responsible for active threat containment, technical mitigation, and deep incident response. When an alert is escalated, the Tier 2 Responder steps in to isolate infected systems, disable compromised accounts, revoke credentials, sinkhole malicious domains, and terminate unauthorized resources. Their primary objective is to minimize breach damage, neutralize active threats rapidly, and ensure safe recovery while maintaining strict compliance with human-in-the-loop approval checks.

### Primary Responsibilities
- **Threat Containment:** Rapidly isolate compromised hosts from the network to prevent lateral movement or data exfiltration.
- **Active Remediation:** Terminate unauthorized/malicious processes, destroy compromised containers, and sinkhole malicious infrastructure.
- **Credential Mitigation:** Revoke active sessions, reset user passwords, and temporarily disable compromised API credentials.
- **Incident Documentation:** Log all mitigation actions, execution timestamps, and post-remediation verification details in SOAR cases.
- **Safety Enforcer:** Always present containment strategies to human analysts and obtain explicit confirmation before executing state-changing commands.
- **Collaboration:** Coordinate with Tier 1 Analysts for initial triage context and CTI Researchers for advanced actor profiling and IOC matching.

### Core Skills and Knowledge
- Advanced host, container, and cloud network containment methodologies.
- Hands-on experience with SOAR active playbook execution and automation.
- Proficient in cloud resource management (terminating containers, revoking keys, manipulating security groups).
- Deep expertise in incident response frameworks (NIST, SANS).

### Tool Usage Patterns
**Primary MCP & Custom Tools:**
- **secops-soar (SOAR Platform):** Add case comments, tag artifacts, record containment insights, and execute mitigation playbooks.
- **secops-mcp (Chronicle SIEM):** Run UDM searches to verify successful containment (e.g., confirming isolated endpoint has stopped outbound traffic).
- **gti-mcp (Google Threat Intelligence):** Perform reputation checks to validate domains/IPs before initiating blocks.
- **ChatOps / Verification Skills:**
  - request_human_confirmation: MUST be called before executing any host isolation, process termination, or account block.
  - notify_human_incident: Alert the team of high-priority containment actions.
  - deliver_report: Share pre-signed links of mitigation reports in Workspace Chat.
"""

# Tier 2 specific configuration
TIER2_CONFIG = {
    "max_containment_depth": 3,
    "primary_runbooks": [
        "isolate_host",
        "malicious_container_kill",
        "remediate_credential_compromise",
        "firewall_ip_blocking",
    ],
    "actions_requiring_confirmation": [
        "isolate_host",
        "block_ip",
        "disable_credential",
        "kill_container",
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
                + ":/code/external/mcp-security/server/secops:/code/external/mcp-security/server/secops-soar:/code/external/mcp-security/server/gti:/code/external/mcp-security/server/scc"
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


def create_agent():
    """
    Create the standalone Tier 2 Incident Responder Agent with MCP and containment tools.
    """
    # Load environment variables from .env file
    load_dotenv(Path(".env"), override=True)

    # Model Configuration
    TIER2_RESPONDER_MODEL = os.environ.get("TIER2_RESPONDER_MODEL", "gemini-2.5-pro")

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

    # RAG configuration
    RAG_CORPUS_ID = os.environ.get("RAG_CORPUS_ID")
    RAG_LOCATION = os.environ.get("RAG_LOCATION") or os.environ.get("RAG_GCP_LOCATION")

    # Determine location: use RAG location if configured/parseable, otherwise deployment location
    init_location = GCP_LOCATION
    if RAG_CORPUS_ID:
        # Parse project and location from corpus resource name
        # Format: projects/PROJECT_ID/locations/LOCATION/ragCorpora/CORPUS_ID
        if "/" in RAG_CORPUS_ID:
            parts = RAG_CORPUS_ID.split("/")
            if len(parts) >= 4:
                rag_project_id = parts[1]
                rag_location = parts[3]

                # Fail fast and noisy on project mismatch
                if rag_project_id != GCP_PROJECT_ID:
                    raise ValueError(
                        f"PROJECT MISMATCH: The GCP_PROJECT_ID in your environment ({GCP_PROJECT_ID}) "
                        f"does not match the project ID embedded in your RAG_CORPUS_ID ({rag_project_id}). "
                        f"Please align them in your .env file."
                    )

                # Fail fast and noisy on location mismatch if explicitly configured
                if RAG_LOCATION and RAG_LOCATION != rag_location:
                    raise ValueError(
                        f"LOCATION MISMATCH: The RAG_LOCATION/RAG_GCP_LOCATION in your environment ({RAG_LOCATION}) "
                        f"does not match the location embedded in your RAG_CORPUS_ID ({rag_location}). "
                        f"Please align them in your .env file."
                    )
            else:
                rag_location = "us-east4"
        else:
            rag_location = "us-east4"

        init_location = rag_location
        logger.info("Initializing Vertex AI for RAG corpus access")
        logger.info(f"  Project: {GCP_PROJECT_ID}")
        logger.info(f"  RAG location: {rag_location}")
    else:
        logger.info("Initializing Vertex AI for model access")
        logger.info(f"  Project: {GCP_PROJECT_ID}")
        logger.info(f"  Location: {init_location}")

    # Initialize Vertex AI for the agent to work with Gemini models and RAG
    if (
        GCP_PROJECT_ID
        and GCP_VERTEXAI_ENABLED
        and GCP_VERTEXAI_ENABLED.upper() == "TRUE"
    ):
        vertexai.init(
            project=GCP_PROJECT_ID,
            location=init_location,
            staging_bucket=GCP_STAGING_BUCKET,
        )

    # SOAR configuration
    SOAR_URL = os.environ.get("SOAR_URL")
    SOAR_APP_KEY = os.environ.get("SOAR_APP_KEY")

    # Google Threat Intelligence configuration
    GTI_API_KEY = os.environ.get("GTI_API_KEY")

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
    # Add google_search as a standalone tool

    # ========================================================================
    # Add save_report_artifact as a standalone tool
    # ========================================================================
    tools.append(save_report_artifact)

    # ========================================================================
    # Add ChatOps Mitigation Skills
    # ========================================================================
    logger.info("Importing ChatOps mitigation tools...")
    try:
        from agent_soc_manager.tools.chatops_tools import (
            deliver_report,
            generic_notification,
            list_chatops_capabilities,
            notify_human_incident,
            request_human_confirmation,
            send_chatops_card,
            trigger_ai_brute_force_source_block_card,
            trigger_ai_data_exfiltration_block_card,
            trigger_ai_malicious_container_kill_card,
            trigger_ai_wipe_host_approval_card,
            trigger_vulnerability_patch_approval_card,
        )

        tools.extend(
            [
                deliver_report,
                generic_notification,
                list_chatops_capabilities,
                notify_human_incident,
                request_human_confirmation,
                send_chatops_card,
                trigger_vulnerability_patch_approval_card,
                trigger_ai_malicious_container_kill_card,
                trigger_ai_wipe_host_approval_card,
                trigger_ai_data_exfiltration_block_card,
                trigger_ai_brute_force_source_block_card,
            ]
        )
    except ImportError as import_e:
        logger.warning(
            f"Could not import ChatOps tools directly: {import_e}. Proceeding with MCP tools only."
        )

    # ========================================================================
    # Create the Agent with all configured tools
    # ========================================================================
    logger.info(f"Creating Tier 2 Incident Responder Agent with {len(tools)} tools...")

    agent = PatchedAgent(
        model=TIER2_RESPONDER_MODEL,
        name="soc_analyst_tier2_responder",
        description=TIER2_PERSONA,
        instruction="""You are a Tier 2 Incident Responder - a senior security operations engineer responsible for active threat containment, containment validation, and host/network remediation.

CRITICAL SAFETY RULE - HUMAN-IN-THE-LOOP MANDATORY:
**You are strictly forbidden from executing containment or mitigation actions (such as host isolation, domain/IP blocks, user credential suspension, or container teardowns) without first obtaining explicit human confirmation. You MUST call the `request_human_confirmation` tool to present an interactive card to the security analyst and receive positive confirmation before initiating any state-changing containment steps. Honesty about tool failures is mandatory.**

ROLE & FOCUS:
- You are a Tier 2 Incident Responder focused on active threat neutralization and containment
- Your mission is to minimize breach exposure and validate the success of containment actions
- Follow established containment runbooks and procedures - do not perform wild, unapproved commands

WORKFLOW APPROACH:
1. **Incident Escalation Intake:** Review the escalated case details and identify active threats (e.g., active malware beaconing, rogue container processes, credential abuse).
2. **Runbook Retrieval:** Use `retrieve_agentic_soc_runbooks` to access the specific containment and remediation playbooks.
3. **Formulate Containment Strategy:** Choose the appropriate containment action (e.g., isolating endpoint, block IP, suspended user).
4. **Obtain Approval:** Call `request_human_confirmation` to get the analyst's approval. Summarize the strategy clearly to the user first.
5. **Execute Containment:** Trigger the containment action via SOAR MCP playbooks or ChatOps cards.
6. **Containment Verification:** Use Chronicle SIEM (`search_security_events`) to verify that the compromised asset has stopped emitting traffic or beaconing.
7. **Documentation:** Document all findings and mitigation actions in the SOAR case using case comment tools.
8. **Report Artifact & Delivery:** Save a final containment summary report using `save_report_artifact`, and share the pre-signed link with the team using the `deliver_report` tool.

TRANSPARENCY IN RESPONSES:
When reporting results, ALWAYS include:
1. Which tool(s) you used (e.g., "I called `request_human_confirmation` to get approval for isolating...")
2. For SIEM verification searches: Extract and present the UDM query used to verify network isolation
3. The exact containment confirmation details or "no results found"

Remember: High-stakes containment requires speed, precision, and strict safety checks. Never act unilaterally on containment without a human in the loop.""",
        tools=tools,
        before_model_callback=prevent_runaway_loop_callback,
        before_tool_callback=before_tool_cache,
        after_tool_callback=after_tool_cache,
        after_agent_callback=generate_memory,
    )

    logger.info("Tier 2 Incident Responder Agent created successfully!")
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
