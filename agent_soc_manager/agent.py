import json
import logging
import mimetypes
import os
import sys
from pathlib import Path


# Add text/markdown mimetype for .md files
mimetypes.add_type("text/markdown", ".md")


# Override location BEFORE any google imports to enable Gemini 3.x models
# Gemini 3.x models require location="global" but Reasoning Engine deploys to a specific region
# This workaround routes model API calls to global while keeping Reasoning Engine regional
# See: https://github.com/google/adk-python/issues/3628#issuecomment-3595215761
os.environ["GOOGLE_CLOUD_LOCATION"] = "global"
if "GOOGLE_GENAI_USE_VERTEXAI" not in os.environ:
    if os.environ.get("REASONING_ENGINE_DEPLOYMENT") == "True":
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE"
    else:
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "FALSE"

"""
SOC Agent Module - Orchestrator with Sub-Agent Delegation

This module implements a multi-agent orchestrator pattern that intelligently delegates
tasks to specialized sub-agents using LLM-based delegation (sub_agents pattern).

ARCHITECTURE:
- Main orchestrator (gemini-3.1-pro-preview): Routes requests to appropriate specialists via LLM delegation
  - Direct tool: RAG retrieval (VertexAiRagRetrieval) for runbooks and procedures
  - Delegates to: CTI sub-agent and Tier 1 sub-agent or AgentTool
- CTI sub-agent (gemini-3.1-flash-preview): Threat intelligence research with MCP tools (GTI, SecOps SIEM, SecOps SOAR, SCC)
- Tier 1 sub-agent (gemini-3.1-flash-preview): Alert triage with MCP tools (SecOps SIEM, SecOps SOAR, GTI)

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

See PR #25 discussion for additional context on this architectural decision.
"""

# -------------------------------------------------------------------------
# Framework Monkey-Patches
# -------------------------------------------------------------------------
import google.adk.sessions.in_memory_session_service as im_session  # noqa: E402
import google.cloud.logging  # noqa: E402
import vertexai  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from google.adk.agents import Agent  # noqa: E402
from google.adk.agents.callback_context import CallbackContext  # noqa: E402
from google.adk.agents.context import Context  # noqa: E402
from google.adk.models import LlmRequest, LlmResponse  # noqa: E402
from google.adk.skills import load_skill_from_dir  # noqa: E402
from google.adk.tools import skill_toolset  # noqa: E402
from google.adk.tools.agent_tool import AgentTool  # noqa: E402
from google.adk.tools.mcp_tool.mcp_session_manager import (  # noqa: E402
    StdioConnectionParams,  # noqa: E402
)
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset  # noqa: E402
from mcp import StdioServerParameters  # noqa: E402


# Silence the harmless but noisy InMemorySessionService warning inside sub-agents
# The AgentTool spins up sub-agents with a brand new InMemorySessionService but passes
# the parent's session object, causing a "not in sessions" warning on every single event.
# TODO: This warning occurs because subagent runners do not share the main orchestrator's
# InMemorySessionService instance. This issue remains unresolved in ADK 2.0.0 (see enforcing
# checks on lines 329-337 of adk/sessions/in_memory_session_service.py).
# Review and safe to remove when ADK implements native session registry sharing across subagent delegation contexts.
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

import re  # noqa: E402

import google.adk.apps.app as adk_app  # noqa: E402


# Monkey-patch validate_app_name to prevent ADK 2.0 serialization errors
# The Vertex AI Agent Engine/Reasoning Engine uses the numeric engine resource ID as the App's name.
# ADK 2.0 App model validation rejects names that do not start with a letter.
original_validate_app_name = adk_app.validate_app_name


def _patched_validate_app_name(name: str) -> None:
    if re.match(r"^\d+$", name):
        return
    return original_validate_app_name(name)


adk_app.validate_app_name = _patched_validate_app_name

# Monkey-patch remove_client_function_call_id to preserve function call/response IDs on Vertex Reasoning Engine.
# Stripping these IDs causes 400 INVALID_ARGUMENT on multi-turn/tool-response queries.
import google.adk.flows.llm_flows.contents as adk_contents  # noqa: E402
import google.adk.flows.llm_flows.functions as adk_funcs  # noqa: E402


def _patched_remove_client_function_call_id(content) -> None:
    pass


adk_funcs.remove_client_function_call_id = _patched_remove_client_function_call_id
adk_contents.remove_client_function_call_id = _patched_remove_client_function_call_id

# Redirect LLM model request debug logs to warning level to guarantee they are logged line-by-line
llm_logger = logging.getLogger("google_adk.google.adk.models.google_llm")


def _patched_debug(msg, *args, **kwargs):
    for line in str(msg).splitlines():
        if line.strip():
            llm_logger.warning(f"[DEBUG OVERRIDE] {line}", *args, **kwargs)


llm_logger.debug = _patched_debug
# -------------------------------------------------------------------------


from google.adk.tools.load_memory_tool import LoadMemoryTool  # noqa: E402
from google.adk.tools.preload_memory_tool import PreloadMemoryTool  # noqa: E402
from google.adk.tools.retrieval import VertexAiRagRetrieval  # noqa: E402
from google.cloud import storage  # noqa: E402
from google.genai.types import (  # noqa: E402
    AutomaticFunctionCallingConfig,
    GenerateContentConfig,
    Part,
)

from agent_soc_manager.tools.chatops_tools import (  # noqa: E402
    deliver_report,
    generic_notification,
    list_chatops_capabilities,
    notify_human_incident,
    request_human_confirmation,
    request_triage_approval,
    send_all_example_cards,
    send_chatops_card,
    trigger_ai_brute_force_source_block_card,
    trigger_ai_canary_token_deployment_card,
    trigger_ai_compliance_violation_alert_card,
    trigger_ai_credential_reset_approval_card,
    trigger_ai_data_classification_request_card,
    trigger_ai_data_exfiltration_block_card,
    trigger_ai_dns_exfiltration_detection_card,
    trigger_ai_draft_comms_review_card,
    trigger_ai_false_positive_tuning_card,
    trigger_ai_firewall_bypass_request_card,
    trigger_ai_forensic_image_approval_card,
    trigger_ai_incident_closure_confirm_card,
    trigger_ai_incident_retrospective_request_card,
    trigger_ai_incident_summary_confirm_card,
    trigger_ai_malicious_container_kill_card,
    trigger_ai_malicious_domain_sinkhole_card,
    trigger_ai_network_scan_approval_card,
    trigger_ai_playbook_selection_card,
    trigger_ai_privilege_access_v2_card,
    trigger_ai_privileged_session_recording_card,
    trigger_ai_security_group_audit_card,
    trigger_ai_sensitive_log_access_card,
    trigger_ai_stale_account_cleanup_card,
    trigger_ai_suspicious_login_location_card,
    trigger_ai_suspicious_process_kill_card,
    trigger_ai_threat_hunt_hypothesis_card,
    trigger_ai_threat_intel_sharing_card,
    trigger_ai_user_interview_request_card,
    trigger_ai_user_privilege_audit_card,
    trigger_ai_vulnerability_revalidation_card,
    trigger_ai_wipe_host_approval_card,
    trigger_brute_force_alert_card,
    trigger_bulk_deletion_verification_card,
    trigger_forensics_evidence_ready_card,
    trigger_impossible_travel_alert_card,
    trigger_impossible_travel_verification_card,
    trigger_ioc_enrichment_card_card,
    trigger_malware_sandbox_report_card,
    trigger_mfa_api_key_alert_card,
    trigger_phishing_report_summary_card,
    trigger_shadow_it_discovery_card,
    trigger_temp_admin_request_card,
    trigger_vulnerability_patch_approval_card,
    verify_user_travel,
)


# Monkey-patch version property to prevent Vertex AI Agent Engine serialization errors
# The Vertex AI telemetry/instrumentation sometimes searches for '.version' on models/tools
Agent.version = "1.0"
AgentTool.version = "1.0"


# -------------------------------------------------------------------------
# Shared-Scope PreloadMemoryTool
# -------------------------------------------------------------------------
# PreloadMemoryTool uses process_llm_request() which bypasses
# before_tool_callback, so the monkey-patch in before_tool_cache that
# forces user_id="global_soc_team" does NOT apply.
# This subclass overrides process_llm_request to call the memory service
# directly with the shared team scope.
class SharedScopePreloadMemoryTool(PreloadMemoryTool):
    """PreloadMemoryTool that always searches under the shared team scope.

    The default PreloadMemoryTool uses the per-user scope from the
    invocation context. This subclass overrides the memory search to
    use user_id='global_soc_team' so that all analysts share the same
    memory bank.
    """

    SHARED_USER_ID = "global_soc_team"

    async def process_llm_request(self, *, tool_context, llm_request) -> None:
        from google.adk.tools import _memory_entry_utils

        user_content = tool_context.user_content
        if not user_content or not user_content.parts or not user_content.parts[0].text:
            return

        user_query = user_content.parts[0].text
        try:
            # Bypass tool_context.search_memory (which uses per-user scope)
            # and call the memory service directly with the shared team scope.
            memory_service = getattr(
                tool_context._invocation_context, "memory_service", None
            )
            if not memory_service:
                logger.warning("PRELOAD_MEMORY: No memory service available, skipping.")
                return

            response = await memory_service.search_memory(
                app_name=tool_context._invocation_context.app_name,
                user_id=self.SHARED_USER_ID,
                query=user_query,
            )
        except Exception:
            logger.warning(
                "Failed to preload shared-scope memory for query: %s",
                user_query,
            )
            return

        if not response.memories:
            return

        memory_text_lines = []
        for memory in response.memories:
            if time_str := (f"Time: {memory.timestamp}" if memory.timestamp else ""):
                memory_text_lines.append(time_str)
            if memory_text := _memory_entry_utils.extract_text(memory):
                memory_text_lines.append(
                    f"{memory.author}: {memory_text}" if memory.author else memory_text
                )
        if not memory_text_lines:
            return

        full_memory_text = "\n".join(memory_text_lines)
        si = f"""The following content is from your team's previous investigations and conversations.
They may be useful for answering the user's current query.
<PAST_CONVERSATIONS>
{full_memory_text}
</PAST_CONVERSATIONS>
"""
        llm_request.append_instructions([si])
        logger.info(
            "PRELOAD_MEMORY: Injected %d memory entries into system instruction.",
            len(memory_text_lines),
        )


# Explicitly disable the automatic execution loop
strict_config = GenerateContentConfig(
    automatic_function_calling=AutomaticFunctionCallingConfig(
        # maximum_remote_calls=0 # commenting out as this is possibly source of "400 INVALID_ARGUMENT." error when using gemini 3.1
        disable=True
    ),
)

# Determine Python executable based on environment
# In deployed Vertex AI environment, use container's virtual env Python
# In local development, use sys.executable (respects venv)
PYTHON_EXECUTABLE = (
    "/code/.venv/bin/python"
    if os.environ.get("REASONING_ENGINE_DEPLOYMENT") == "True"
    else sys.executable
)

# Configure logging


try:
    if os.environ.get("REASONING_ENGINE_DEPLOYMENT") == "True":
        logging_client = google.cloud.logging.Client()
        logging_client.setup_logging()
    else:
        logging.basicConfig(level=logging.INFO)
except Exception as e:
    print(f"Warning: Cloud logging initialization failed: {e}")

logger = logging.getLogger(__name__)

# ========================================================================
# Persona Definitions (extracted from specialized agents)
# ========================================================================

CTI_PERSONA = """
## Cyber Threat Intelligence (CTI) Researcher

### Overview
The Cyber Threat Intelligence (CTI) Researcher focuses on the proactive discovery, analysis, and dissemination of intelligence regarding cyber threats. They delve deep into threat actors, malware families, campaigns, vulnerabilities, and Tactics, Techniques, and Procedures (TTPs) to understand the evolving threat landscape.

### Primary Responsibilities
- Conduct in-depth research on threat actors, malware families, campaigns, and vulnerabilities
- Identify, extract, analyze, and contextualize IOCs and TTPs. Map findings to MITRE ATT&CK framework
- Monitor and track threat actor activities, infrastructure, and evolution over time
- Produce detailed and actionable threat intelligence reports
- Collaborate with SOC analysts, incident responders, and security engineers

### Core Skills
- Deep understanding of cyber threat landscape
- Proficiency in threat intelligence platforms (Google Threat Intelligence/VirusTotal)
- Strong knowledge of IOC types and TTPs
- Experience with OSINT gathering and MITRE ATT&CK framework
- Excellent analytical and report writing skills
"""

TIER1_PERSONA = """
## Tier 1 SOC Analyst

### Overview
The Tier 1 SOC Analyst is the first line of defense, responsible for monitoring security alerts, performing initial triage, and escalating incidents based on predefined procedures.

### Primary Responsibilities
- Actively monitor alert queues in SOAR platform
- Perform initial assessment based on severity, type, and initial indicators
- Gather preliminary information using basic lookup tools
- Create and manage cases in SOAR
- Identify and close duplicate cases or false positives
- Escalate complex or confirmed incidents to Tier 2/3 analysts
- Maintain clear documentation within SOAR cases

### Core Skills
- Understanding of fundamental cybersecurity concepts
- Ability to perform basic entity enrichment using SIEM
- Strong attention to detail and ability to follow procedures
- Good communication skills for documentation and escalation
"""

# ========================================================================
# Helper Functions
# ========================================================================


async def fetch_full_document(gcs_uri: str, ctx: Context) -> str:
    """
    Fetches the complete document text from Google Cloud Storage.

    Args:
        gcs_uri: The gs:// URI of the document (found via the RAG retrieval tool).
    """
    logger.info(f"FETCH_FULL_DOC_CALL: Initiated for URI: {gcs_uri}")
    if not gcs_uri.startswith("gs://"):
        logger.warning(f"FETCH_FULL_DOC_ERROR: Invalid URI format: {gcs_uri}")
        return "Error: Please provide a valid gs:// URI."

    try:
        # Parse the GCS URI
        path_parts = gcs_uri.replace("gs://", "").split("/", 1)
        bucket_name = path_parts[0]
        blob_name = path_parts[1]

        logger.info(
            f"FETCH_FULL_DOC_GCS: Accessing bucket='{bucket_name}', blob='{blob_name}'"
        )

        # Fetch the blob
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)

        # Download and return the full text
        content = blob.download_as_text()

        # Log the line count as proof of document size
        line_count = len(content.splitlines())
        logger.info(
            f"FETCH_FULL_DOC_SUCCESS: Retrieved document. Total size: {len(content)} characters, Total lines: {line_count}"
        )
        logger.info("FETCH_FULL_DOC_CTX: Calling save_report_artifact automatically.")
        base_name = blob_name.split("/")[-1]
        if not base_name.endswith(".md"):
            base_name += ".md"
        filename = f"runbook_{base_name}"
        await save_report_artifact(filename, content, ctx)
        return content
    except Exception as e:
        logger.error(
            f"FETCH_FULL_DOC_ERROR: Failed to retrieve document: {str(e)}",
            exc_info=True,
        )
        return f"Failed to retrieve document: {str(e)}"


async def save_report_artifact(filename: str, report_content: str, ctx: Context) -> str:
    """
    Saves a generated analysis, intelligence report, or investigation finding as an artifact.
    MUST be called by the agent whenever you finalize a detailed report to formally save it to the system.
    Also call whenever a document is obtained from fetch_full_document.

    Args:
        filename: A logical filename for the report ending in .md (e.g. 'APT29_Analysis.md').
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

        # Default to ADK protocol if we can't determine the bucket
        link_to_provide = f"[{filename}](artifact://{filename})"

        # Dynamically construct the real Google Cloud Storage URL if the GcsArtifactService is used
        try:
            if (
                hasattr(ctx, "_invocation_context")
                and ctx._invocation_context.artifact_service
            ):
                art_svc = ctx._invocation_context.artifact_service

                # Unwrap ForwardingArtifactService when called by sub-agents
                while (
                    hasattr(art_svc, "_invocation_context")
                    and hasattr(art_svc._invocation_context, "artifact_service")
                    and art_svc._invocation_context.artifact_service is not art_svc
                ):
                    art_svc = art_svc._invocation_context.artifact_service

                if hasattr(art_svc, "bucket_name"):
                    bucket = art_svc.bucket_name
                    # Always use the root context's app/user/session since that's where GcsArtifactService saves it
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
                        # Fallback to direct console link
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
    except ValueError as e:
        logger.error(
            f"SAVE_REPORT_ARTIFACT_ERROR: ValueError - ArtifactService might not be configured: {e}"
        )
        return f"Error saving report: {e}. ArtifactService might not be configured."
    except Exception as e:
        logger.error(
            f"SAVE_REPORT_ARTIFACT_ERROR: Unexpected error: {e}", exc_info=True
        )
        return f"An unexpected error occurred saving report: {e}"


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
        # to force LoadMemoryTool (on-demand) to retrieve from the global team scope.
        # NOTE: PreloadMemoryTool bypasses before_tool_callback entirely
        # (it uses process_llm_request), so SharedScopePreloadMemoryTool
        # handles the shared scope directly in its override.
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


def compress_vt_report_data(raw_data):
    """Compresses VirusTotal report data to reduce context size."""
    try:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except json.JSONDecodeError:
                return raw_data  # Not JSON, return as is

        if not isinstance(raw_data, dict):
            return raw_data

        data = raw_data.get("data", raw_data)
        if not isinstance(data, dict):
            return raw_data

        attributes = data.get("attributes", data)
        if not isinstance(attributes, dict):
            return raw_data

        compressed_report = {
            "id": data.get("id"),
            "hashes": {
                "sha256": attributes.get("sha256"),
                "md5": attributes.get("md5"),
                "sha1": attributes.get("sha1"),
            },
            "names": attributes.get("names", [])[:5],
            "file_type": attributes.get("type_description"),
            "tags": attributes.get("tags", []),
            "analysis_stats": attributes.get("last_analysis_stats", {}),
            "threat_classification": attributes.get(
                "popular_threat_classification", {}
            ).get("suggested_threat_label", "Unknown"),
            "threat_severity": attributes.get("threat_severity", {}).get(
                "threat_severity_level", "Unknown"
            ),
            "severity_description": attributes.get("threat_severity", {}).get(
                "level_description", ""
            ),
        }

        sigma = attributes.get("sigma_analysis_results", [])
        if sigma:
            if isinstance(sigma[0], dict):
                compressed_report["sigma_rules"] = [
                    r.get("rule_title") for r in sigma if "rule_title" in r
                ]
            else:
                compressed_report["sigma_rules"] = sigma

        yara = attributes.get("crowdsourced_yara_results", [])
        if yara:
            compressed_report["yara_rules"] = [
                r.get("rule_name") for r in yara if "rule_name" in r
            ]

        final_report = {}
        for k, v in compressed_report.items():
            if v and v != "Unknown":
                if isinstance(v, dict):
                    clean_dict = {dk: dv for dk, dv in v.items() if dv is not None}
                    if clean_dict:
                        final_report[k] = clean_dict
                elif isinstance(v, list) and not v:
                    pass
                else:
                    final_report[k] = v

        return final_report
    except Exception as e:
        logger.error(f"Failed to compress VT report data: {e}", exc_info=True)
        return raw_data


async def after_tool_cache(tool, args, tool_context: Context, tool_response, **kwargs):
    """
    Caches the tool result for deduplication within the same session.
    Memory generation is handled by after_agent_callback (generate_memory)
    at the end of each agent turn — not per tool call.
    """
    try:
        # Compress GTI get_file_report responses to save context window
        if tool.name == "get_file_report":
            try:
                if hasattr(tool_response, "content") and isinstance(
                    tool_response.content, list
                ):
                    for content_item in tool_response.content:
                        if hasattr(content_item, "text"):
                            compressed = compress_vt_report_data(content_item.text)
                            content_item.text = (
                                json.dumps(compressed)
                                if isinstance(compressed, dict)
                                else compressed
                            )
                elif isinstance(tool_response, str):
                    compressed = compress_vt_report_data(tool_response)
                    tool_response = (
                        json.dumps(compressed)
                        if isinstance(compressed, dict)
                        else compressed
                    )
                elif isinstance(tool_response, dict):
                    tool_response = compress_vt_report_data(tool_response)
            except Exception as e:
                logger.error(
                    f"Error compressing get_file_report data: {e}", exc_info=True
                )

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


async def delegate_to_tier2_responder(query: str, tool_context: Context) -> str:
    """
    Delegates threat containment, host isolation, container teardown, or active mitigation
    to the standalone Tier 2 Incident Responder agent remotely via Agent-to-Agent (A2A) call.
    Use this tool ONLY when a threat is confirmed and active containment/mitigation is required.

    Args:
        query: The specific containment task or mitigation request (e.g., 'Isolate host MALWARETEST-WIN' or 'Suspend compromised user credentials').
    """
    logger.info(
        f"A2A_DELEGATION: Attempting to delegate to Tier 2 Incident Responder for: {query}"
    )
    try:
        # Retrieve Tier 2 Agent Engine resource name from environment variables
        tier2_engine_name = os.environ.get("TIER2_AGENT_RESOURCE_NAME")
        if not tier2_engine_name:
            logger.error(
                "A2A_DELEGATION_ERROR: TIER2_AGENT_RESOURCE_NAME not set in environment."
            )
            return "Error: Tier 2 Incident Responder is not currently configured in the environment."

        # Get the remote Reasoning Engine client
        from vertexai import agent_engines

        remote_engine = agent_engines.get(tier2_engine_name)

        # Retrieve session context parameters
        session_id = None  # Let remote specialist auto-create its own session to prevent SessionNotFoundError
        user_id = "secops_assistant"

        # Map parent context to child session if available
        if (
            hasattr(tool_context, "_invocation_context")
            and tool_context._invocation_context
        ):
            root_ctx = tool_context._invocation_context
            if hasattr(root_ctx, "user_id"):
                user_id = root_ctx.user_id

        logger.info(
            f"A2A_DELEGATION: Calling remote Tier 2 agent ({tier2_engine_name}) with User: {user_id}"
        )

        # Invoke the remote engine client dynamically accumulating streaming events
        response_parts = []
        async for event in remote_engine.async_stream_query(
            user_id=user_id, session_id=session_id, message=query
        ):
            logger.debug(f"A2A_DELEGATION_EVENT: {event}")

            # Safe lookup helper supporting both dict and object structures interchangeably
            def get_field(obj, field_name):
                if obj is None:
                    return None
                if isinstance(obj, dict):
                    return obj.get(field_name)
                return getattr(obj, field_name, None)

            # Extract text content and tool invocations safely
            content = get_field(event, "content")
            if content:
                parts = get_field(content, "parts")
                if parts and isinstance(parts, list):
                    for part in parts:
                        # 1. Extract conversational text
                        text = get_field(part, "text")
                        if text:
                            response_parts.append(text)

                        # 2. Extract tool/function calls for real-time status updates
                        function_call = get_field(part, "function_call")
                        if function_call:
                            name = get_field(function_call, "name")
                            if name in [
                                "request_human_confirmation",
                                "request_triage_approval",
                            ]:
                                response_parts.append(
                                    "[Specialist Action] Dispatched a high-priority ChatOps confirmation card to the security operations channel requesting human analyst approval before executing containment."
                                )
                            elif name == "deliver_report":
                                response_parts.append(
                                    "[Specialist Action] Saved and delivered the incident containment report to the security operations channel."
                                )
                            else:
                                response_parts.append(
                                    f"[Specialist Action] Invoking containment tool: {name}"
                                )

        final_text = "".join(response_parts).strip()
        if not final_text:
            final_text = "The Tier 2 specialist completed the request without generating a text response."

        logger.info("A2A_DELEGATION_SUCCESS: Successfully completed remote A2A call.")
        return (
            f"--- Response from Tier 2 Incident Responder Specialist ---\n{final_text}"
        )

    except Exception as e:
        logger.error(
            f"A2A_DELEGATION_ERROR: Failed to delegate task to Tier 2 agent: {e}",
            exc_info=True,
        )
        return f"Failed to communicate with the remote Tier 2 Incident Responder specialist agent: {e}"


def _find_mcp_paths() -> list[str]:
    root_dir = Path(__file__).parent.parent.absolute()

    paths = []
    target_names = {"secops", "secops-soar", "gti", "scc"}

    # Check directly under root_dir (container flat packaging)
    for name in target_names:
        dir_path = root_dir / name
        if dir_path.exists() and dir_path.is_dir():
            paths.append(str(dir_path))

    # Check under root_dir / "external/mcp-security/server" (local directory layout)
    local_mcp_dir = root_dir / "external/mcp-security/server"
    if local_mcp_dir.exists() and local_mcp_dir.is_dir():
        for name in target_names:
            dir_path = local_mcp_dir / name
            if dir_path.exists() and dir_path.is_dir():
                paths.append(str(dir_path))

    return list(set(paths))


def create_agent():
    """
    Create the SOC Orchestrator Agent with specialized sub-agents.

    This function creates a multi-agent system where:
    1. Main orchestrator routes requests to appropriate specialists
    2. RAG sub-agent handles runbook retrieval
    3. CTI sub-agent handles threat intelligence research and quick lookups
    4. Tier 1 sub-agent handles alert triage and case management

    Returns:
        Configured Agent instance (orchestrator)
    """
    # Load environment variables from .env file
    load_dotenv(Path(".env"), override=True)

    # Model Configuration
    ORCHESTRATOR_MODEL = os.environ.get("ORCHESTRATOR_MODEL", "gemini-3.1-pro-preview")
    CTI_RESEARCHER_MODEL = os.environ.get("CTI_RESEARCHER_MODEL", "gemini-3.5-flash")
    TIER1_ANALYST_MODEL = os.environ.get("TIER1_ANALYST_MODEL", "gemini-3.5-flash")
    logger.warning("Model configuration loaded:")
    logger.warning(f"  ORCHESTRATOR_MODEL: {ORCHESTRATOR_MODEL}")
    logger.warning(f"  CTI_RESEARCHER_MODEL: {CTI_RESEARCHER_MODEL}")
    logger.warning(f"  TIER1_ANALYST_MODEL: {TIER1_ANALYST_MODEL}")

    # Get all required environment variables
    logger.warning("AUTH_DEBUG [agent_soc_manager]: Starting create_agent() execution")
    GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")
    logger.warning(f"AUTH_DEBUG [agent_soc_manager]: GCP_PROJECT_ID={GCP_PROJECT_ID}")
    GCP_LOCATION = os.environ.get("GCP_LOCATION", "us-central1")
    GCP_STAGING_BUCKET = os.environ.get("GCP_STAGING_BUCKET")
    GCP_VERTEXAI_ENABLED = os.environ.get("GCP_VERTEXAI_ENABLED", "True")

    # Chronicle/SIEM configuration
    CHRONICLE_CUSTOMER_ID = os.environ.get("CHRONICLE_CUSTOMER_ID")
    CHRONICLE_PROJECT_ID = os.environ.get("CHRONICLE_PROJECT_ID")
    CHRONICLE_REGION = os.environ.get("CHRONICLE_REGION", "us")
    CHRONICLE_SERVICE_ACCOUNT_PATH = os.environ.get("CHRONICLE_SERVICE_ACCOUNT_PATH")
    CHRONICLE_SERVICE_ACCOUNT_SECRET = os.environ.get(
        "CHRONICLE_SERVICE_ACCOUNT_SECRET"
    )
    logger.warning(
        f"AUTH_DEBUG [agent_soc_manager]: CHRONICLE_CUSTOMER_ID={CHRONICLE_CUSTOMER_ID}"
    )
    logger.warning(
        f"AUTH_DEBUG [agent_soc_manager]: CHRONICLE_PROJECT_ID={CHRONICLE_PROJECT_ID}"
    )
    logger.warning(
        f"AUTH_DEBUG [agent_soc_manager]: CHRONICLE_REGION={CHRONICLE_REGION}"
    )
    logger.warning(
        f"AUTH_DEBUG [agent_soc_manager]: CHRONICLE_SERVICE_ACCOUNT_PATH={CHRONICLE_SERVICE_ACCOUNT_PATH}"
    )
    logger.warning(
        f"AUTH_DEBUG [agent_soc_manager]: CHRONICLE_SERVICE_ACCOUNT_SECRET={CHRONICLE_SERVICE_ACCOUNT_SECRET[:50] if CHRONICLE_SERVICE_ACCOUNT_SECRET else None}"
    )

    # Validate required Chronicle environment variables
    if not CHRONICLE_PROJECT_ID:
        raise ValueError(
            "CHRONICLE_PROJECT_ID is required. Please set it in your .env file."
        )

    # Validate service account configuration (either secret or file path required)
    if not CHRONICLE_SERVICE_ACCOUNT_SECRET and not CHRONICLE_SERVICE_ACCOUNT_PATH:
        raise ValueError(
            "Either CHRONICLE_SERVICE_ACCOUNT_SECRET or CHRONICLE_SERVICE_ACCOUNT_PATH is required.\n"
            "Set CHRONICLE_SERVICE_ACCOUNT_SECRET for Secret Manager (recommended) or\n"
            "CHRONICLE_SERVICE_ACCOUNT_PATH for local file."
        )

    # Verify service account file exists if using local path
    if CHRONICLE_SERVICE_ACCOUNT_PATH:
        service_account_path = Path(CHRONICLE_SERVICE_ACCOUNT_PATH)
        if not service_account_path.exists():
            raise FileNotFoundError(
                f"Chronicle service account file not found: {CHRONICLE_SERVICE_ACCOUNT_PATH}\n"
                f"Please verify the path in your .env file points to a valid service account JSON file."
            )
        service_account_filename = service_account_path.name
    else:
        # Using Secret Manager - no local file needed
        service_account_filename = None

    # SOAR configuration
    SOAR_URL = os.environ.get("SOAR_URL")
    SOAR_APP_KEY = os.environ.get("SOAR_APP_KEY")

    # Google Threat Intelligence configuration
    GTI_API_KEY = os.environ.get("GTI_API_KEY")

    # Build container paths statically to ensure container compatibility when pickled
    container_paths = [
        "/code/external/mcp-security/server/secops",
        "/code/external/mcp-security/server/secops-soar",
        "/code/external/mcp-security/server/gti",
        "/code/external/mcp-security/server/scc",
    ]
    mcp_paths = _find_mcp_paths()
    all_paths = list(set(container_paths + mcp_paths))
    current_pythonpath = os.environ.get("PYTHONPATH", "")
    new_pythonpath = os.pathsep.join(
        all_paths + [current_pythonpath] if current_pythonpath else all_paths
    )

    mcp_env = os.environ.copy()
    mcp_env.update(
        {
            "CHRONICLE_PROJECT_ID": CHRONICLE_PROJECT_ID or "",
            "CHRONICLE_CUSTOMER_ID": CHRONICLE_CUSTOMER_ID or "",
            "CHRONICLE_REGION": CHRONICLE_REGION or "us",
            "SOAR_URL": SOAR_URL or "",
            "SOAR_APP_KEY": SOAR_APP_KEY or "",
            "VT_APIKEY": GTI_API_KEY or "",  # GTI uses VT_APIKEY
            "GCP_PROJECT_ID": GCP_PROJECT_ID or "",
            "PYTHONPATH": new_pythonpath,
            # GTI caching configuration (latency optimization)
            "GTI_CACHE_ENABLED": os.environ.get("GTI_CACHE_ENABLED", "True"),
            "GTI_CACHE_FILE_TTL": os.environ.get("GTI_CACHE_FILE_TTL", "86400"),
            "GTI_CACHE_IP_TTL": os.environ.get("GTI_CACHE_IP_TTL", "900"),
            "GTI_CACHE_DOMAIN_TTL": os.environ.get("GTI_CACHE_DOMAIN_TTL", "1800"),
            "GTI_CACHE_URL_TTL": os.environ.get("GTI_CACHE_URL_TTL", "1800"),
            "GTI_CACHE_MAX_SIZE": os.environ.get("GTI_CACHE_MAX_SIZE", "1000"),
            "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY": "True",
            "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "True",
            "OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT": "32768",  # Truncate large tool payloads to prevent 64KB GCP Trace limit crash
            "OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT": "32768",
        }
    )

    # Add Chronicle service account if available
    if CHRONICLE_SERVICE_ACCOUNT_SECRET:
        logger.warning(
            "AUTH_DEBUG [agent_soc_manager]: Adding CHRONICLE_SERVICE_ACCOUNT_SECRET to mcp_env"
        )
        mcp_env["CHRONICLE_SERVICE_ACCOUNT_SECRET"] = CHRONICLE_SERVICE_ACCOUNT_SECRET
    elif service_account_filename:
        logger.warning(
            "AUTH_DEBUG [agent_soc_manager]: Adding SECOPS_SA_PATH to mcp_env"
        )
        # Ensure we use the filename (not absolute path) so it works in the container where the file is copied.
        # For local execution, use the absolute path since the file isn't copied to the runner CWD.
        if os.environ.get("REASONING_ENGINE_DEPLOYMENT") == "True":
            mcp_env["SECOPS_SA_PATH"] = service_account_filename
        else:
            mcp_env["SECOPS_SA_PATH"] = CHRONICLE_SERVICE_ACCOUNT_PATH
    else:
        logger.warning(
            "AUTH_DEBUG [agent_soc_manager]: NEITHER SECRET NOR PATH WAS ADDED TO mcp_env!"
        )

    # RAG configuration
    RAG_CORPUS_ID = os.environ.get("RAG_CORPUS_ID")
    RAG_SIMILARITY_TOP_K = int(os.environ.get("RAG_SIMILARITY_TOP_K", "10"))
    RAG_DISTANCE_THRESHOLD = float(os.environ.get("RAG_DISTANCE_THRESHOLD", "0.6"))

    # Debug mode
    DEBUG = os.environ.get("DEBUG", "False") == "True"
    if DEBUG:
        os.environ["GRPC_VERBOSITY"] = "DEBUG"
        os.environ["GRPC_TRACE"] = "all"
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger("google").setLevel(logging.DEBUG)

    # Initialize Vertex AI for model access
    # When deployed to Vertex AI Reasoning Engine, agents need Vertex AI initialized
    # to use Vertex AI models instead of falling back to genai client
    skip_vertexai_init = os.environ.get("SKIP_VERTEXAI_INIT", "False") == "True"

    # Always initialize Vertex AI when enabled, using appropriate location
    if not skip_vertexai_init and GCP_PROJECT_ID and GCP_VERTEXAI_ENABLED == "True":
        # Determine location: use RAG location if RAG is configured, otherwise deployment location
        if RAG_CORPUS_ID:
            # Parse RAG location from corpus resource name
            # Format: projects/PROJECT_ID/locations/LOCATION/ragCorpora/CORPUS_ID
            rag_location = (
                RAG_CORPUS_ID.split("/")[3] if "/" in RAG_CORPUS_ID else "us-east4"
            )
            init_location = rag_location
            logger.info("Initializing Vertex AI for RAG corpus access")
            logger.info(f"  Project: {GCP_PROJECT_ID}")
            logger.info(f"  RAG location: {rag_location}")
        else:
            # No RAG - use deployment location
            init_location = GCP_LOCATION
            logger.info("Initializing Vertex AI for model access")
            logger.info(f"  Project: {GCP_PROJECT_ID}")
            logger.info(f"  Location: {init_location}")

        vertexai.init(
            project=GCP_PROJECT_ID,
            location=init_location,
            staging_bucket=GCP_STAGING_BUCKET,
        )
    elif skip_vertexai_init:
        logger.info("Skipping Vertex AI initialization (deployment mode)")
    else:
        logger.info("Vertex AI not initialized - agents will use Gemini API key")
        logger.info("  Gemini API key from environment: GEMINI_API_KEY")
        logger.info("  No location restrictions - all Gemini models available")

    # ========================================================================
    # SUB-AGENT 1: CTI Researcher (GTI + Chronicle + SOAR)
    # ========================================================================
    logger.info("Creating CTI sub-agent...")

    logger.info("Loading ADK Skills...")
    skill_dir = Path(__file__).parent / "skills"
    ioc_enrichment_skill = load_skill_from_dir(skill_dir / "ioc-enrichment-skill")
    malware_triage_skill = load_skill_from_dir(skill_dir / "malware-triage-skill")
    chatops_skill = load_skill_from_dir(skill_dir / "chatops-skill")

    cti_skill_toolset = skill_toolset.SkillToolset(skills=[ioc_enrichment_skill])
    tier1_skill_toolset = skill_toolset.SkillToolset(
        skills=[malware_triage_skill, chatops_skill]
    )

    cti_tools = [
        save_report_artifact,
        cti_skill_toolset,
        SharedScopePreloadMemoryTool(),  # Auto-load memories at start of every turn
        LoadMemoryTool(),  # On-demand memory queries during investigation
    ]

    # GTI tools for threat intelligence
    cti_tools.append(
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=PYTHON_EXECUTABLE,
                    args=["-m", "gti_mcp.server"],
                    env=mcp_env,
                ),
                timeout=90000,  # 90 seconds (balanced timeout)
            ),
            errlog=None,  # Suppress errlog to permit serialization
        )
    )

    # Chronicle for correlation
    cti_tools.append(
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=PYTHON_EXECUTABLE,
                    args=["-m", "secops_mcp.server"],
                    env=mcp_env,
                ),
                timeout=90000,  # 90 seconds (balanced timeout)
            ),
            errlog=None,  # Suppress errlog to permit serialization
        )
    )

    # SOAR for dissemination
    cti_tools.append(
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=PYTHON_EXECUTABLE,
                    args=["-m", "secops_soar_mcp.server"],
                    env=mcp_env,
                ),
                timeout=90000,  # 90 seconds (balanced timeout)
            ),
            errlog=None,  # Suppress errlog to permit serialization
        )
    )

    # SCC for cloud security findings
    cti_tools.append(
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=PYTHON_EXECUTABLE, args=["-m", "scc_mcp"], env=mcp_env
                ),
                timeout=90000,  # 90 seconds (balanced timeout)
            ),
            errlog=None,  # Suppress errlog to permit serialization
        )
    )

    cti_subagent = Agent(
        name="cti_researcher",
        model=CTI_RESEARCHER_MODEL,
        description=CTI_PERSONA,
        instruction="""You are a Cyber Threat Intelligence (CTI) Researcher focused on proactive threat discovery, analysis, and intelligence production.

CRITICAL SAFETY RULE - NEVER HALLUCINATE:
**NEVER make up threat intelligence data, IOCs, or findings. If a tool fails or returns an error, you MUST report the actual error to the user. Do NOT fabricate threat actor details, IOCs, attack patterns, or any other intelligence data. Honesty about tool failures is mandatory.**

INTERPRETING TOOL RESPONSES:
- **Tool Error (isError=True or exception)**: Report the actual error to the user
- **Empty Success (isError=False, empty/null data)**: Confidently state "No results found" or "No [items] at this time"
  - Example: `list_cases()` returns `{}` → "There are no open cases at this time"
  - Example: `search_security_events()` returns `[]` → "No events matching the criteria were found"
- Do NOT say "unable to retrieve" or "might indicate" when a tool succeeds with empty results - be definitive

ROLE & FOCUS:
- Specialize in threat actor tracking, malware analysis, and campaign investigation
- Produce actionable intelligence that informs security strategy and operations
- Apply structured analytical techniques and maintain high confidence standards

ANALYTICAL APPROACH:
1. Research Initiation: Start with clear intelligence requirements
2. Data Collection: Use GTI as primary source, correlate with Chronicle
3. Analysis & Pivoting: Follow relationships between entities, actors, campaigns (up to 5 levels deep)
4. Intelligence Production: Create reports with confidence levels, source attribution, MITRE ATT&CK mapping
5. Dissemination: Share findings through SOAR comments

TOOL USAGE:
- **LoadMemoryTool** (CONTEXT): Retrieve historical insights, actor profiles, and previous investigation findings.
  - ALWAYS use this at the start of a research task to identify known patterns or previous encounters with an entity/actor.
- **GTI (PRIMARY)**: Threat research, IOC analysis, actor tracking, collection reports, MITRE mapping
  - Specify which GTI tool you used (e.g., `get_ip_address_report()`, `get_file_report()`)
- **Chronicle (CORRELATION)**: Validate threats locally, IOC hunting, prevalence checking
  - When using `search_security_events()`, ALWAYS extract and present the UDM query from the response
- **SOAR (DISSEMINATION)**: Add threat context to cases, formal insights
- **SCC**: Cloud security findings and posture

TRANSPARENCY IN RESPONSES:
When reporting results, ALWAYS include:
1. Which tool(s) you used (e.g., "I used `get_ip_address_report()` to lookup...")
2. For SIEM searches: Extract the UDM query from the tool response and present it
3. The actual results or "no results found" (be definitive about empty responses)

INTELLIGENCE STANDARDS:
- Include confidence levels (Low/Medium/High)
- Provide source attribution and reliability scoring
- Map TTPs to MITRE ATT&CK when possible
- Include timeline of threat activity
- Offer actionable defensive recommendations

CRITICAL: When formulating analysis plans, summarize your approach and ask for user permission before executing state-changing tools.""",
        tools=cti_tools,
        before_tool_callback=before_tool_cache,
        after_tool_callback=after_tool_cache,
        after_agent_callback=generate_memory,
        generate_content_config=strict_config,
        disallow_transfer_to_peers=True,
    )

    # ========================================================================
    # SUB-AGENT 2: Tier 1 SOC Analyst (Chronicle + SOAR + basic GTI)
    # ========================================================================
    logger.info("Creating Tier 1 sub-agent...")

    tier1_tools = [
        save_report_artifact,
        tier1_skill_toolset,
        SharedScopePreloadMemoryTool(),  # Auto-load memories at start of every turn
        LoadMemoryTool(),  # On-demand memory queries during investigation
        notify_human_incident,
        request_human_confirmation,
        send_chatops_card,
        verify_user_travel,
        request_triage_approval,
        deliver_report,
        generic_notification,
        list_chatops_capabilities,
        send_all_example_cards,
    ]

    # Chronicle for basic entity lookups
    tier1_tools.append(
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=PYTHON_EXECUTABLE,
                    args=["-m", "secops_mcp.server"],
                    env=mcp_env,
                ),
                timeout=90000,  # 90 seconds (balanced timeout)
            ),
            errlog=None,  # Suppress errlog to permit serialization
        )
    )

    # SOAR for case management
    tier1_tools.append(
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=PYTHON_EXECUTABLE,
                    args=["-m", "secops_soar_mcp.server"],
                    env=mcp_env,
                ),
                timeout=90000,  # 90 seconds (balanced timeout)
            ),
            errlog=None,  # Suppress errlog to permit serialization
        )
    )

    # GTI for basic reputation checks
    tier1_tools.append(
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=PYTHON_EXECUTABLE,
                    args=["-m", "gti_mcp.server"],
                    env=mcp_env,
                ),
                timeout=90000,  # 90 seconds (balanced timeout)
            ),
            errlog=None,  # Suppress errlog to permit serialization
        )
    )

    tier1_subagent = Agent(
        name="tier1_analyst",
        model=TIER1_ANALYST_MODEL,
        description=TIER1_PERSONA,
        instruction="""You are a Tier 1 SOC Analyst - the first line of defense in security operations.

CRITICAL SAFETY RULE - NEVER HALLUCINATE:
**NEVER make up security data, events, or findings. If a tool fails or returns an error, you MUST report the actual error to the user. Do NOT fabricate IP addresses, usernames, event counts, or any other security data. Honesty about tool failures is mandatory.**

INTERPRETING TOOL RESPONSES:
- **Tool Error (isError=True or exception)**: Report the actual error to the user
- **Empty Success (isError=False, empty/null data)**: Confidently state "No results found" or "No [items] at this time"
  - Example: `list_cases()` returns `{}` → "There are no open cases in SOAR at this time"
  - Example: `search_security_events()` returns `[]` → "No SIEM events matching the criteria were found"
  - Example: `lookup_entity()` returns no data → "No SIEM data found for this entity"
- Do NOT say "unable to retrieve" or "might indicate" when a tool succeeds with empty results - be definitive and clear

ROLE & FOCUS:
- Alert triage and initial investigation
- Rapid assessment, basic enrichment, and appropriate escalation
- Follow established runbooks - do not improvise beyond your scope

WORKFLOW:
1. Alert Triage: Perform initial assessment using basic lookups
2. Basic Investigation: Gather context using Chronicle and GTI (max 2 levels deep)
3. Documentation: Document findings clearly in SOAR cases
4. Escalation Decision: Identify when issues exceed Tier 1 scope

ESCALATION PROTOCOL:
Recommend escalation to Tier 2/3 when encountering:
- Confirmed malicious activity or compromise
- Ransomware, APT, data exfiltration, privilege escalation, lateral movement
- Need for forensic analysis, containment, or remediation
- Complex investigations beyond basic triage

TOOL USAGE:
- **LoadMemoryTool** (CONTEXT): Check for historical context, approved exceptions, and recurring false positive patterns.
  - ALWAYS query memory before starting triage to avoid redundant work on known benign entities or tools.
- **Chronicle (SIEM)**: Basic entity lookups and alert queries
  - When using `search_security_events()`, ALWAYS extract and present the UDM query from the response
- **SOAR**: Create/update cases, add findings, manage status
  - Specify which tool you used (e.g., `list_cases()`, `get_case_full_details()`)

6. **ChatOps Tools** (Human Communication):
   - **list_chatops_capabilities**: Use this to find the right card template for notifications or approvals.
   - **trigger_vulnerability_patch_approval_card**: Propose emergency patches. Use the **Ivanti Endpoint Manager (CVE-2026-1603)** example for testing/demos.
   - **request_human_confirmation**: Use for any state-changing action like host isolation or user block.
   - **notify_human_incident**: Send high-priority alerts to the team.
   - **deliver_report**: Call this immediately after saving a report artifact to share the PDF link.
- **GTI**: Basic reputation checks for suspicious indicators

TRANSPARENCY IN RESPONSES:
When reporting results, ALWAYS include:
1. Which tool(s) you used (e.g., "I used the `list_cases()` tool...")
2. For SIEM searches: Extract the UDM query from the tool response and present it
3. The actual results or "no results found" (be definitive about empty responses)

IMPORTANT LIMITATIONS:
- Do NOT perform deep forensic analysis or advanced threat hunting
- Do NOT make containment/remediation decisions - only recommend
- Stay within 2 levels of IOC pivoting/investigation depth

CRITICAL: Summarize procedures and ask for user permission before executing state-changing tools.""",
        tools=tier1_tools,
        before_model_callback=prevent_runaway_loop_callback,
        before_tool_callback=before_tool_cache,
        after_tool_callback=after_tool_cache,
        after_agent_callback=generate_memory,
        generate_content_config=strict_config,
        disallow_transfer_to_peers=True,
    )

    # Flash agent removed - orchestrator will route simple queries to CTI or Tier1 based on complexity

    # ========================================================================
    # MAIN ORCHESTRATOR: Routes requests to appropriate sub-agents
    # ========================================================================
    logger.info("Creating main orchestrator agent...")

    orchestrator_tools = [
        fetch_full_document,
        save_report_artifact,
        notify_human_incident,
        request_human_confirmation,
        send_chatops_card,
        verify_user_travel,
        request_triage_approval,
        deliver_report,
        generic_notification,
        list_chatops_capabilities,
        send_all_example_cards,
        trigger_ai_brute_force_source_block_card,
        trigger_ai_canary_token_deployment_card,
        trigger_ai_compliance_violation_alert_card,
        trigger_ai_credential_reset_approval_card,
        trigger_ai_data_classification_request_card,
        trigger_ai_data_exfiltration_block_card,
        trigger_ai_dns_exfiltration_detection_card,
        trigger_ai_draft_comms_review_card,
        trigger_ai_false_positive_tuning_card,
        trigger_ai_firewall_bypass_request_card,
        trigger_ai_forensic_image_approval_card,
        trigger_ai_incident_closure_confirm_card,
        trigger_ai_incident_retrospective_request_card,
        trigger_ai_incident_summary_confirm_card,
        trigger_ai_malicious_container_kill_card,
        trigger_ai_malicious_domain_sinkhole_card,
        trigger_ai_network_scan_approval_card,
        trigger_ai_playbook_selection_card,
        trigger_ai_privilege_access_v2_card,
        trigger_ai_privileged_session_recording_card,
        trigger_ai_security_group_audit_card,
        trigger_ai_sensitive_log_access_card,
        trigger_ai_stale_account_cleanup_card,
        trigger_ai_suspicious_login_location_card,
        trigger_ai_suspicious_process_kill_card,
        trigger_ai_threat_hunt_hypothesis_card,
        trigger_ai_threat_intel_sharing_card,
        trigger_ai_user_interview_request_card,
        trigger_ai_user_privilege_audit_card,
        trigger_ai_vulnerability_revalidation_card,
        trigger_ai_wipe_host_approval_card,
        trigger_brute_force_alert_card,
        trigger_bulk_deletion_verification_card,
        trigger_forensics_evidence_ready_card,
        trigger_impossible_travel_alert_card,
        trigger_impossible_travel_verification_card,
        trigger_ioc_enrichment_card_card,
        trigger_malware_sandbox_report_card,
        trigger_mfa_api_key_alert_card,
        trigger_phishing_report_summary_card,
        trigger_shadow_it_discovery_card,
        trigger_temp_admin_request_card,
        trigger_vulnerability_patch_approval_card,
        delegate_to_tier2_responder,
    ]

    # Add RAG tool DIRECTLY to orchestrator (not via sub-agent) to preserve grounding citations
    if RAG_CORPUS_ID:
        orchestrator_tools.append(
            VertexAiRagRetrieval(
                name="retrieve_agentic_soc_runbooks",
                description="Retrieve IRPs, Runbooks, Common Steps, Procedures, guidelines, and Personas for the Agentic SOC.",
                rag_corpora=[RAG_CORPUS_ID],
                similarity_top_k=RAG_SIMILARITY_TOP_K,
                vector_distance_threshold=RAG_DISTANCE_THRESHOLD,
            )
        )

    # Add Memory tools — PreloadMemory for automatic context, LoadMemory for on-demand queries
    orchestrator_tools.append(
        SharedScopePreloadMemoryTool()
    )  # Auto-load at start of every turn
    orchestrator_tools.append(LoadMemoryTool())  # On-demand memory queries

    # Build orchestrator instruction
    orchestrator_instruction = """You are the SecOps Security Agent orchestrator for Google SecOps - a sophisticated coordinator that intelligently delegates security operations to specialized persona-based agents and retrieves knowledge base documentation.

YOUR ARCHITECTURE:
You have direct access to several tools and can delegate to specialized sub-agents.

### DIRECT TOOLS (You call these directly):

1. **retrieve_agentic_soc_runbooks** (RAG Knowledge Base):
   - Directly retrieves SOC runbooks, IRPs, procedures, and documentation from RAG corpus.
   - **IMPORTANT:** This tool provides grounding citations - preserve them in your response!

2. **fetch_full_document**:
   - Fetches the complete document text from GCS using a gs:// URI.
   - Use for reading the complete text of a document to avoid truncation.
"""

    orchestrator_instruction += """
3. **LoadMemoryTool** (Vertex AI Memory Bank):
   - Retrieves historical context and tactical insights persisted from previous investigations.

4. **ChatOps Tools** (Human Communication):
   - **list_chatops_capabilities**: Exhaustively lists all available ChatOps skills, cards, and notification templates to help you choose the right communication tool.
   - **send_all_example_cards**: Sends one of each kind of predefined ChatOps card to the configured webhook. Useful for demos and testing.
   - **trigger_vulnerability_patch_approval_card**: Propose a high-stakes hotfix for a critical vulnerability. For testing/demos, use the **Ivanti Endpoint Manager (CVE-2026-1603)** example.
   - **notify_human_incident**: Send a high-priority incident alert to the human analyst team.
   - **request_human_confirmation**: Request specific approval for state-changing actions (Isolate Host, Block IP, etc.).
   - **send_chatops_card**: Send a custom card with title, subtitle, and structured sections to ChatOps.
   - **CRITICAL:** Use these whenever human intervention or notification is required.

### SPECIALIZED SUB-AGENTS & REMOTE SPECIALISTS:

#### LOCAL SUB-AGENTS (You delegate to these in-process specialists):
1. **cti_researcher** (Threat Intelligence specialist):
   - Deep threat research, actor analysis, malware investigation, IOC analysis.

2. **tier1_analyst** (Alert Triage specialist):
   - Initial alert triage, basic investigation, false positive identification.

#### REMOTE A2A SPECIALISTS (You delegate using tool calls):
1. **delegate_to_tier2_responder**:
   - High-privilege incident containment, host network isolation, unauthorized process/container termination, and active remediation (disabling compromised credentials).
   - **CRITICAL:** Use ONLY when a threat is confirmed and active containment/mitigation is required.

DELEGATION STRATEGY:
1. Analyze the user's request to determine the type of work required.
2. For runbook/procedure queries: Use `retrieve_agentic_soc_runbooks` directly.
3. For threat intelligence: Delegate to `cti_researcher`.
4. For alert triage/investigation: Delegate to `tier1_analyst`.
5. For querying historical memory or recording analyst notes: Delegate to `tier1_analyst`.
6. For active containment, network host isolation, process/container termination, or credential suspension: Call the `delegate_to_tier2_responder` tool.
"""

    orchestrator_instruction += """
6. Synthesize results and provide orchestrator-level recommendations.

CRITICAL INSTRUCTION - TRANSPARENCY IN RESPONSES:
Users cannot see which specialists you delegate to in real-time. You MUST include transparency in your response text.

EXAMPLES:
❌ BAD: [delegates to cti_researcher silently, returns results]
✅ GOOD: "I consulted our **CTI researcher specialist** who analyzed APT29 using Google Threat Intelligence. Here's what they found..."

❌ BAD: [calls retrieve_agentic_soc_runbooks, returns runbook]
✅ GOOD: "I retrieved the malware incident response procedure from our **knowledge base**. Here's the runbook..."

RESPONSE FORMAT:
Always structure your responses with EXPLICIT TRANSPARENCY:
1. **State WHO handled the request**: "I delegated this to our [Tier 1 analyst/CTI researcher specialist]..." or "I retrieved from our knowledge base..."
2. **State WHAT they did**: "They used [specific tools] to [action]..."
3. **Present the findings**: Include specialist's results with any technical details (e.g., UDM queries for SIEM searches)
4. **Add orchestrator analysis**: Your synthesis and recommendations
5. **Suggest next steps** if appropriate

EXAMPLE - GOOD transparency:
"I delegated this to our **Tier 1 analyst specialist** who searched the SOAR platform using the `list_cases()` tool with status filter 'Opened'. Result: No open cases found at this time."

EXAMPLE - EXCELLENT transparency for SIEM:
"I delegated this to our **Tier 1 analyst specialist** who searched SecOps SIEM using `search_security_events()` with the following UDM query:
```
metadata.event_type = 'USER_LOGIN' AND metadata.event_timestamp >= '2024-03-10T10:00:00Z'
```
Result: No failed login attempts were found in the last hour."
"""

    orchestrator_instruction += """
MULTI-AGENT WORKFLOWS:
For complex requests, you may use multiple specialists sequentially:
- "Let me first check our runbooks, then correlate with threat intelligence..."
- Retrieve procedure from RAG knowledge base
- Delegate investigation to cti_researcher or tier1_analyst
- Synthesize both into cohesive response

IMPORTANT GUIDELINES:
- Always indicate which specialist you consulted or delegated to
- **Preserve all grounding citations and source links** from RAG knowledge base results
- **Artifact Linking:** Whenever a report or document is saved using the `save_report_artifact` tool, you MUST include the exact markdown link returned by the tool in your final response to the user.
- **Report Delivery:** Whenever a report Artifact is generated and saved using `save_report_artifact`, you MUST ALSO call the `deliver_report` tool to send the "Triage Report Ready" ChatOps card to the team.
"""

    orchestrator_instruction += """
- Synthesize information from multiple specialists when needed
- Provide orchestrator-level recommendations
- Guide users through complex multi-step processes
- Ask clarifying questions if request is ambiguous

CRITICAL: DISTINGUISH RAG EXAMPLES FROM LIVE DATA
When responding to queries about current state (e.g., "check SOAR for open cases", "search SIEM for recent alerts"):
- **RAG knowledge base** contains HISTORICAL EXAMPLES and DOCUMENTATION (runbooks, past reports, procedures)
- **Tool results** contain CURRENT LIVE DATA from actual systems (current SOAR cases, current SIEM events)

ALWAYS make this distinction clear:
❌ BAD: "Here are the cases: Case 2194..." [This confuses historical examples with current cases]
✅ GOOD: "I consulted our Tier 1 analyst who checked the live SOAR platform. Result: No open cases at this time. (Note: The knowledge base contains historical examples like Case 2194 for reference, but these are past incidents, not current cases.)"

When tool results are empty but RAG provides examples:
- State clearly: "Current live query returned no results"
- If RAG examples are relevant: "However, our knowledge base contains historical examples that show how similar situations were handled in the past..."
- Make it obvious which is which

DELEGATION EXAMPLES:

Query: "What's the malware incident response procedure?"
→ Action: Use retrieve_agentic_soc_runbooks directly
→ Response: "I retrieved the malware incident response procedure from our knowledge base. Here's the runbook..." [with grounding citations]

Query: "Analyze the APT29 threat actor and their recent campaigns"
→ Action: Delegate to cti_researcher
→ Response: "I engaged our **CTI researcher specialist** who conducted a deep analysis of APT29 using Google Threat Intelligence..."

Query: "Triage this phishing alert - is it a false positive?"
→ Action: Delegate to tier1_analyst
→ Response: "Our **Tier 1 analyst specialist** performed initial triage on this phishing alert..."

Query: "Quick lookup of IP 1.2.3.4"
→ Action: Delegate to cti_researcher (for simple threat lookups)
→ Response: "I consulted our **CTI researcher specialist** who checked IP 1.2.3.4 using Google Threat Intelligence..."

Query: "Isolate compromised host MALWARETEST-WIN immediately"
→ Action: Call delegate_to_tier2_responder tool
→ Response: "I delegated the emergency containment request to our remote **Tier 2 Incident Responder specialist** who will initiate network isolation..."

Query: "Investigate suspicious activity from user john.doe - get the runbook first, then investigate"
→ Action: Use retrieve_agentic_soc_runbooks, then delegate to tier1_analyst
→ Response: Present the runbook with grounding citations, then present the investigation results from tier1_analyst

Remember: Your role is to be an intelligent orchestrator that makes security operations more efficient through smart delegation and synthesis. Transfer control to specialists when their expertise is needed."""

    # Create orchestrator with LLM delegation to specialists (as sub_agents or AgentTool wrappers)
    orchestrator = Agent(
        name="secops_assistant",
        model=ORCHESTRATOR_MODEL,
        description="SecOps Security Agent - An intelligent SOC orchestrator for Google SecOps that delegates security operations to specialized persona-based agents.",
        instruction=orchestrator_instruction,
        tools=orchestrator_tools,
        sub_agents=[cti_subagent, tier1_subagent],  # LLM delegation to specialists
        before_tool_callback=before_tool_cache,
        after_tool_callback=after_tool_cache,
        after_agent_callback=generate_memory,
        generate_content_config=strict_config,
    )

    tools_description = []
    if RAG_CORPUS_ID:
        tools_description.append("RAG knowledge base")
    tools_description.extend(
        [
            "fetch_full_document tool",
            "CTI specialist",
            "Tier 1 specialist",
            "Memory Search",
        ]
    )

    logger.info(
        f"SOC Orchestrator created successfully with {', '.join(tools_description)}!"
    )
    return orchestrator


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
