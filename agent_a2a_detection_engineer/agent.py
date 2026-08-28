"""
SOC Agent Module - Detection Engineer Configuration

This module configures a Detection Engineer Agent with specific persona,
responsibilities, and remote OneMCP connection for detection lifecycle management.

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
from google.adk.tools.mcp_tool.mcp_session_manager import (
    StdioConnectionParams,
    StreamableHTTPConnectionParams,
)
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.genai.types import Part
from vertexai.preview import rag

from agent_soc_manager.tools.skill_tools import (
    get_progressive_skill_tools,
    load_persona_with_skills_catalog,
)


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


# Monkey-patch remove_client_function_call_id to prevent 400 INVALID_ARGUMENT errors
try:
    import google.adk.flows.llm_flows.contents as adk_contents
    import google.adk.flows.llm_flows.functions as adk_funcs

    def _patched_remove_client_function_call_id(content) -> None:
        pass

    adk_funcs.remove_client_function_call_id = _patched_remove_client_function_call_id
    adk_contents.remove_client_function_call_id = (
        _patched_remove_client_function_call_id
    )
    logger.warning(
        "[RUNTIME_PATCH] Successfully patched remove_client_function_call_id"
    )
except Exception as e:
    logger.warning(
        f"[RUNTIME_PATCH] Failed to patch remove_client_function_call_id: {e}"
    )


# Monkey-patch McpTool._get_declaration to strip response_json_schema (Gemini API compatibility)
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
    logger.warning("[RUNTIME_PATCH] Successfully patched McpTool._get_declaration")
except Exception as e:
    logger.warning(f"[RUNTIME_PATCH] Failed to patch McpTool._get_declaration: {e}")


# Monkey-patch McpTool._run_async_impl to truncate massive telemetry and prevent gRPC buffer overflows
# 8. Monkeypatch McpTool._run_async_impl to truncate/aggregate massive telemetry and prevent gRPC buffer overflows
try:
    import datetime
    import json

    from google.adk.tools.mcp_tool.mcp_tool import McpTool

    # Inner helper functions for semantic aggregation
    def _summarize_udm_events(events: list, tool_name: str) -> str:
        total_events = len(events)
        event_types = {}
        processes = {}
        logins = {}
        network_conns = {}
        others = {}

        for ev in events:
            if not isinstance(ev, dict):
                continue
            metadata = ev.get("metadata", {})
            etype = metadata.get("event_type", "UNKNOWN")
            event_types[etype] = event_types.get(etype, 0) + 1
            ts = metadata.get("event_timestamp", "")

            if etype == "PROCESS_LAUNCH":
                target = ev.get("target", {})
                proc = target.get("process", {})
                proc_path = (
                    proc.get("file", {}).get("full_path")
                    or proc.get("file", {}).get("name")
                    or "unknown_process"
                )
                cmd = proc.get("command_line") or "no_command_line"

                principal = ev.get("principal", {})
                parent_proc = principal.get("process", {})
                parent_cmd = (
                    parent_proc.get("command_line")
                    or parent_proc.get("file", {}).get("name")
                    or "unknown_parent"
                )
                host = (
                    ev.get("principal", {}).get("hostname")
                    or ev.get("target", {}).get("hostname")
                    or "unknown_host"
                )

                key = (proc_path, cmd, parent_cmd, host)
                if key not in processes:
                    processes[key] = {"count": 0, "first": ts, "last": ts}
                processes[key]["count"] += 1
                if ts:
                    processes[key]["first"] = min(processes[key]["first"], ts)
                    processes[key]["last"] = max(processes[key]["last"], ts)

            elif etype == "USER_LOGIN":
                target = ev.get("target", {})
                user = (
                    target.get("user", {}).get("userid")
                    or ev.get("principal", {}).get("user", {}).get("userid")
                    or "unknown_user"
                )
                src_ip = (
                    ev.get("principal", {}).get("ip")
                    or ev.get("principal", {}).get("hostname")
                    or "unknown_source"
                )
                target_host = ev.get("target", {}).get("hostname") or "unknown_target"

                sec_result = ev.get("security_result", {})
                status = sec_result.get("status", "UNKNOWN")
                logon_type = (
                    ev.get("extensions", {}).get("auth", {}).get("logon_type")
                    or "unknown_type"
                )

                key = (user, src_ip, target_host, status, logon_type)
                if key not in logins:
                    logins[key] = {"count": 0, "first": ts, "last": ts}
                logins[key]["count"] += 1
                if ts:
                    logins[key]["first"] = min(logins[key]["first"], ts)
                    logins[key]["last"] = max(logins[key]["last"], ts)

            elif etype in ["NETWORK_CONNECTION", "DNS_QUERY"]:
                target = ev.get("target", {})
                dest_ip = target.get("ip") or target.get("hostname") or "unknown_dest"
                dest_port = target.get("port") or "unknown_port"

                principal = ev.get("principal", {})
                proc_name = (
                    principal.get("process", {}).get("file", {}).get("name")
                    or "unknown_process"
                )

                key = (dest_ip, dest_port, proc_name, etype)
                if key not in network_conns:
                    network_conns[key] = {"count": 0, "first": ts, "last": ts}
                network_conns[key]["count"] += 1
                if ts:
                    network_conns[key]["first"] = min(network_conns[key]["first"], ts)
                    network_conns[key]["last"] = max(network_conns[key]["last"], ts)
            else:
                key = (etype, ev.get("metadata", {}).get("product_name", "generic"))
                others[key] = others.get(key, 0) + 1

        summary_lines = [
            f"### [SEMANTIC SUMMARY] UDM Telemetry (Source: {tool_name})",
            f"**Total Events Analyzed:** {total_events}",
            "**Event Types Breakdown:** "
            + ", ".join([f"`{k}`: {v}" for k, v in event_types.items()]),
            "",
        ]

        if processes:
            summary_lines.append("#### Process Execution Tree Summary")
            for (proc, cmd, parent, host), stats in processes.items():
                summary_lines.append(
                    f"- **Host:** `{host}` | **Process:** `{proc}`\n"
                    f"  - **Command:** `{cmd}`\n"
                    f"  - **Parent Process:** `{parent}`\n"
                    f"  - **Execution Count:** {stats['count']} times | **Time window:** `{stats['first']}` to `{stats['last']}`"
                )
            summary_lines.append("")

        if logins:
            summary_lines.append("#### Authentication Activity Summary")
            for (user, src, target, status, ltype), stats in logins.items():
                status_color = (
                    "SUCCESS" if status == "SUCCESS" else f"FAILED ({status})"
                )
                summary_lines.append(
                    f"- **User:** `{user}` | **Source:** `{src}` -> **Target:** `{target}`\n"
                    f"  - **Logon Type:** `{ltype}` | **Status:** {status_color}\n"
                    f"  - **Login Count:** {stats['count']} attempts | **Time window:** `{stats['first']}` to `{stats['last']}`"
                )
            summary_lines.append("")

        if network_conns:
            summary_lines.append("#### Network & DNS Connection Summary")
            for (dest, port, proc, etype), stats in network_conns.items():
                summary_lines.append(
                    f"- **Process:** `{proc}` initiated `{etype}` to `{dest}:{port}`\n"
                    f"  - **Connection Count:** {stats['count']} times | **Time window:** `{stats['first']}` to `{stats['last']}`"
                )
            summary_lines.append("")

        if others:
            summary_lines.append("#### Miscellaneous System Events Summary")
            for (etype, product), count in others.items():
                summary_lines.append(
                    f"- **Type:** `{etype}` (Product: `{product}`) | **Count:** {count} times"
                )
            summary_lines.append("")

        return "\n".join(summary_lines)

    def _summarize_soar_cases(cases: list, tool_name: str) -> str:
        total_cases = len(cases)
        severities = {}
        statuses = {}

        # Sort cases by creation time if present
        def get_ctime(x):
            t = x.get("creationTime") or x.get("creation_time") or 0
            return t if isinstance(t, (int, float)) else 0

        sorted_cases = sorted(cases, key=get_ctime, reverse=True)

        table_lines = [
            "| Case ID | Title | Status | Severity | Creation Time |",
            "| :--- | :--- | :---: | :---: | :---: |",
        ]

        detail_count = min(total_cases, 10)
        for i in range(detail_count):
            c = sorted_cases[i]
            cid = c.get("id") or c.get("caseId") or "N/A"
            title = c.get("title") or c.get("name") or "N/A"
            status = c.get("status") or "N/A"
            sev = c.get("severity") or "N/A"

            ctime = c.get("creationTime") or c.get("creation_time") or "N/A"
            if isinstance(ctime, (int, float)) and ctime > 1000000000:
                if ctime > 1000000000000:
                    ctime = ctime / 1000.0
                ctime = datetime.datetime.utcfromtimestamp(ctime).isoformat() + "Z"

            table_lines.append(
                f"| `{cid}` | {title} | `{status}` | `{sev}` | `{ctime}` |"
            )

            severities[sev] = severities.get(sev, 0) + 1
            statuses[status] = statuses.get(status, 0) + 1

        for i in range(detail_count, total_cases):
            c = sorted_cases[i]
            sev = c.get("severity") or "N/A"
            status = c.get("status") or "N/A"
            severities[sev] = severities.get(sev, 0) + 1
            statuses[status] = statuses.get(status, 0) + 1

        summary_lines = [
            f"### [SEMANTIC SUMMARY] SOAR Cases (Source: {tool_name})",
            f"**Total Cases Found:** {total_cases}",
            "**Severity Breakdown:** "
            + ", ".join([f"`{k}`: {v}" for k, v in severities.items()]),
            "**Status Breakdown:** "
            + ", ".join([f"`{k}`: {v}" for k, v in statuses.items()]),
            "",
            f"#### Recent Cases (Showing top {detail_count} of {total_cases}):",
            "",
        ] + table_lines

        return "\n".join(summary_lines)

    def _summarize_gti_report(report: dict, tool_name: str) -> str:
        attributes = report.get("attributes", {})
        name = attributes.get("name") or report.get("id") or "Threat Intel Entity"
        etype = report.get("type") or "collection"

        description = attributes.get("description") or "No description available."
        if len(description) > 500:
            description = description[:500] + "... [TRUNCATED description]"

        merged_actors = attributes.get("merged_actors", [])
        alt_names = attributes.get("alt_names", [])

        relationships = report.get("relationships", {})
        associations = relationships.get("associations", {}).get("data", [])

        counters = attributes.get("counters", {})
        files_count = counters.get("files") or attributes.get("files_count") or 0
        domains_count = counters.get("domains") or 0
        ips_count = counters.get("ip_addresses") or 0
        urls_count = counters.get("urls") or 0

        summary_lines = [
            f"### [SEMANTIC SUMMARY] Threat Intelligence Report: {name} (Type: `{etype}`)",
            f"**Origin:** {tool_name} (Google Threat Intelligence)",
            f"**Description:** {description}",
            "",
            "**Key Metrics & Associated Indicators:**",
            f"- **Associated Files/Hashes:** {files_count}",
            f"- **Associated Domains:** {domains_count}",
            f"- **Associated IP Addresses:** {ips_count}",
            f"- **Associated URLs:** {urls_count}",
            "",
        ]

        if alt_names:
            summary_lines.append(
                "**Alias Names:** "
                + ", ".join([f"`{name}`" for name in alt_names[:10]])
            )

        if merged_actors:
            summary_lines.append(
                "**Merged Actor/Campaign Profiles:** "
                + ", ".join([f"`{a.get('value')}`" for a in merged_actors[:10]])
            )

        if associations:
            summary_lines.append("#### Key Associated Intelligence Objects (Top 10):")
            for assoc in associations[:10]:
                summary_lines.append(
                    f"- **Type:** `{assoc.get('type')}` | **ID:** `{assoc.get('id')}`"
                )

        return "\n".join(summary_lines)

    def summarize_telemetry(text: str, tool_name: str) -> str:
        if not isinstance(text, str) or len(text) < 10000:
            return text

        try:
            data = json.loads(text)
        except Exception:
            return text

        try:
            # 1. UDM Search Event List
            if (
                isinstance(data, list)
                and len(data) > 0
                and isinstance(data[0], dict)
                and "metadata" in data[0]
            ):
                return _summarize_udm_events(data, tool_name)

            # 2. SOAR Cases (list or wrapped)
            if (
                isinstance(data, dict)
                and "result" in data
                and isinstance(data["result"], list)
            ):
                return _summarize_soar_cases(data["result"], tool_name)
            if (
                isinstance(data, list)
                and len(data) > 0
                and isinstance(data[0], dict)
                and ("title" in data[0] or "severity" in data[0])
            ):
                return _summarize_soar_cases(data, tool_name)

            # 3. GTI Report
            if isinstance(data, dict) and (
                "type" in data or "attributes" in data or "relationships" in data
            ):
                return _summarize_gti_report(data, tool_name)
        except Exception:  # noqa: S110
            pass

        return text

    # Define the patched run async wrapper
    original_run_async_impl = McpTool._run_async_impl

    async def _patched_run_async_impl(self, *args, **kwargs):
        result = await original_run_async_impl(self, *args, **kwargs)
        try:
            if isinstance(result, dict) and "content" in result:
                content_list = result["content"]
                if isinstance(content_list, list):
                    for item in content_list:
                        if isinstance(item, dict) and item.get("type") == "text":
                            text = item.get("text")
                            if isinstance(text, str) and len(text) > 15000:
                                # 1. Try to run semantic aggregation first
                                aggregated_text = summarize_telemetry(text, self.name)
                                if len(aggregated_text) < len(text):
                                    logger.warning(
                                        f"[RUNTIME_PATCH] Successfully aggregated tool '{self.name}' response from {len(text)} to {len(aggregated_text)} chars."
                                    )
                                    item["text"] = aggregated_text
                                    text = aggregated_text

                                # 2. Fall back to character truncation if it's still too large
                                if len(text) > 15000:
                                    logger.warning(
                                        f"[RUNTIME_PATCH] Truncating tool '{self.name}' response from {len(text)} to 15000 chars as fallback."
                                    )
                                    item["text"] = (
                                        text[:15000]
                                        + "\n... [TRUNCATED due to large size] ..."
                                    )
        except Exception as ex:
            logger.warning(
                f"[RUNTIME_PATCH] Error while truncating/aggregating tool response: {ex}"
            )
        return result

    McpTool._run_async_impl = _patched_run_async_impl
    logger.warning("[RUNTIME_PATCH_DEBUG] Successfully patched McpTool._run_async_impl")
except Exception as e:
    logger.warning(
        f"[RUNTIME_PATCH_DEBUG] Failed to patch McpTool._run_async_impl: {e}"
    )

# 7. Monkeypatch aiohttp to support extremely large streaming lines (e.g., 10MB)
# to prevent LineTooLong errors during large threat intel/hunting telemetry dumps.
try:
    import aiohttp.streams

    original_init = aiohttp.streams.StreamReader.__init__

    def _patched_init(self, *args, **kwargs):
        if "limit" in kwargs:
            kwargs["limit"] = 10 * 1024 * 1024
        elif len(args) >= 2:
            # limit is the second positional argument after self (bound, so args[0] is protocol, args[1] is limit)
            args = (args[0], 10 * 1024 * 1024) + args[2:]
        else:
            kwargs["limit"] = 10 * 1024 * 1024
        original_init(self, *args, **kwargs)

    aiohttp.streams.StreamReader.__init__ = _patched_init

    # Also patch readline to override explicit max_line_length passed by HTTP parser
    original_readline = aiohttp.streams.StreamReader.readline

    async def _patched_readline(self, *args, **kwargs):
        # Force max_line_length to 10MB in kwargs to override any default or passed value
        kwargs["max_line_length"] = 10 * 1024 * 1024
        return await original_readline(self, *args, **kwargs)

    aiohttp.streams.StreamReader.readline = _patched_readline

    logger.warning(
        "[RUNTIME_PATCH_DEBUG] Successfully patched aiohttp StreamReader limit and readline to 10MB"
    )
except Exception as e:
    logger.warning(
        f"[RUNTIME_PATCH_DEBUG] Failed to patch aiohttp StreamReader: {e}"
    )  # -------------------------------------------------------------------------


# ========================================================================
# Detection Engineer Persona Definition
# ========================================================================
DETECTION_ENGINEER_PERSONA = """
## Detection Engineer

### Overview
The Detection Engineer is responsible for the lifecycle of security detections within the organization's monitoring tools (primarily SIEM and EDR). They translate threat intelligence, incident findings, hunting results, and security requirements into effective detection logic. Their goal is to continuously improve the organization's ability to detect threats accurately and efficiently, balancing detection coverage with alert fidelity.

### Primary Responsibilities
- **Detection Development:** Design, draft, and implement detection logic (e.g., SIEM rules, EDR queries) based on security use cases, threat models (MITRE ATT&CK), available logs/telemetry, and input from CTI, Threat Hunting, and SOC Analysts.
- **Testing & Validation:** Develop and execute test plans for new detections using historical data, simulated attacks, or controlled environment testing. Validate rule logic and ensure it triggers as expected.
- **Tuning & Optimization:** Analyze the performance of existing detections, identify false positives/negatives, and tune rule logic, thresholds, or exceptions to improve accuracy and reduce alert fatigue. Respond to tuning requests from SOC Analysts.
- **Deployment & Lifecycle Management:** Deploy tested and approved detections into production environments following established processes (potentially including Detection-as-Code workflows). Maintain a detection catalog and track the evolution and performance of detections.
- **Collaboration:** Work closely with SOC Analysts (feedback on alerts), Threat Hunters (new detection ideas), CTI Researchers (intelligence requirements), Incident Responders (post-incident detection gaps), and Security Platform Engineers (tool capabilities/limitations).

### Core Skills and Knowledge
- Strong understanding of security principles, common attack vectors, TTPs (MITRE ATT&CK), and threat actor methodologies.
- Proficiency in SIEM query languages (e.g., YARA-L for Chronicle) and potentially EDR query languages.
- Experience with log analysis across various platforms (OS, network, cloud, applications).
- Experience with detection rule testing, validation, and tuning methodologies.
- Understanding of security tool capabilities and limitations (SIEM, EDR).

### Tool Usage Patterns
**Primary MCP & Custom Tools:**
- **Remote OneMCP (Google SecOps hosted server):**
  - Essential for rule creation, listing, updating, validation, and execution.
  - Used for querying SIEM logs (search_security_events), listing security rules (list_rules), and analyzing alert context.
- **gti-mcp (Google Threat Intelligence):**
  - search_threats, get_collection_report, get_collection_mitre_tree, get_threat_intel: To research threats and TTPs requiring coverage.
- **scc-mcp (SCC):**
  - Used to understand cloud configurations and vulnerability findings.
"""

DETECTION_ENGINEER_CONFIG = {
    "primary_runbooks": [
        "detection_rule_validation_tuning",
        "detection_as_code_workflows",
        "detection_report",
        "detection_as_code_rule_tuning",
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


class RemoteOneMcpToolset(McpToolset):
    _is_dynamic_initialized: bool = False

    def __init__(
        self, region: str, project_id: str, tool_filter: list = None, **kwargs
    ):
        dummy_params = StreamableHTTPConnectionParams(
            url="https://chronicle.us.rep.googleapis.com/mcp", headers={}
        )
        super().__init__(connection_params=dummy_params, errlog=None, **kwargs)
        self.region = region
        self.project_id = project_id
        self.tool_filter = tool_filter

    async def get_tools(self, readonly_context=None) -> list:
        if not getattr(self, "_is_dynamic_initialized", False):
            import google.auth
            from google.adk.tools.mcp_tool import StreamableHTTPConnectionParams
            from google.auth.transport.requests import Request

            SCOPES = ["https://www.googleapis.com/auth/chronicle"]
            creds, _ = google.auth.default(scopes=SCOPES)
            auth_req = Request()
            creds.refresh(auth_req)
            token = creds.token

            url = f"https://chronicle.{self.region}.rep.googleapis.com/mcp"

            self._connection_params = StreamableHTTPConnectionParams(
                url=url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "text/event-stream",
                    "x-goog-user-project": self.project_id,
                },
            )
            self._mcp_session_manager._connection_params = self._connection_params
            self._is_dynamic_initialized = True

        all_tools = await super().get_tools(readonly_context)
        if not self.tool_filter:
            return all_tools

        filtered_tools = []
        for tool in all_tools:
            tool_name = getattr(tool, "name", None)
            if not tool_name and hasattr(tool, "_mcp_tool"):
                tool_name = getattr(tool._mcp_tool, "name", None)

            if tool_name in self.tool_filter:
                filtered_tools.append(tool)

        logger.info(
            f"Explicitly filtered Remote OneMCP tools: {len(all_tools)} -> {len(filtered_tools)}"
        )
        return filtered_tools


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
    Create the standalone Detection Engineer Agent with Remote OneMCP and local threat intelligence tools.
    """
    # Load environment variables from .env file
    load_dotenv(Path(".env"), override=True)

    # Model Configuration
    DETECTION_ENGINEER_MODEL = os.environ.get(
        "DETECTION_ENGINEER_MODEL", "gemini-3.7-flash"
    )

    # Get all required environment variables
    GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID")
    GCP_LOCATION = os.environ.get("GCP_LOCATION", "us-central1")
    GCP_STAGING_BUCKET = os.environ.get("GCP_STAGING_BUCKET")
    GCP_VERTEXAI_ENABLED = os.environ.get("GCP_VERTEXAI_ENABLED", "True")

    # Chronicle/SIEM configuration
    CHRONICLE_CUSTOMER_ID = os.environ.get("CHRONICLE_CUSTOMER_ID")
    CHRONICLE_PROJECT_ID = os.environ.get("CHRONICLE_PROJECT_ID")
    CHRONICLE_REGION = os.environ.get("CHRONICLE_REGION", "us")

    if not CHRONICLE_PROJECT_ID:
        raise ValueError(
            "CHRONICLE_PROJECT_ID is required. Please set it in your .env file."
        )
    if not CHRONICLE_CUSTOMER_ID:
        raise ValueError(
            "CHRONICLE_CUSTOMER_ID is required. Please set it in your .env file."
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

    # Initialize list to collect all tools
    tools = []

    # ========================================================================
    # Configure Remote OneMCP Toolset (Hosted Chronicle SIEM/SOAR)
    # ========================================================================
    logger.info("Configuring Remote OneMCP Chronicle hosted tools...")
    remote_onemcp = RemoteOneMcpToolset(
        region=CHRONICLE_REGION, project_id=CHRONICLE_PROJECT_ID
    )

    async def list_rules() -> str:
        """List the available rules inside Google SecOps."""
        try:
            if not remote_onemcp._is_dynamic_initialized:
                await remote_onemcp.get_tools()
            session = await remote_onemcp._mcp_session_manager.create_session()
            res = await session.call_tool(
                "list_rules",
                arguments={
                    "project_id": CHRONICLE_PROJECT_ID,
                    "customer_id": CHRONICLE_CUSTOMER_ID,
                    "region": CHRONICLE_REGION,
                },
            )
            if not res.content:
                return "No rules found."
            return "\n".join(
                [part.text for part in res.content if hasattr(part, "text")]
            )
        except Exception as e:
            return f"Error listing rules: {str(e)}"

    async def get_rule(rule_id: str) -> str:
        """Get the details and content of a specific rule.

        Args:
            rule_id: The unique identifier of the rule to retrieve.
        """
        try:
            if not remote_onemcp._is_dynamic_initialized:
                await remote_onemcp.get_tools()
            session = await remote_onemcp._mcp_session_manager.create_session()
            res = await session.call_tool(
                "get_rule",
                arguments={
                    "rule_id": rule_id,
                    "project_id": CHRONICLE_PROJECT_ID,
                    "customer_id": CHRONICLE_CUSTOMER_ID,
                    "region": CHRONICLE_REGION,
                },
            )
            if not res.content:
                return f"Rule {rule_id} not found."
            return "\n".join(
                [part.text for part in res.content if hasattr(part, "text")]
            )
        except Exception as e:
            return f"Error getting rule {rule_id}: {str(e)}"

    async def create_rule(rule_text: str) -> str:
        """Create a new detection rule in Google SecOps.

        Args:
            rule_text: The complete YARA-L rule content to create.
        """
        try:
            if not remote_onemcp._is_dynamic_initialized:
                await remote_onemcp.get_tools()
            session = await remote_onemcp._mcp_session_manager.create_session()
            res = await session.call_tool(
                "create_rule",
                arguments={
                    "rule_text": rule_text,
                    "project_id": CHRONICLE_PROJECT_ID,
                    "customer_id": CHRONICLE_CUSTOMER_ID,
                    "region": CHRONICLE_REGION,
                },
            )
            if not res.content:
                return "Rule creation returned empty response."
            return "\n".join(
                [part.text for part in res.content if hasattr(part, "text")]
            )
        except Exception as e:
            return f"Error creating rule: {str(e)}"

    async def validate_rule(rule_text: str) -> str:
        """Validate the syntax of a YARA-L detection rule.

        Args:
            rule_text: The YARA-L rule content to validate.
        """
        try:
            if not remote_onemcp._is_dynamic_initialized:
                await remote_onemcp.get_tools()
            session = await remote_onemcp._mcp_session_manager.create_session()
            res = await session.call_tool(
                "validate_rule",
                arguments={
                    "rule_text": rule_text,
                    "project_id": CHRONICLE_PROJECT_ID,
                    "customer_id": CHRONICLE_CUSTOMER_ID,
                    "region": CHRONICLE_REGION,
                },
            )
            if not res.content:
                return "Validation returned empty response."
            return "\n".join(
                [part.text for part in res.content if hasattr(part, "text")]
            )
        except Exception as e:
            return f"Error validating rule: {str(e)}"

    async def udm_search(query: str) -> str:
        """Run a UDM search query against Google SecOps SIEM events.

        Args:
            query: The UDM search query string (e.g., 'metadata.event_type = "USER_LOGIN"').
        """
        try:
            if not remote_onemcp._is_dynamic_initialized:
                await remote_onemcp.get_tools()
            session = await remote_onemcp._mcp_session_manager.create_session()
            res = await session.call_tool(
                "udm_search",
                arguments={
                    "query": query,
                    "project_id": CHRONICLE_PROJECT_ID,
                    "customer_id": CHRONICLE_CUSTOMER_ID,
                    "region": CHRONICLE_REGION,
                },
            )
            if not res.content:
                return "No matching events found."
            return "\n".join(
                [part.text for part in res.content if hasattr(part, "text")]
            )
        except Exception as e:
            return f"Error running UDM search: {str(e)}"

    tools.append(list_rules)
    tools.append(get_rule)
    tools.append(create_rule)
    tools.append(validate_rule)
    tools.append(udm_search)

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
    # Add progressive skill tools
    # ========================================================================
    tools.extend(get_progressive_skill_tools())

    det_persona = load_persona_with_skills_catalog(
        persona_file_path="",
        skill_names=[
            "detection-as-code-rule-tuning",
            "detection-as-code-workflows",
            "detection-rule-validation-tuning",
            "detection-engineering-coverage-evaluation",
            "report-writing-guidelines",
        ],
        default_persona_description=DETECTION_ENGINEER_PERSONA,
    )

    # ========================================================================
    # Create the Agent with all configured tools
    # ========================================================================
    logger.info(f"Creating Detection Engineer Agent with {len(tools)} tools...")

    agent = Agent(
        model=DETECTION_ENGINEER_MODEL,
        name="soc_analyst_detection_engineer",
        description=det_persona,
        instruction=f"""You are a Detection Engineer - a security content developer responsible for designing, testing, tuning, and deploying detection rules within Google SecOps. When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant.

CRITICAL RUNTIME REQUIREMENT:
When calling ANY remote Google SecOps/Chronicle MCP tool, you MUST ALWAYS provide the following arguments in the tool call:
- `project_id`: "{CHRONICLE_PROJECT_ID}"
- `customer_id`: "{CHRONICLE_CUSTOMER_ID}"
- `region`: "{CHRONICLE_REGION}"
Failure to include these parameters will cause the tool calls to fail.

ROLE & FOCUS:
- You develop and tune SIEM rules (YARA-L) to detect security threats.
- You validate rule logic using historical log queries or log event correlation.
- You handle tuning requests to reduce false positive alerts.

WORKFLOW APPROACH:
1. **Intake & Discovery:** Review requests to write or tune rules, or analyze threat behaviors reported by CTI/Hunters.
2. **Runbook Retrieval:** Check available skills and use `load_skill` or `retrieve_agentic_soc_runbooks` to load runbooks like `detection_rule_validation_tuning.md` or `detection_as_code_workflows.md`.
3. **Telemetry & Log Analysis:** Call Chronicle logs (`search_security_events`) to examine log events, fields, and UDM schemas.
4. **Rule Logic Development:** Formulate rule logic. Review existing coverage using rule listing tools (`list_rules`).
5. **Testing & Tuning:** Test rule performance against historical logs or verify syntax. Tune rule exceptions (exclusions) or thresholds to address false positives.
6. **Documentation:** Write a detailed detection report outlining the rule logic, test logs, coverage context, and deployment status. Call `save_report_artifact` to save the Markdown report.

TRANSPARENCY IN RESPONSES:
When reporting results, ALWAYS include:
1. Which tools you called and why.
2. The specific rule details, test queries, or results returned by Remote OneMCP.
3. The exact YARA-L rule code or tuning conditions applied.

Remember: Detection quality determines alert fidelity. Balance speed of deployment with coverage validation and false-positive minimization.""",
        tools=tools,
        before_model_callback=prevent_runaway_loop_callback,
        before_tool_callback=before_tool_cache,
        after_tool_callback=after_tool_cache,
        after_agent_callback=generate_memory,
    )

    logger.info("Detection Engineer Agent created successfully!")
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
