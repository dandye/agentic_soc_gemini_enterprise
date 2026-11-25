"""Progressive MCP tool & SOC runbook pruner using Gemini Decision 1.

Runs inside an ADK ``before_model_callback`` to evaluate a single flat-latency
``gemini-decision-1`` call (0 output tokens) containing:
  1. One ``choice`` question (``select_runbook`` with a ``general_triage``
     catch-all) to pick the single matching ~300-word SOC runbook.
  2. N ``noul`` questions (``tool_needed_<tool_name>``) across the full
     Chronicle SIEM / SOAR / GTI tool catalog (30-40+ tools).

Tools scoring below ``threshold`` and non-selected runbooks are pruned from
``LlmRequest`` before the downstream generative model sees the prompt, cutting
prefill schema bytes and tokens without sacrificing tool recall.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import time
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Any

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.tools.base_tool import BaseTool
from google.genai import types


try:
    from shared_decision_guards.decision_client import (
        aevaluate_decisions,
        choice_question,
        evaluate_decisions,
        noul_question,
    )
except ImportError:
    try:
        from governed_agents.shared_decision_guards.decision_client import (
            aevaluate_decisions,
            choice_question,
            evaluate_decisions,
            noul_question,
        )
    except ImportError:
        from governed_agents.soc_orchestrator.decision_client import (
            aevaluate_decisions,
            choice_question,
            evaluate_decisions,
            noul_question,
        )


logger = logging.getLogger("google_adk." + __name__)

DEFAULT_PRUNE_THRESHOLD = float(os.getenv("TOOL_PRUNE_THRESHOLD", "0.50"))
DEFAULT_FALLBACK_TOP_K = int(os.getenv("TOOL_PRUNE_FALLBACK_TOP_K", "3"))
DEFAULT_MIN_TOOLS_TO_PRUNE = int(os.getenv("TOOL_PRUNE_MIN_TOOLS", "12"))
_RUNBOOK_TAG_RE = re.compile(
    r'<runbook\s+id="(?P<id>[a-zA-Z0-9_-]+)">(?P<body>.*?)</runbook>',
    re.DOTALL,
)


@dataclass(frozen=True)
class ToolCatalogEntry:
    """Metadata and JSON parameter schema for a governed SOC tool."""

    name: str
    category: str
    description: str
    decision_prompt: str
    parameters: dict[str, Any]

    def to_function_declaration(self) -> types.FunctionDeclaration:
        return types.FunctionDeclaration(
            name=self.name,
            description=self.description,
            parameters=self.parameters,
        )

    def to_base_tool(self) -> BaseTool:
        return _CatalogTool(self)


class _CatalogTool(BaseTool):
    """Lightweight ADK BaseTool wrapper for a ToolCatalogEntry."""

    def __init__(self, entry: ToolCatalogEntry) -> None:
        super().__init__(name=entry.name, description=entry.description)
        self._declaration = entry.to_function_declaration()

    def _get_declaration(self) -> types.FunctionDeclaration:
        return self._declaration


def _schema(
    properties: dict[str, dict[str, Any]],
    required: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "OBJECT",
        "properties": properties,
        "required": required or [],
    }


def _str_prop(description: str) -> dict[str, Any]:
    return {"type": "STRING", "description": description}


def _int_prop(description: str) -> dict[str, Any]:
    return {"type": "INTEGER", "description": description}


def _bool_prop(description: str) -> dict[str, Any]:
    return {"type": "BOOLEAN", "description": description}


def _arr_str_prop(description: str) -> dict[str, Any]:
    return {
        "type": "ARRAY",
        "items": {"type": "STRING"},
        "description": description,
    }


# 35-tool Chronicle SIEM / SOAR / GTI catalog grounded in governed_agents/ and
# agent_soc_manager/ tool definitions.
SOC_TOOL_CATALOG: tuple[ToolCatalogEntry, ...] = (
    # --- Chronicle SIEM Threat Hunting & Alert Triage (12) ---
    ToolCatalogEntry(
        name="udm_search",
        category="siem_hunt",
        description=(
            "Search Chronicle SIEM Unified Data Model (UDM) telemetry events "
            "using UDM query syntax and a bounded UTC time window."
        ),
        decision_prompt=(
            "Is `udm_search` (searching structured Chronicle SIEM UDM telemetry "
            "events across hosts, users, or processes) needed for this request?"
        ),
        parameters=_schema(
            {
                "query": _str_prop(
                    'UDM filter expression, e.g. principal.hostname = "wkstn-01".'
                ),
                "start_time": _str_prop("RFC3339 UTC start timestamp."),
                "end_time": _str_prop("RFC3339 UTC end timestamp."),
                "limit": _int_prop("Maximum UDM events to return (capped at 100)."),
            },
            ["query", "start_time", "end_time"],
        ),
    ),
    ToolCatalogEntry(
        name="search_raw_logs",
        category="siem_hunt",
        description=(
            "Search unparsed or raw ingested log payloads in Chronicle SIEM "
            "when UDM fields are insufficient."
        ),
        decision_prompt=(
            "Is `search_raw_logs` (searching raw unparsed log lines in Chronicle "
            "SIEM) needed for this request?"
        ),
        parameters=_schema(
            {
                "query": _str_prop("Substring or regex pattern to match in raw logs."),
                "log_type": _str_prop("Optional Chronicle ingestion log type."),
                "start_time": _str_prop("RFC3339 UTC start timestamp."),
                "end_time": _str_prop("RFC3339 UTC end timestamp."),
            },
            ["query", "start_time", "end_time"],
        ),
    ),
    ToolCatalogEntry(
        name="translate_udm_query",
        category="siem_hunt",
        description=(
            "Translate natural-language hunting criteria into a valid Chronicle "
            "SIEM UDM search query."
        ),
        decision_prompt=(
            "Is `translate_udm_query` (converting natural language into Chronicle "
            "UDM query syntax) needed for this request?"
        ),
        parameters=_schema(
            {
                "natural_language": _str_prop(
                    "Plain-English description of events to find."
                )
            },
            ["natural_language"],
        ),
    ),
    ToolCatalogEntry(
        name="list_security_alerts",
        category="siem_alerts",
        description=(
            "List Chronicle SIEM security alerts filtered by status, severity, "
            "or time range."
        ),
        decision_prompt=(
            "Is `list_security_alerts` (listing recent Chronicle SIEM security "
            "alerts in a time window or status filter) needed for this request?"
        ),
        parameters=_schema(
            {
                "start_time": _str_prop("RFC3339 UTC start timestamp."),
                "end_time": _str_prop("RFC3339 UTC end timestamp."),
                "severity": _str_prop(
                    "Optional severity filter: LOW, MEDIUM, HIGH, CRITICAL."
                ),
                "status": _str_prop(
                    "Optional alert status filter: OPEN, CLOSED, IN_PROGRESS."
                ),
            },
            ["start_time", "end_time"],
        ),
    ),
    ToolCatalogEntry(
        name="get_security_alert",
        category="siem_alerts",
        description=(
            "Retrieve full metadata, rule context, and verdict details for a "
            "specific Chronicle SIEM security alert ID."
        ),
        decision_prompt=(
            "Is `get_security_alert` (fetching details for a specific Chronicle "
            "SIEM alert ID) needed for this request?"
        ),
        parameters=_schema(
            {"alert_id": _str_prop("Chronicle SIEM alert identifier.")},
            ["alert_id"],
        ),
    ),
    ToolCatalogEntry(
        name="fetch_alert_data",
        category="siem_alerts",
        description=(
            "Fetch underlying UDM events and detection evidence associated with "
            "a Chronicle SIEM alert."
        ),
        decision_prompt=(
            "Is `fetch_alert_data` (retrieving the underlying UDM events for a "
            "specific alert) needed for this request?"
        ),
        parameters=_schema(
            {
                "alert_id": _str_prop("Chronicle SIEM alert identifier."),
                "include_raw_logs": _bool_prop("Whether to include raw log payloads."),
            },
            ["alert_id"],
        ),
    ),
    ToolCatalogEntry(
        name="update_security_alert",
        category="siem_alerts",
        description=(
            "Update the triage status, verdict, or analyst comment on a "
            "Chronicle SIEM security alert."
        ),
        decision_prompt=(
            "Is `update_security_alert` (mutating the status, verdict, or "
            "comment of a Chronicle SIEM alert) needed for this request?"
        ),
        parameters=_schema(
            {
                "alert_id": _str_prop("Chronicle SIEM alert identifier."),
                "status": _str_prop("New status: IN_PROGRESS, CLOSED, ESCALATED."),
                "verdict": _str_prop("Verdict: TRUE_POSITIVE, FALSE_POSITIVE, BENIGN."),
                "comment": _str_prop("Analyst disposition note."),
            },
            ["alert_id", "status"],
        ),
    ),
    ToolCatalogEntry(
        name="search_entity",
        category="siem_entity",
        description=(
            "Look up entity records (hostname, user, IP, domain, or file hash) "
            "in the Chronicle SIEM entity graph."
        ),
        decision_prompt=(
            "Is `search_entity` (looking up a host, user, IP, domain, or hash "
            "in the Chronicle SIEM entity graph) needed for this request?"
        ),
        parameters=_schema(
            {
                "indicator": _str_prop(
                    "Entity value such as hostname, username, or IP."
                ),
                "entity_type": _str_prop(
                    "ASSET, USER, IP_ADDRESS, DOMAIN_NAME, or FILE."
                ),
                "start_time": _str_prop("RFC3339 UTC start timestamp."),
                "end_time": _str_prop("RFC3339 UTC end timestamp."),
            },
            ["indicator"],
        ),
    ),
    ToolCatalogEntry(
        name="summarize_entity",
        category="siem_entity",
        description=(
            "Generate a risk and activity summary for a Chronicle SIEM entity "
            "including first/last seen, prevalence, and related alerts."
        ),
        decision_prompt=(
            "Is `summarize_entity` (getting a prevalence, first/last seen, and "
            "alert summary for a SIEM entity) needed for this request?"
        ),
        parameters=_schema(
            {
                "indicator": _str_prop("Entity identifier to summarize."),
                "start_time": _str_prop("RFC3339 UTC start timestamp."),
                "end_time": _str_prop("RFC3339 UTC end timestamp."),
            },
            ["indicator"],
        ),
    ),
    ToolCatalogEntry(
        name="get_ioc_match",
        category="siem_entity",
        description=(
            "Check Chronicle SIEM IoC match feeds for hits against an IP, "
            "domain, URL, or file hash."
        ),
        decision_prompt=(
            "Is `get_ioc_match` (checking internal Chronicle SIEM IoC match "
            "hits for an indicator) needed for this request?"
        ),
        parameters=_schema(
            {
                "indicator": _str_prop("IOC value to query against SIEM IoC matches."),
                "start_time": _str_prop("RFC3339 UTC start timestamp."),
                "end_time": _str_prop("RFC3339 UTC end timestamp."),
            },
            ["indicator"],
        ),
    ),
    ToolCatalogEntry(
        name="list_log_types",
        category="siem_admin",
        description=(
            "List supported Chronicle SIEM log types and active ingestion "
            "sources for parser or rule scoping."
        ),
        decision_prompt=(
            "Is `list_log_types` (listing Chronicle SIEM log types for parser "
            "or rule coverage checks) needed for this request?"
        ),
        parameters=_schema(
            {"filter_prefix": _str_prop("Optional prefix filter for log type names.")},
        ),
    ),
    ToolCatalogEntry(
        name="list_feeds",
        category="siem_admin",
        description=(
            "List configured Chronicle SIEM ingestion feeds and their health " "status."
        ),
        decision_prompt=(
            "Is `list_feeds` (inspecting Chronicle SIEM ingestion feed "
            "configurations and status) needed for this request?"
        ),
        parameters=_schema(
            {"page_size": _int_prop("Maximum number of feeds to return.")},
        ),
    ),
    # --- Chronicle SIEM Detection Engineering & YARA-L 2.0 (8) ---
    ToolCatalogEntry(
        name="validate_rule",
        category="detection_eng",
        description=(
            "Validate YARA-L 2.0 rule syntax, UDM field references, and "
            "compilation diagnostics without deploying."
        ),
        decision_prompt=(
            "Is `validate_rule` (validating YARA-L 2.0 detection rule syntax) "
            "needed for this request?"
        ),
        parameters=_schema(
            {"rule_text": _str_prop("Full YARA-L 2.0 rule source text.")},
            ["rule_text"],
        ),
    ),
    ToolCatalogEntry(
        name="list_rules",
        category="detection_eng",
        description=(
            "List existing YARA-L 2.0 detection rules in Chronicle SIEM with "
            "enabled/live status."
        ),
        decision_prompt=(
            "Is `list_rules` (listing existing Chronicle SIEM YARA-L 2.0 "
            "detection rules) needed for this request?"
        ),
        parameters=_schema(
            {
                "filter_query": _str_prop("Optional substring filter on rule name."),
                "only_enabled": _bool_prop("Return only enabled rules."),
            },
        ),
    ),
    ToolCatalogEntry(
        name="get_rule",
        category="detection_eng",
        description=(
            "Fetch the full YARA-L 2.0 source text and metadata for a specific "
            "Chronicle SIEM rule ID."
        ),
        decision_prompt=(
            "Is `get_rule` (retrieving the source text and metadata of a "
            "specific YARA-L 2.0 rule) needed for this request?"
        ),
        parameters=_schema(
            {"rule_id": _str_prop("Chronicle rule ID (e.g. ru_12345).")},
            ["rule_id"],
        ),
    ),
    ToolCatalogEntry(
        name="create_rule",
        category="detection_eng",
        description=(
            "Create a new YARA-L 2.0 detection rule in Chronicle SIEM "
            "(governed write action)."
        ),
        decision_prompt=(
            "Is `create_rule` (creating/deploying a new YARA-L 2.0 rule in "
            "Chronicle SIEM) needed for this request?"
        ),
        parameters=_schema(
            {
                "rule_text": _str_prop("Validated YARA-L 2.0 rule text."),
                "enabled": _bool_prop("Whether to enable the rule immediately."),
            },
            ["rule_text"],
        ),
    ),
    ToolCatalogEntry(
        name="list_rule_detections",
        category="detection_eng",
        description=(
            "List recent detections fired by a specific YARA-L 2.0 rule for "
            "precision and noise tuning."
        ),
        decision_prompt=(
            "Is `list_rule_detections` (inspecting detections generated by a "
            "specific YARA-L 2.0 rule) needed for this request?"
        ),
        parameters=_schema(
            {
                "rule_id": _str_prop("Chronicle rule ID."),
                "start_time": _str_prop("RFC3339 UTC start timestamp."),
                "end_time": _str_prop("RFC3339 UTC end timestamp."),
                "limit": _int_prop("Maximum detections to return."),
            },
            ["rule_id"],
        ),
    ),
    ToolCatalogEntry(
        name="list_rule_errors",
        category="detection_eng",
        description=(
            "List runtime or compilation errors reported for a Chronicle SIEM "
            "YARA-L 2.0 rule."
        ),
        decision_prompt=(
            "Is `list_rule_errors` (checking runtime or compilation errors on "
            "a YARA-L 2.0 rule) needed for this request?"
        ),
        parameters=_schema(
            {"rule_id": _str_prop("Chronicle rule ID.")},
            ["rule_id"],
        ),
    ),
    ToolCatalogEntry(
        name="evaluate_rule_coverage",
        category="detection_eng",
        description=(
            "Run a YARA-L 2.0 rule retrohunt/evaluation against historical UDM "
            "data or synthetic events to measure hit volume."
        ),
        decision_prompt=(
            "Is `evaluate_rule_coverage` (testing or evaluating a YARA-L 2.0 "
            "rule against UDM events for false-positive rate) needed for this request?"
        ),
        parameters=_schema(
            {
                "rule_text": _str_prop("YARA-L 2.0 rule source text."),
                "start_time": _str_prop("RFC3339 UTC start timestamp."),
                "end_time": _str_prop("RFC3339 UTC end timestamp."),
            },
            ["rule_text"],
        ),
    ),
    ToolCatalogEntry(
        name="generate_synthetic_events",
        category="detection_eng",
        description=(
            "Generate synthetic UDM test events matching an attack technique to "
            "unit-test a YARA-L 2.0 rule."
        ),
        decision_prompt=(
            "Is `generate_synthetic_events` (creating synthetic UDM test "
            "events to test a YARA-L 2.0 rule) needed for this request?"
        ),
        parameters=_schema(
            {
                "technique_id": _str_prop("MITRE ATT&CK technique ID, e.g. T1003.001."),
                "count": _int_prop("Number of synthetic UDM events to generate."),
            },
            ["technique_id"],
        ),
    ),
    # --- Chronicle Reference Lists & Parsers (5) ---
    ToolCatalogEntry(
        name="get_reference_list",
        category="reference_lists",
        description=(
            "Read entries from a Chronicle SIEM reference list (allowlist, "
            "blocklist, or containment list)."
        ),
        decision_prompt=(
            "Is `get_reference_list` (reading a Chronicle SIEM reference list "
            "or allowlist/blocklist) needed for this request?"
        ),
        parameters=_schema(
            {"name": _str_prop("Reference list name.")},
            ["name"],
        ),
    ),
    ToolCatalogEntry(
        name="create_reference_list",
        category="reference_lists",
        description=(
            "Create a new Chronicle SIEM reference list for rules or containment."
        ),
        decision_prompt=(
            "Is `create_reference_list` (creating a brand-new Chronicle SIEM "
            "reference list) needed for this request?"
        ),
        parameters=_schema(
            {
                "name": _str_prop("Reference list name."),
                "description": _str_prop("Purpose of the reference list."),
                "entries": _arr_str_prop("Initial string or regex entries."),
            },
            ["name", "entries"],
        ),
    ),
    ToolCatalogEntry(
        name="update_reference_list",
        category="reference_lists",
        description=(
            "Add or remove entries in an existing Chronicle SIEM containment "
            "or exclusion reference list."
        ),
        decision_prompt=(
            "Is `update_reference_list` (adding or removing entries in an "
            "existing Chronicle SIEM reference list) needed for this request?"
        ),
        parameters=_schema(
            {
                "name": _str_prop("Reference list name."),
                "add_entries": _arr_str_prop("Entries to append."),
                "remove_entries": _arr_str_prop("Entries to remove."),
            },
            ["name"],
        ),
    ),
    ToolCatalogEntry(
        name="activate_parser",
        category="parsers",
        description=("Activate a Chronicle SIEM CBN parser revision for a log type."),
        decision_prompt=(
            "Is `activate_parser` (activating a Chronicle SIEM log parser) "
            "needed for this request?"
        ),
        parameters=_schema(
            {
                "log_type": _str_prop("Chronicle log type."),
                "parser_id": _str_prop("Parser revision ID."),
            },
            ["log_type", "parser_id"],
        ),
    ),
    ToolCatalogEntry(
        name="deactivate_parser",
        category="parsers",
        description=("Deactivate an active Chronicle SIEM CBN parser revision."),
        decision_prompt=(
            "Is `deactivate_parser` (deactivating a Chronicle SIEM log parser) "
            "needed for this request?"
        ),
        parameters=_schema(
            {
                "log_type": _str_prop("Chronicle log type."),
                "parser_id": _str_prop("Parser revision ID."),
            },
            ["log_type", "parser_id"],
        ),
    ),
    # --- GTI / CTI Enrichment (5) ---
    ToolCatalogEntry(
        name="lookup_file_hash_reputation",
        category="cti",
        description=(
            "Look up an MD5, SHA-1, or SHA-256 file hash in Google Threat "
            "Intelligence (GTI) / VirusTotal v3."
        ),
        decision_prompt=(
            "Is `lookup_file_hash_reputation` (enriching a file hash in Google "
            "Threat Intelligence / VirusTotal) needed for this request?"
        ),
        parameters=_schema(
            {"file_hash": _str_prop("MD5, SHA-1, or SHA-256 hash.")},
            ["file_hash"],
        ),
    ),
    ToolCatalogEntry(
        name="lookup_domain_reputation",
        category="cti",
        description=(
            "Look up a domain name in Google Threat Intelligence (GTI) for "
            "malicious verdicts, threat actors, and DNS/WHOIS context."
        ),
        decision_prompt=(
            "Is `lookup_domain_reputation` (enriching a domain name in Google "
            "Threat Intelligence) needed for this request?"
        ),
        parameters=_schema(
            {"domain": _str_prop("Domain name to enrich.")},
            ["domain"],
        ),
    ),
    ToolCatalogEntry(
        name="lookup_ip_reputation",
        category="cti",
        description=(
            "Look up an IPv4 or IPv6 address in Google Threat Intelligence "
            "(GTI) for C2, botnet, or scanner reputation."
        ),
        decision_prompt=(
            "Is `lookup_ip_reputation` (enriching an IP address in Google "
            "Threat Intelligence) needed for this request?"
        ),
        parameters=_schema(
            {"ip_address": _str_prop("IPv4 or IPv6 address.")},
            ["ip_address"],
        ),
    ),
    ToolCatalogEntry(
        name="get_threat_collection",
        category="cti",
        description=(
            "Fetch a Google Threat Intelligence (GTI) threat actor, malware "
            "family, or campaign collection."
        ),
        decision_prompt=(
            "Is `get_threat_collection` (retrieving a GTI threat actor or "
            "malware campaign collection) needed for this request?"
        ),
        parameters=_schema(
            {"collection_id": _str_prop("GTI collection ID or slug.")},
            ["collection_id"],
        ),
    ),
    ToolCatalogEntry(
        name="triage_unstructured_cti_artifact",
        category="cti",
        description=(
            "Score and extract structured IOCs, MITRE TTPs, and actionability "
            "from unstructured threat advisories or CTI reports."
        ),
        decision_prompt=(
            "Is `triage_unstructured_cti_artifact` (extracting IOCs and "
            "severity from unstructured CTI prose) needed for this request?"
        ),
        parameters=_schema(
            {
                "artifact_text": _str_prop(
                    "Unstructured threat report or advisory text."
                )
            },
            ["artifact_text"],
        ),
    ),
    # --- Tier-2 Containment & SOAR / ChatOps (5) ---
    ToolCatalogEntry(
        name="isolate_endpoint_host",
        category="containment",
        description=(
            "Network-isolate a compromised endpoint host via EDR/SOAR under "
            "Tier-2 containment governance."
        ),
        decision_prompt=(
            "Is `isolate_endpoint_host` (network-isolating a compromised "
            "endpoint host) needed for this request?"
        ),
        parameters=_schema(
            {
                "hostname": _str_prop("Target endpoint hostname."),
                "reason": _str_prop("Incident justification and ticket ID."),
            },
            ["hostname", "reason"],
        ),
    ),
    ToolCatalogEntry(
        name="disable_compromised_account",
        category="containment",
        description=(
            "Disable or revoke active sessions for a compromised user account "
            "in identity provider / SOAR."
        ),
        decision_prompt=(
            "Is `disable_compromised_account` (disabling a compromised user "
            "account or revoking its sessions) needed for this request?"
        ),
        parameters=_schema(
            {
                "username": _str_prop("Account UPN or username to disable."),
                "reason": _str_prop("Incident justification and ticket ID."),
            },
            ["username", "reason"],
        ),
    ),
    ToolCatalogEntry(
        name="execute_manual_action",
        category="soar",
        description=(
            "Execute a Siemplify SOAR manual playbook action on an active " "case."
        ),
        decision_prompt=(
            "Is `execute_manual_action` (running a Siemplify SOAR playbook "
            "action on a case) needed for this request?"
        ),
        parameters=_schema(
            {
                "case_id": _str_prop("Siemplify SOAR case ID."),
                "action_name": _str_prop("SOAR integration action identifier."),
                "target": _str_prop("Target entity or scope."),
            },
            ["case_id", "action_name"],
        ),
    ),
    ToolCatalogEntry(
        name="trigger_ai_wipe_host_approval_card",
        category="chatops",
        description=(
            "Post an interactive ChatOps approval card requesting human "
            "sign-off before wiping a host."
        ),
        decision_prompt=(
            "Is `trigger_ai_wipe_host_approval_card` (posting a ChatOps "
            "approval card to wipe a host) needed for this request?"
        ),
        parameters=_schema(
            {
                "hostname": _str_prop("Target hostname."),
                "incident_id": _str_prop("Associated incident ID."),
            },
            ["hostname"],
        ),
    ),
    ToolCatalogEntry(
        name="trigger_phishing_report_summary_card",
        category="chatops",
        description=(
            "Send a structured ChatOps phishing triage summary card to the "
            "SOC analyst channel."
        ),
        decision_prompt=(
            "Is `trigger_phishing_report_summary_card` (posting a ChatOps "
            "phishing summary card) needed for this request?"
        ),
        parameters=_schema(
            {
                "sender": _str_prop("Phishing email sender address."),
                "subject": _str_prop("Email subject line."),
                "verdict": _str_prop("Phishing triage verdict."),
            },
            ["sender", "verdict"],
        ),
    ),
)

TOOL_CATALOG_BY_NAME: dict[str, ToolCatalogEntry] = {
    entry.name: entry for entry in SOC_TOOL_CATALOG
}


# ~300-word SOC runbooks keyed by `select_runbook` choice ID.
SOC_RUNBOOKS: dict[str, str] = {
    "credential_dump_hunt": (
        "RUNBOOK: Credential Dump & LSASS Access Hunt (RB-CRED-001)\n"
        "Scope: Investigate suspected credential harvesting (MITRE T1003.001 / "
        "T1003.003) involving LSASS memory access, comsvcs.dll MiniDump, "
        "procdump, Mimikatz, or NTDS.dit extraction on domain-joined hosts.\n"
        "1. Anchor the hunt: If an alert ID is provided, call "
        "`get_security_alert` and `fetch_alert_data` first to extract the "
        "target hostname, user principal, and exact UTC timestamp.\n"
        "2. Pivot in UDM: Run `udm_search` over a +/- 2-hour UTC window "
        "filtering on `principal.hostname` and process launch/injection "
        "events (`PROCESS_LAUNCH`, `PROCESS_OPEN`, `lsass.exe`, `comsvcs.dll`, "
        "`rundll32.exe`, `procdump`).\n"
        "3. Entity context: Call `search_entity` and `summarize_entity` on "
        "both the source host and any privileged account involved to check "
        "first-seen times, recent logons (Event 4624/4648), and lateral "
        "movement indicators.\n"
        "4. Triage & Escalation: Confirm whether the parent process is an "
        "authorized EDR/backup binary. If unauthorized LSASS access is "
        "confirmed, summarize process lineage (parent -> child -> command line) "
        "and recommend Tier-2 host isolation and credential rotation. Never "
        "execute containment mutations from a read-only hunt turn."
    ),
    "phishing_triage": (
        "RUNBOOK: Phishing Email & Suspicious Link Triage (RB-PHISH-002)\n"
        "Scope: Triage user-reported phishing emails, suspicious sender "
        "domains, credential-harvesting URLs, and malicious attachments.\n"
        "1. Extract indicators: Identify sender domain, reply-to domain, "
        "embedded URLs, and attachment file hashes from the report.\n"
        "2. External CTI enrichment: Enrich domains with "
        "`lookup_domain_reputation` and attachment hashes with "
        "`lookup_file_hash_reputation` in GTI. Record detection ratios, "
        "domain age, and associated malware families.\n"
        "3. Internal exposure check: Run `udm_search` across mail gateway and "
        "proxy/DNS telemetry (`network.dns.questions.name`, `target.url`, "
        "`network.email.from`) to determine if other users received or clicked "
        "the indicator.\n"
        "4. Disposition: If malicious, call `search_entity` on any clicking "
        "users to check post-click sign-ins, and optionally emit "
        "`trigger_phishing_report_summary_card` for SOC visibility. Clearly "
        "separate confirmed clicks from mere delivery."
    ),
    "cti_enrichment": (
        "RUNBOOK: CTI Indicator & Threat Report Enrichment (RB-CTI-003)\n"
        "Scope: Enrich file hashes (MD5/SHA-1/SHA-256), IP addresses, domains, "
        "threat actor collections, and unstructured CTI advisories using "
        "Google Threat Intelligence (GTI) and internal IoC feeds.\n"
        "1. Classify observables: Route file hashes to "
        "`lookup_file_hash_reputation`, domains to `lookup_domain_reputation`, "
        "and IPs to `lookup_ip_reputation`.\n"
        "2. Campaign & prose triage: When given an actor/malware collection "
        "ID, call `get_threat_collection`. When given unstructured threat "
        "prose, call `triage_unstructured_cti_artifact` to extract IOCs and "
        "actionability.\n"
        "3. Internal correlation (only if asked): Check `get_ioc_match` if "
        "the analyst asks whether the IOC has been observed in Chronicle SIEM.\n"
        "4. Reporting standard: Report exact GTI verdict, malicious engine "
        "counts, last-analysis timestamp, and attributed threat actors without "
        "speculating beyond tool output."
    ),
    "crown_jewel_containment": (
        "RUNBOOK: Tier-2 Crown Jewel Host & Account Containment (RB-RESP-004)\n"
        "Scope: Execute or validate Tier-2 containment actions on confirmed "
        "compromised endpoints, privileged accounts, and Chronicle SIEM "
        "containment reference lists.\n"
        "1. Pre-containment verification: Before mutating state, verify the "
        "alert or incident context via `get_security_alert` or "
        "`search_entity` so the target hostname/account matches the ticket.\n"
        "2. Containment execution: Use `isolate_endpoint_host` for host "
        "network isolation, `disable_compromised_account` for identity "
        "revocation, and `update_reference_list` to add confirmed C2 IPs or "
        "hashes to active blocklists.\n"
        "3. Alert lifecycle: Update the alert disposition via "
        "`update_security_alert` once containment actions complete.\n"
        "4. Governance guardrails: Never invoke destructive host-wipe "
        "workflows without explicit human approval. Include exact target IDs "
        "and justification in every containment call."
    ),
    "detection_rule_tuning": (
        "RUNBOOK: Chronicle SIEM YARA-L 2.0 Rule Authoring & Tuning (RB-DET-005)\n"
        "Scope: Author, validate, debug, and tune Chronicle SIEM YARA-L 2.0 "
        "detection rules to improve signal-to-noise ratio.\n"
        "1. Inspect existing rule: When tuning an existing rule ID, call "
        "`get_rule`, `list_rule_detections`, and `list_rule_errors` to "
        "measure false-positive volume and identify noisy entities or fields.\n"
        "2. Syntax & coverage validation: Before recommending any rule edit, "
        "validate the updated YARA-L 2.0 text with `validate_rule` and test "
        "historical hit volume with `evaluate_rule_coverage`.\n"
        "3. Synthetic verification: Use `generate_synthetic_events` when "
        "verifying new detection logic against a MITRE ATT&CK technique.\n"
        "4. Guardrails: Prefer precise UDM field exclusions or reference-list "
        "allowlists (`get_reference_list`) over broad suppressions, and never "
        "deploy unvalidated YARA-L."
    ),
    "general_triage": (
        "RUNBOOK: General SOC Triage & Situational Awareness (RB-GEN-006)\n"
        "Scope: Catch-all runbook for broad alert queue reviews, ambiguous "
        "security questions, or multi-domain requests that do not map cleanly "
        "to a single specialized playbook.\n"
        "1. Establish scope: Clarify the time window, severity filter, and "
        "target environment. For queue overviews, start with "
        "`list_security_alerts` or `get_security_alert`.\n"
        "2. Read-only pivot: Use `udm_search` or `search_entity` to gather "
        "factual telemetry before recommending escalation to CTI, Detection "
        "Engineering, or Tier-2 Response.\n"
        "3. Reporting standard: Cite exact alert IDs, timestamps, and UDM "
        "fields observed. Explicitly note any missing parameters needed for "
        "deeper investigation."
    ),
}

RUNBOOK_CRITERIA: dict[str, str] = {
    "credential_dump_hunt": (
        "Hunting credential dumping, LSASS access, Mimikatz, Kerberoasting, "
        "or lateral movement in Chronicle SIEM UDM logs."
    ),
    "phishing_triage": (
        "Triaging suspicious emails, phishing links, malicious attachments, "
        "or user-reported phish."
    ),
    "cti_enrichment": (
        "Looking up or enriching file hashes, IPs, domains, GTI threat "
        "collections, or unstructured CTI reports."
    ),
    "crown_jewel_containment": (
        "Tier-2 incident containment: isolating compromised hosts, disabling "
        "accounts, updating containment reference lists, or closing alerts."
    ),
    "detection_rule_tuning": (
        "Authoring, validating, debugging, or tuning Chronicle SIEM YARA-L "
        "2.0 detection rules and evaluating false positives."
    ),
    "general_triage": (
        "Catch-all for broad alert queue reviews, general security questions, "
        "or ambiguous requests not matching the specialized runbooks."
    ),
}


@dataclass(frozen=True)
class PruningResult:
    """Telemetry and outcome of a single Decision 1 progressive pruning pass."""

    enabled: bool
    selected_runbook: str
    runbook_confidence: float
    kept_tools: tuple[str, ...]
    pruned_tools: tuple[str, ...]
    tool_scores: dict[str, float]
    decision_latency_ms: float
    decision_input_tokens: int
    decision_output_tokens: int
    baseline_schema_bytes: int
    pruned_schema_bytes: int
    baseline_runbook_bytes: int
    pruned_runbook_bytes: int
    baseline_total_bytes: int
    pruned_total_bytes: int
    bytes_saved: int
    reduction_pct: float
    estimated_tokens_saved: int
    fallback_triggered: bool = False
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def build_pruning_questions(
    tool_names: list[str] | tuple[str, ...],
    catalog: dict[str, ToolCatalogEntry] | None = None,
    tool_descriptions: dict[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Builds the combined 1-call Decision 1 question map (1 choice + N noul)."""
    lookup = catalog or TOOL_CATALOG_BY_NAME
    descriptions = tool_descriptions or {}
    questions: dict[str, dict[str, Any]] = {
        "select_runbook": choice_question(
            (
                "Select the single SOC operational runbook that best matches "
                "the user's current investigation or action request. Use "
                "`general_triage` if no specialized runbook clearly fits."
            ),
            RUNBOOK_CRITERIA,
        )
    }
    for name in tool_names:
        entry = lookup.get(name)
        if entry is not None:
            prompt = entry.decision_prompt
        elif descriptions.get(name):
            desc = " ".join(descriptions[name].split())
            prompt = f"Is `{name}` ({desc}) needed to fulfill this SOC request?"
        else:
            prompt = f"Is the tool `{name}` needed to fulfill this SOC request?"
        questions[f"tool_needed_{name}"] = noul_question(prompt)
    return questions


def render_runbook_catalog_block(runbooks: dict[str, str] | None = None) -> str:
    """Renders all runbooks wrapped in ``<runbook id="...">`` tags."""
    rb_map = runbooks or SOC_RUNBOOKS
    blocks = [
        f'<runbook id="{rb_id}">\n{text.strip()}\n</runbook>'
        for rb_id, text in rb_map.items()
    ]
    return "<runbook_catalog>\n" + "\n\n".join(blocks) + "\n</runbook_catalog>"


def build_baseline_llm_request(
    prompt: str,
    *,
    tools: tuple[ToolCatalogEntry, ...] = SOC_TOOL_CATALOG,
    runbooks: dict[str, str] | None = None,
    base_instruction: str = (
        "You are an expert Chronicle SIEM / SOAR / GTI SOC analyst. "
        "Follow the applicable runbook and invoke only the required tools."
    ),
) -> LlmRequest:
    """Constructs an unpruned LlmRequest containing all tools and all runbooks."""
    full_instruction = f"{base_instruction}\n\n{render_runbook_catalog_block(runbooks)}"
    req = LlmRequest(
        model="gemini-3.8-flash",
        contents=[
            types.Content(
                role="user",
                parts=[types.Part.from_text(text=prompt)],
            )
        ],
        config=types.GenerateContentConfig(
            system_instruction=full_instruction,
        ),
    )
    req.append_tools([entry.to_base_tool() for entry in tools])
    return req


def _measure_tool_schema_bytes(llm_request: LlmRequest) -> int:
    """Returns serialized JSON byte size of all function_declarations in LlmRequest."""
    config = getattr(llm_request, "config", None)
    tools = getattr(config, "tools", None) or []
    decls_payload: list[dict[str, Any]] = []
    for tool in tools:
        for decl in getattr(tool, "function_declarations", None) or []:
            if hasattr(decl, "model_dump"):
                decls_payload.append(decl.model_dump(exclude_none=True, mode="json"))
            else:
                decls_payload.append(
                    {
                        "name": getattr(decl, "name", ""),
                        "description": getattr(decl, "description", ""),
                    }
                )
    return len(json.dumps(decls_payload, separators=(",", ":")).encode("utf-8"))


def _measure_runbook_bytes(llm_request: LlmRequest) -> int:
    """Returns UTF-8 byte length of runbook content in system_instruction."""
    config = getattr(llm_request, "config", None)
    sys_inst = getattr(config, "system_instruction", None)
    if not isinstance(sys_inst, str) or not sys_inst:
        return 0
    matches = _RUNBOOK_TAG_RE.findall(sys_inst)
    if matches:
        return sum(len(body.encode("utf-8")) for _, body in matches)
    # Fallback: measure any injected [ACTIVE_RUNBOOK: ...] block.
    marker_idx = sys_inst.find("[ACTIVE_RUNBOOK:")
    if marker_idx != -1:
        return len(sys_inst[marker_idx:].encode("utf-8"))
    return 0


def _collect_request_tool_names(llm_request: LlmRequest) -> list[str]:
    """Collects unique tool names declared in LlmRequest (preserving order)."""
    names: list[str] = []
    seen: set[str] = set()
    config = getattr(llm_request, "config", None)
    for tool in getattr(config, "tools", None) or []:
        for decl in getattr(tool, "function_declarations", None) or []:
            name = str(getattr(decl, "name", "") or "")
            if name and name not in seen:
                seen.add(name)
                names.append(name)
    for name in getattr(llm_request, "tools_dict", None) or {}:
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _extract_request_tool_descriptions(llm_request: LlmRequest) -> dict[str, str]:
    """Extracts FunctionDeclaration descriptions from `LlmRequest`."""
    descriptions: dict[str, str] = {}
    config = getattr(llm_request, "config", None)
    for tool in getattr(config, "tools", None) or []:
        for decl in getattr(tool, "function_declarations", None) or []:
            name = str(getattr(decl, "name", "") or "")
            desc = str(getattr(decl, "description", "") or "").strip()
            if name and desc and name not in descriptions:
                descriptions[name] = desc
    for name, tool in (getattr(llm_request, "tools_dict", None) or {}).items():
        if name not in descriptions:
            desc = str(getattr(tool, "description", "") or "").strip()
            if desc:
                descriptions[name] = desc
    return descriptions


def compute_prefix_hash(llm_request: LlmRequest) -> str:
    """Returns SHA-256 hash of system_instruction + tool declarations for KV-cache audit."""
    config = getattr(llm_request, "config", None)
    sys_inst = getattr(config, "system_instruction", None)
    tools = getattr(config, "tools", None) or []
    decls_payload: list[dict[str, Any]] = []
    for tool in tools:
        for decl in getattr(tool, "function_declarations", None) or []:
            if hasattr(decl, "model_dump"):
                decls_payload.append(decl.model_dump(exclude_none=True, mode="json"))
            else:
                decls_payload.append(
                    {
                        "name": getattr(decl, "name", ""),
                        "description": getattr(decl, "description", ""),
                    }
                )
    canonical = json.dumps(
        {
            "system_instruction": sys_inst if isinstance(sys_inst, str) else "",
            "tools": decls_payload,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _is_tool_continuation_step(llm_request: LlmRequest) -> bool:
    """Returns True when the latest turn is a tool response or model continuation."""
    contents = getattr(llm_request, "contents", None) or []
    if not contents:
        return False
    last = contents[-1]
    if getattr(last, "role", None) != "user":
        return True
    parts = getattr(last, "parts", None) or []
    return any(getattr(part, "function_response", None) is not None for part in parts)


def _extract_latest_user_text(llm_request: LlmRequest) -> str | None:
    """Returns the latest plain user prompt text, or None on tool-response turns."""
    contents = getattr(llm_request, "contents", None) or []
    if not contents or _is_tool_continuation_step(llm_request):
        return None
    last = contents[-1]
    texts = [
        part.text.strip()
        for part in (getattr(last, "parts", None) or [])
        if isinstance(getattr(part, "text", None), str) and part.text.strip()
    ]
    return "\n".join(texts) or None


def _extract_decision_input_text(llm_request: LlmRequest) -> str:
    """Extracts user prompt + compact turn context for Decision 1 evaluation."""
    contents = getattr(llm_request, "contents", None) or []
    parts_text: list[str] = []
    for content in contents[-4:]:
        role = getattr(content, "role", "user") or "user"
        for part in getattr(content, "parts", None) or []:
            text = getattr(part, "text", None)
            if isinstance(text, str) and text.strip():
                parts_text.append(f"[{role}] {text.strip()}")
            elif getattr(part, "function_call", None) is not None:
                fc = part.function_call
                parts_text.append(f"[previous_tool_call] {fc.name}")
            elif getattr(part, "function_response", None) is not None:
                fr = part.function_response
                parts_text.append(f"[previous_tool_response] {fr.name}")
    return "\n".join(parts_text).strip()


def _prune_tools_in_request(llm_request: LlmRequest, kept_set: set[str]) -> None:
    """Mutates `llm_request` in-place to retain only tools in `kept_set`."""
    if isinstance(getattr(llm_request, "tools_dict", None), dict):
        llm_request.tools_dict = {
            name: tool
            for name, tool in llm_request.tools_dict.items()
            if name in kept_set
        }
    config = getattr(llm_request, "config", None)
    if config is None or not getattr(config, "tools", None):
        return
    new_tools: list[types.Tool] = []
    for tool in config.tools:
        decls = getattr(tool, "function_declarations", None)
        if decls is None:
            new_tools.append(tool)
            continue
        kept_decls = [d for d in decls if getattr(d, "name", None) in kept_set]
        if kept_decls:
            copied = copy.copy(tool)
            copied.function_declarations = kept_decls
            new_tools.append(copied)
    config.tools = new_tools


def _prune_runbooks_in_request(
    llm_request: LlmRequest,
    selected_runbook: str,
    runbooks: dict[str, str],
) -> None:
    """Keeps only `selected_runbook` in `llm_request.config.system_instruction`."""
    config = getattr(llm_request, "config", None)
    if config is None:
        return
    selected_text = runbooks.get(selected_runbook) or runbooks.get("general_triage", "")
    active_block = (
        f'<runbook id="{selected_runbook}">\n{selected_text.strip()}\n</runbook>'
        if selected_text
        else ""
    )
    sys_inst = getattr(config, "system_instruction", None)
    if isinstance(sys_inst, str) and "<runbook_catalog>" in sys_inst:
        config.system_instruction = re.sub(
            r"<runbook_catalog>.*?</runbook_catalog>",
            active_block,
            sys_inst,
            flags=re.DOTALL,
        )
        return
    if isinstance(sys_inst, str) and _RUNBOOK_TAG_RE.search(sys_inst):
        stripped = _RUNBOOK_TAG_RE.sub("", sys_inst).strip()
        config.system_instruction = (
            f"{stripped}\n\n{active_block}".strip() if active_block else stripped
        )
        return
    if active_block:
        llm_request.append_instructions(
            [f"[ACTIVE_RUNBOOK: {selected_runbook}]\n{selected_text.strip()}"]
        )


def apply_decision_pruning(
    llm_request: LlmRequest,
    decision_result: dict[str, Any],
    *,
    tool_names: list[str],
    threshold: float = DEFAULT_PRUNE_THRESHOLD,
    safety_floor_tools: tuple[str, ...] = (),
    preserve_canary_tools: tuple[str, ...] = (),
    fallback_top_k: int = DEFAULT_FALLBACK_TOP_K,
    min_tools_to_prune: int = DEFAULT_MIN_TOOLS_TO_PRUNE,
    runbooks: dict[str, str] | None = None,
    decision_latency_ms: float = 0.0,
) -> PruningResult:
    """Applies a Decision 1 evaluation result to prune `llm_request` in-place."""
    rb_map = runbooks or SOC_RUNBOOKS
    baseline_schema_bytes = _measure_tool_schema_bytes(llm_request)
    baseline_runbook_bytes = _measure_runbook_bytes(llm_request)
    baseline_total_bytes = baseline_schema_bytes + baseline_runbook_bytes

    if len(tool_names) < min_tools_to_prune:
        return PruningResult(
            enabled=False,
            selected_runbook="general_triage",
            runbook_confidence=0.0,
            kept_tools=tuple(tool_names),
            pruned_tools=(),
            tool_scores={},
            decision_latency_ms=0.0,
            decision_input_tokens=0,
            decision_output_tokens=0,
            baseline_schema_bytes=baseline_schema_bytes,
            pruned_schema_bytes=baseline_schema_bytes,
            baseline_runbook_bytes=baseline_runbook_bytes,
            pruned_runbook_bytes=baseline_runbook_bytes,
            baseline_total_bytes=baseline_total_bytes,
            pruned_total_bytes=baseline_total_bytes,
            bytes_saved=0,
            reduction_pct=0.0,
            estimated_tokens_saved=0,
            error=(
                f"catalog size {len(tool_names)} < min_tools_to_prune "
                f"({min_tools_to_prune})"
            ),
        )

    if not decision_result.get("enabled") or decision_result.get("error"):
        return PruningResult(
            enabled=False,
            selected_runbook="general_triage",
            runbook_confidence=0.0,
            kept_tools=tuple(tool_names),
            pruned_tools=(),
            tool_scores={},
            decision_latency_ms=round(decision_latency_ms, 2),
            decision_input_tokens=0,
            decision_output_tokens=0,
            baseline_schema_bytes=baseline_schema_bytes,
            pruned_schema_bytes=baseline_schema_bytes,
            baseline_runbook_bytes=baseline_runbook_bytes,
            pruned_runbook_bytes=baseline_runbook_bytes,
            baseline_total_bytes=baseline_total_bytes,
            pruned_total_bytes=baseline_total_bytes,
            bytes_saved=0,
            reduction_pct=0.0,
            estimated_tokens_saved=0,
            error=decision_result.get("error") or decision_result.get("reason"),
        )

    answers = decision_result.get("answers") or {}
    usage = decision_result.get("usage") or {}

    rb_ans = answers.get("select_runbook") or {}
    selected_runbook = str(rb_ans.get("choice") or "general_triage")
    if selected_runbook not in rb_map:
        selected_runbook = "general_triage"
    runbook_confidence = float(rb_ans.get("confidence", 0.0))

    tool_scores: dict[str, float] = {}
    for name in tool_names:
        ans = answers.get(f"tool_needed_{name}") or {}
        tool_scores[name] = float(ans.get("noul", 0.0))

    protected_set = set(safety_floor_tools) | set(preserve_canary_tools)
    kept_list = [
        name
        for name in tool_names
        if tool_scores.get(name, 0.0) >= threshold or name in protected_set
    ]
    fallback_triggered = False
    if not kept_list and tool_names:
        fallback_triggered = True
        ranked = sorted(
            tool_names,
            key=lambda n: tool_scores.get(n, 0.0),
            reverse=True,
        )
        kept_list = ranked[: max(1, fallback_top_k)]

    kept_set = set(kept_list)
    pruned_list = [name for name in tool_names if name not in kept_set]

    _prune_tools_in_request(llm_request, kept_set)
    _prune_runbooks_in_request(llm_request, selected_runbook, rb_map)

    pruned_schema_bytes = _measure_tool_schema_bytes(llm_request)
    pruned_runbook_bytes = _measure_runbook_bytes(llm_request)
    pruned_total_bytes = pruned_schema_bytes + pruned_runbook_bytes
    bytes_saved = max(0, baseline_total_bytes - pruned_total_bytes)
    reduction_pct = (
        round((bytes_saved / baseline_total_bytes) * 100.0, 2)
        if baseline_total_bytes > 0
        else 0.0
    )
    estimated_tokens_saved = bytes_saved // 4

    return PruningResult(
        enabled=True,
        selected_runbook=selected_runbook,
        runbook_confidence=round(runbook_confidence, 4),
        kept_tools=tuple(kept_list),
        pruned_tools=tuple(pruned_list),
        tool_scores={k: round(v, 4) for k, v in tool_scores.items()},
        decision_latency_ms=round(decision_latency_ms, 2),
        decision_input_tokens=int(usage.get("total_input_tokens", 0)),
        decision_output_tokens=int(usage.get("total_output_tokens", 0)),
        baseline_schema_bytes=baseline_schema_bytes,
        pruned_schema_bytes=pruned_schema_bytes,
        baseline_runbook_bytes=baseline_runbook_bytes,
        pruned_runbook_bytes=pruned_runbook_bytes,
        baseline_total_bytes=baseline_total_bytes,
        pruned_total_bytes=pruned_total_bytes,
        bytes_saved=bytes_saved,
        reduction_pct=reduction_pct,
        estimated_tokens_saved=estimated_tokens_saved,
        fallback_triggered=fallback_triggered,
    )


def prune_llm_request_sync(
    llm_request: LlmRequest,
    *,
    threshold: float = DEFAULT_PRUNE_THRESHOLD,
    safety_floor_tools: tuple[str, ...] = (),
    preserve_canary_tools: tuple[str, ...] = (),
    fallback_top_k: int = DEFAULT_FALLBACK_TOP_K,
    min_tools_to_prune: int = DEFAULT_MIN_TOOLS_TO_PRUNE,
    catalog: dict[str, ToolCatalogEntry] | None = None,
    runbooks: dict[str, str] | None = None,
) -> PruningResult:
    """Synchronously evaluates Decision 1 and prunes `llm_request` in 1 pass."""
    tool_names = _collect_request_tool_names(llm_request)
    input_text = _extract_decision_input_text(llm_request)
    if not input_text or len(tool_names) < min_tools_to_prune:
        return apply_decision_pruning(
            llm_request,
            {"enabled": False, "reason": "empty prompt or below min_tools_to_prune"},
            tool_names=tool_names,
            threshold=threshold,
            safety_floor_tools=safety_floor_tools,
            preserve_canary_tools=preserve_canary_tools,
            fallback_top_k=fallback_top_k,
            min_tools_to_prune=min_tools_to_prune,
            runbooks=runbooks,
        )

    tool_descriptions = _extract_request_tool_descriptions(llm_request)
    questions = build_pruning_questions(
        tool_names, catalog=catalog, tool_descriptions=tool_descriptions
    )
    started = time.perf_counter()
    decision_result = evaluate_decisions(input_text, questions)
    latency_ms = (time.perf_counter() - started) * 1000.0
    return apply_decision_pruning(
        llm_request,
        decision_result,
        tool_names=tool_names,
        threshold=threshold,
        safety_floor_tools=safety_floor_tools,
        preserve_canary_tools=preserve_canary_tools,
        fallback_top_k=fallback_top_k,
        min_tools_to_prune=min_tools_to_prune,
        runbooks=runbooks,
        decision_latency_ms=latency_ms,
    )


async def prune_llm_request_async(
    llm_request: LlmRequest,
    *,
    threshold: float = DEFAULT_PRUNE_THRESHOLD,
    safety_floor_tools: tuple[str, ...] = (),
    preserve_canary_tools: tuple[str, ...] = (),
    fallback_top_k: int = DEFAULT_FALLBACK_TOP_K,
    min_tools_to_prune: int = DEFAULT_MIN_TOOLS_TO_PRUNE,
    catalog: dict[str, ToolCatalogEntry] | None = None,
    runbooks: dict[str, str] | None = None,
) -> PruningResult:
    """Asynchronously evaluates Decision 1 and prunes `llm_request` in 1 pass."""
    tool_names = _collect_request_tool_names(llm_request)
    input_text = _extract_decision_input_text(llm_request)
    if not input_text or len(tool_names) < min_tools_to_prune:
        return apply_decision_pruning(
            llm_request,
            {"enabled": False, "reason": "empty prompt or below min_tools_to_prune"},
            tool_names=tool_names,
            threshold=threshold,
            safety_floor_tools=safety_floor_tools,
            preserve_canary_tools=preserve_canary_tools,
            fallback_top_k=fallback_top_k,
            min_tools_to_prune=min_tools_to_prune,
            runbooks=runbooks,
        )

    tool_descriptions = _extract_request_tool_descriptions(llm_request)
    questions = build_pruning_questions(
        tool_names, catalog=catalog, tool_descriptions=tool_descriptions
    )
    started = time.perf_counter()
    decision_result = await aevaluate_decisions(input_text, questions)
    latency_ms = (time.perf_counter() - started) * 1000.0
    return apply_decision_pruning(
        llm_request,
        decision_result,
        tool_names=tool_names,
        threshold=threshold,
        safety_floor_tools=safety_floor_tools,
        preserve_canary_tools=preserve_canary_tools,
        fallback_top_k=fallback_top_k,
        min_tools_to_prune=min_tools_to_prune,
        runbooks=runbooks,
        decision_latency_ms=latency_ms,
    )


def _apply_pinned_plan(
    llm_request: LlmRequest,
    pinned_plan: dict[str, Any],
    *,
    tool_names: list[str],
    safety_floor_tools: tuple[str, ...],
    preserve_canary_tools: tuple[str, ...],
    runbooks: dict[str, str] | None,
) -> PruningResult:
    """Re-applies a pinned pruning plan deterministically with 0 Decision 1 RPCs."""
    rb_map = runbooks or SOC_RUNBOOKS
    baseline_schema_bytes = _measure_tool_schema_bytes(llm_request)
    baseline_runbook_bytes = _measure_runbook_bytes(llm_request)
    baseline_total_bytes = baseline_schema_bytes + baseline_runbook_bytes

    selected_runbook = str(pinned_plan.get("selected_runbook") or "general_triage")
    if selected_runbook not in rb_map:
        selected_runbook = "general_triage"
    runbook_confidence = float(pinned_plan.get("runbook_confidence", 0.0))

    protected_set = set(safety_floor_tools) | set(preserve_canary_tools)
    pinned_set = set(pinned_plan.get("kept_tools") or ()) | protected_set
    kept_list = [name for name in tool_names if name in pinned_set]
    kept_set = set(kept_list)
    pruned_list = [name for name in tool_names if name not in kept_set]

    _prune_tools_in_request(llm_request, kept_set)
    _prune_runbooks_in_request(llm_request, selected_runbook, rb_map)

    pruned_schema_bytes = _measure_tool_schema_bytes(llm_request)
    pruned_runbook_bytes = _measure_runbook_bytes(llm_request)
    pruned_total_bytes = pruned_schema_bytes + pruned_runbook_bytes
    bytes_saved = max(0, baseline_total_bytes - pruned_total_bytes)
    reduction_pct = (
        round((bytes_saved / baseline_total_bytes) * 100.0, 2)
        if baseline_total_bytes > 0
        else 0.0
    )
    return PruningResult(
        enabled=True,
        selected_runbook=selected_runbook,
        runbook_confidence=round(runbook_confidence, 4),
        kept_tools=tuple(kept_list),
        pruned_tools=tuple(pruned_list),
        tool_scores={},
        decision_latency_ms=0.0,
        decision_input_tokens=0,
        decision_output_tokens=0,
        baseline_schema_bytes=baseline_schema_bytes,
        pruned_schema_bytes=pruned_schema_bytes,
        baseline_runbook_bytes=baseline_runbook_bytes,
        pruned_runbook_bytes=pruned_runbook_bytes,
        baseline_total_bytes=baseline_total_bytes,
        pruned_total_bytes=pruned_total_bytes,
        bytes_saved=bytes_saved,
        reduction_pct=reduction_pct,
        estimated_tokens_saved=bytes_saved // 4,
        fallback_triggered=False,
        extra={"cache_hit": True, "rpc_count": 0},
    )


async def prune_with_session_pinning_async(
    state: MutableMapping[str, Any] | None,
    llm_request: LlmRequest,
    *,
    threshold: float = DEFAULT_PRUNE_THRESHOLD,
    safety_floor_tools: tuple[str, ...] = (),
    preserve_canary_tools: tuple[str, ...] = (),
    fallback_top_k: int = DEFAULT_FALLBACK_TOP_K,
    min_tools_to_prune: int = DEFAULT_MIN_TOOLS_TO_PRUNE,
    catalog: dict[str, ToolCatalogEntry] | None = None,
    runbooks: dict[str, str] | None = None,
) -> PruningResult:
    """Prunes `llm_request`, pinning the plan per user turn to preserve KV cache."""
    tool_names = _collect_request_tool_names(llm_request)
    if len(tool_names) < min_tools_to_prune:
        return apply_decision_pruning(
            llm_request,
            {"enabled": False, "reason": "below min_tools_to_prune"},
            tool_names=tool_names,
            threshold=threshold,
            safety_floor_tools=safety_floor_tools,
            preserve_canary_tools=preserve_canary_tools,
            fallback_top_k=fallback_top_k,
            min_tools_to_prune=min_tools_to_prune,
            runbooks=runbooks,
        )

    latest_user_text = _extract_latest_user_text(llm_request)
    is_continuation = _is_tool_continuation_step(llm_request)
    pinned_plan = state.get("tool_pruner_pinned_plan") if state is not None else None
    pinned_prompt = (
        state.get("tool_pruner_pinned_prompt") if state is not None else None
    )

    if isinstance(pinned_plan, dict) and (
        is_continuation
        or (latest_user_text is not None and latest_user_text == pinned_prompt)
    ):
        return _apply_pinned_plan(
            llm_request,
            pinned_plan,
            tool_names=tool_names,
            safety_floor_tools=safety_floor_tools,
            preserve_canary_tools=preserve_canary_tools,
            runbooks=runbooks,
        )

    result = await prune_llm_request_async(
        llm_request,
        threshold=threshold,
        safety_floor_tools=safety_floor_tools,
        preserve_canary_tools=preserve_canary_tools,
        fallback_top_k=fallback_top_k,
        min_tools_to_prune=min_tools_to_prune,
        catalog=catalog,
        runbooks=runbooks,
    )
    if result.enabled and state is not None:
        state["tool_pruner_pinned_prompt"] = (
            latest_user_text or _extract_decision_input_text(llm_request)
        )
        state["tool_pruner_pinned_plan"] = {
            "kept_tools": list(result.kept_tools),
            "selected_runbook": result.selected_runbook,
            "runbook_confidence": result.runbook_confidence,
            "decision_input_tokens": result.decision_input_tokens,
        }
    return PruningResult(
        enabled=result.enabled,
        selected_runbook=result.selected_runbook,
        runbook_confidence=result.runbook_confidence,
        kept_tools=result.kept_tools,
        pruned_tools=result.pruned_tools,
        tool_scores=result.tool_scores,
        decision_latency_ms=result.decision_latency_ms,
        decision_input_tokens=result.decision_input_tokens,
        decision_output_tokens=result.decision_output_tokens,
        baseline_schema_bytes=result.baseline_schema_bytes,
        pruned_schema_bytes=result.pruned_schema_bytes,
        baseline_runbook_bytes=result.baseline_runbook_bytes,
        pruned_runbook_bytes=result.pruned_runbook_bytes,
        baseline_total_bytes=result.baseline_total_bytes,
        pruned_total_bytes=result.pruned_total_bytes,
        bytes_saved=result.bytes_saved,
        reduction_pct=result.reduction_pct,
        estimated_tokens_saved=result.estimated_tokens_saved,
        fallback_triggered=result.fallback_triggered,
        error=result.error,
        extra={"cache_hit": False, "rpc_count": 1 if result.enabled else 0},
    )


def _record_metrics_in_context(
    callback_context: CallbackContext | None, result: PruningResult
) -> None:
    if callback_context is None:
        return
    state = getattr(callback_context, "state", None)
    if state is None:
        return
    try:
        state["tool_pruner_last_metrics"] = {
            "enabled": result.enabled,
            "selected_runbook": result.selected_runbook,
            "runbook_confidence": result.runbook_confidence,
            "kept_tools": list(result.kept_tools),
            "pruned_count": len(result.pruned_tools),
            "decision_latency_ms": result.decision_latency_ms,
            "bytes_saved": result.bytes_saved,
            "reduction_pct": result.reduction_pct,
            "estimated_tokens_saved": result.estimated_tokens_saved,
            "fallback_triggered": result.fallback_triggered,
            "cache_hit": bool(result.extra.get("cache_hit", False)),
            "rpc_count": int(result.extra.get("rpc_count", 0)),
        }
    except Exception:  # noqa: BLE001
        logger.debug("Unable to persist tool_pruner_last_metrics in callback_context")


def make_progressive_tool_pruner_callback(
    *,
    threshold: float = DEFAULT_PRUNE_THRESHOLD,
    safety_floor_tools: tuple[str, ...] = (),
    preserve_canary_tools: tuple[str, ...] = (),
    fallback_top_k: int = DEFAULT_FALLBACK_TOP_K,
    min_tools_to_prune: int = DEFAULT_MIN_TOOLS_TO_PRUNE,
) -> Callable[[CallbackContext, LlmRequest], Awaitable[LlmResponse | None]]:
    """Factory for an ADK `before_model_callback` with custom pruning policy."""

    async def _callback(
        callback_context: CallbackContext, llm_request: LlmRequest
    ) -> LlmResponse | None:
        state = getattr(callback_context, "state", None)
        result = await prune_with_session_pinning_async(
            state,
            llm_request,
            threshold=threshold,
            safety_floor_tools=safety_floor_tools,
            preserve_canary_tools=preserve_canary_tools,
            fallback_top_k=fallback_top_k,
            min_tools_to_prune=min_tools_to_prune,
        )
        _record_metrics_in_context(callback_context, result)
        if result.enabled:
            logger.info(
                "progressive_tool_pruner: runbook=%s (conf=%.2f) kept=%d/%d tools "
                "saved=%d bytes (%.1f%%) decision_ms=%.1f cache_hit=%s",
                result.selected_runbook,
                result.runbook_confidence,
                len(result.kept_tools),
                len(result.kept_tools) + len(result.pruned_tools),
                result.bytes_saved,
                result.reduction_pct,
                result.decision_latency_ms,
                bool(result.extra.get("cache_hit", False)),
            )
        elif result.error:
            logger.warning("progressive_tool_pruner bypassed: %s", result.error)
        return None

    return _callback


async def progressive_tool_pruner_callback(
    callback_context: CallbackContext, llm_request: LlmRequest
) -> LlmResponse | None:
    """ADK ``before_model_callback`` that prunes irrelevant tools and runbooks."""
    state = getattr(callback_context, "state", None)
    result = await prune_with_session_pinning_async(state, llm_request)
    _record_metrics_in_context(callback_context, result)
    if result.enabled:
        logger.info(
            "progressive_tool_pruner: runbook=%s (conf=%.2f) kept=%d/%d tools "
            "saved=%d bytes (%.1f%%) decision_ms=%.1f cache_hit=%s",
            result.selected_runbook,
            result.runbook_confidence,
            len(result.kept_tools),
            len(result.kept_tools) + len(result.pruned_tools),
            result.bytes_saved,
            result.reduction_pct,
            result.decision_latency_ms,
            bool(result.extra.get("cache_hit", False)),
        )
    elif result.error:
        logger.warning("progressive_tool_pruner bypassed: %s", result.error)
    return None
