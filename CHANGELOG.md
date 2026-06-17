# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-06-17

### Added
- **MLOps Experimentation Registry**: Established a standardized experimentation framework under `evalsets/experiments/` to log hypotheses, code deltas, scorecard metrics, and conclusions for prompt and parameter tuning campaigns.
- **GEAP Playground Session Tracking**: Integrated automatic generation of live, clickable Gemini Enterprise Agent Platform Playground URLs inside both the raw evaluation ledger and the generated markdown scorecards, enabling one-click console debugging of individual test runs.
- **Session-Dump Tracking Utility**: Formalized the ad-hoc session history retrieval script into a robust CLI subcommand `session-dump` (accessible via `python manage.py agent-engine session-dump` and `just agent-engine-session-dump`). It connects to the live deployed Reasoning Engine in the cloud, pulls its raw history, and beautifully prints the turn-by-turn thoughts, tool calls, and response payloads in a color-coded console format.
- **Google OKF Frontmatter Standard**: Mandated Google Open Knowledge Format (OKF) YAML frontmatter and custom provenance tracking metadata at the top of all Markdown files in the repository.

### Changed
- **Token-Compacted SIEM Event Searches (Submodule)**: Optimized `search_security_events` in the `mcp-security` submodule to automatically strip out verbose nested fields and empty keys from UDM logs, and reduced the default `max_events` from 100 to 15, yielding a 90%+ token footprint reduction.
- **Token-Compacted GTI File Reports (Submodule)**: Optimized `get_file_report` in the `mcp-security` submodule to extract high-density threat signals and summarize relationship arrays, shrinking the returned VirusTotal payload size by 98% to prevent token pressure.
- **Cognitive Tool-Call Budgeting (Threat Hunter)**: Enforced a strict budget of 2-3 knowledge graph queries (`query_neo4j_graph`) and mandated early pivoting to SIEM event searches in the Threat Hunter's system prompt. This completely eliminated runaway exploration loops and prevented cloud step-limit cutoffs, allowing the agent to successfully compile and write its final report, lifting the overall scorecard to a **perfect 100.0%**.
- **Continuous Optimization Reframing**: Renamed the evaluations guide to **Agent Evaluation, Experimentation, and Optimization Framework**, reframing the pipeline around continuous hyperparameter adaptation and active behavioral tuning.
- **Headless Credentials Fallback**: Enabled permanent service account credentials in `.env` to prevent local deployment disruptions caused by expired browser-default Application Default Credentials (ADC).

## [0.3.0] - 2026-06-16

### Added
- **Remote Specialist Agents (A2A)**: Transitioned from nested local sub-agents to a standalone, remote Agent-to-Agent (A2A) architecture. Added three new specialist agents:
  - **Threat Hunter (`agent_a2a_threat_hunter`)**: Specialized in proactive hunting, log query development (UDM), and prevalence checks.
  - **CTI Researcher (`agent_a2a_cti_researcher`)**: Focused on in-depth threat intelligence profiling, actor/campaign tracking, and malware behavior using Google Threat Intelligence.
  - **Detection Engineer (`agent_a2a_detection_engineer`)**: Dedicated to SIEM rule (YARA-L) writing, syntax validation, rule testing, and alert tuning.
- **Orchestrator A2A Tools**: Integrated remote delegation tools (`delegate_to_threat_hunter`, `delegate_to_cti_researcher`, `delegate_to_detection_engineer`) within the main SOC Manager Orchestrator.
- **Dialogflow Role Management**: Added support in `manage_iam.py` for Dialogflow service agent role bindings (`roles/aiplatform.user`), allowing conversational runtime agents to seamlessly invoke Reasoning Engines.

### Changed
- **Build System Migration**: Replaced the legacy `Makefile` with a modern, cross-platform `justfile` and rebranded the system to **Gemini Enterprise Agent Platform**.
- **Remote OneMCP Schema Flattening**: Resolved `500 INTERNAL` Vertex AI platform API failures caused by excessively complex OneMCP nested schemas. Implemented clean, flat Python wrapper functions (`list_rules`, `get_rule`, `create_rule`, `validate_rule`, `udm_search`) to present highly optimized schemas to the LLM.
- **Dependencies Upgrade**: Upgraded core project dependencies, including `google-adk` to version `2.2.0` and `google-genai` to `2.8.0`, ensuring compatibility with the new remote A2A APIs.

### Removed
- **Makefile**: Deleted the legacy `Makefile` from the repository.
- **Local Sub-agent**: Removed the local in-process `cti_subagent` from the Orchestrator, dramatically reducing packaging overhead and cold start latency.
- **Gemini Code Review Workflow**: Deleted the `.github/workflows/gemini-code-review.yml` workflow.

## [0.2.0] - 2026-05-22

### Added
- **Configurable Gemini Model Versions:** Models can now be specified via `.env` and `.env.example` for better environment flexibility. Defaults to 3.x models.
- **A2A Delegation:** Integrated example of remote Agent-to-Agent (A2A) delegation, allowing agents to call one another in a new Tier2 Incident Responder Agent.
- **ChatOps Skills:** Tier2 agent uses various ChatOps skills

### Changed
- **Agent Restructuring:** Moved submodules to an `external/` directory and renamed agent folders to a clustered layout (e.g., `a2a_tier2`).
- **ADK 2.0.0 Migration:** Upgraded `google-adk` to version 2.0.0.
- **Vertex AI SDK Upgrade:** Updated to `google-cloud-aiplatform` version 1.153.0.
- **Triage Reports:** "Download Full PDF" now retrieves pre-signed URLs from the GCS Archive folder.

### Removed
- **A2UI Visual Dashboard:** Completely removed the A2UI feature as the project transitions to a more agentic focus.
- **Redundant Agents:** Deleted redundant `soc_agent_flash` and `soc_agent_tier1` directories.
- **Unused Workflows & Docs:** Deleted `claude.yml` workflow and removed `implementation_plan.md` from git tracking.
