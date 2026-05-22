# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
