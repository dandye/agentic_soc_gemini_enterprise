# Open ToDos and Open Tasks Artifact

## 1. `ToDo.md` Open Tasks (COMPLETED)
*   **Critical Incident Notification:** FIXED. Switched missing severity icon to a Material Icon (`report_problem`).
*   **Triage Report Ready Card:** FIXED. Updated the tool to fetch pre-signed URLs from the correct GCS `archive/` folder.

## 2. Implementation Plan: Memory Call-outs
The `implementation_plan.md` outlines a large-scale task to update markdown files in `adk_runbooks/rules-bank/` with dynamic memory call-outs:
*   **Automated Baseline Update:** A script is needed to inject "Query Memory" and "Save Memory" steps into all runbooks.
*   **Specialized Manual Updates:** Nuanced call-outs are needed for complex playbooks like IRPs.
*   **Topic Consolidation:** Pending question about whether to keep 12 memory topics or consolidate them down to 10.

## 3. Inline TODOs in Codebase
Found **26 inline TODO comments** in the codebase, notably:
*   `soc_agent/tools/cti_facade.py`: How to invoke `McpToolset` functions programmatically.
*   `pyproject.toml`: Add timeouts to requests in the future.
*   Various logging and performance improvements in the `mcp-security` submodules.
