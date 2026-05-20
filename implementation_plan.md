# Implementation Plan: Adding Memory Call-outs to ADK Runbooks

This plan outlines the strategy to update all runbooks in the `adk_runbooks/` repository to dynamically utilize memory. The goal is to instruct the agent on *when to query* specific memory topics at the start of investigations and *when to save* new insights at the conclusion of tasks.

There are currently **125 markdown files** in `adk_runbooks/rules-bank/`. A systematic approach combining an automated script (for broad injection) and manual curation (for specific complex playbooks like IRPs) will be most effective.

## 1. Memory Topics Review

The prompt mentioned "10 different topics", but I found exactly **12 topics** configured in `soc_agent/agent.py`:

1. `analyst_notes`
2. `investigation_patterns`
3. `approved_exceptions`
4. `active_campaign_intelligence`
5. `asset_context`
6. `siem_query_snippets`
7. `containment_strategies`
8. `escalation_preferences`
9. `detection_rule_feedback`
10. `incident_response_status`
11. `threat_actor_profiles`
12. `tool_execution_quirks`

> [!WARNING]
> Please confirm if you want to keep all 12 topics, refactor them down to 10, or add any new ones before we proceed!

## 2. Standardized Call-out Templates

We will introduce two standard steps into the `## Workflow Steps & Diagram` section of each runbook.

**Query Memory (Early Step, Usually Step 1.5 or 2.5):**
> **Query Memory Context:** Before deep analysis, use the `LoadMemoryTool` to retrieve historical context for the involved entities or alert types. Check appropriate topics such as `approved_exceptions`, `investigation_patterns`, or `asset_context` to avoid redundant effort and identify known benign behavior.

**Save Memory (Final Step):**
> **Save Findings to Memory:** If this workflow yielded novel insights (e.g., a new false positive rule, newly identified critical infrastructure, or a successful containment action), save these details to the memory bank under the appropriate topic (e.g., `analyst_notes`, `detection_rule_feedback`, or `containment_strategies`).

## 3. Implementation Strategy

Given the volume of files (125 `.md` files), we will use a hybrid approach to save time:

1. **Automated Baseline Update:**
   - I will write a Python script to iterate through the `.md` files in `adk_runbooks/rules-bank/`.
   - The script will automatically inject a "Query Memory" sub-step after the "Initial Context" part of the `## Workflow Steps` section.
   - It will append a "Save Findings to Memory" step before the `## Completion Criteria` section.
2. **Specialized Manual Updates (IRPs & Complex Runbooks):**
   - Certain critical runbooks like `irps/malware_incident_response.md` or `ransomware_response.md` require nuanced, topic-specific call-outs (e.g., explicitly telling the agent to query `threat_actor_profiles` and `incident_response_status`). We will manually refine these.

## User Review Required

> [!IMPORTANT]
> 1. Are you okay with the **12 identified topics**, or would you like me to consolidate/add any before we start?
> 2. Do you approve of the **hybrid script + manual curation** approach to handle the 125 files efficiently?

## Verification Plan

### Automated Verification
- Run a `grep` across `adk_runbooks/rules-bank/**/*.md` to ensure the strings "Query Memory" and "Save Memory" exist in the workflow sections.

### Manual Verification
- Review the diffs of a few critical Incident Response Playbooks (IRPs) to ensure the call-outs are logically placed within the complex workflows.
