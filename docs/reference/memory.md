---
type: "Documentation"
title: "Vertex AI Memory Bank Reference Guide"
description: "Comprehensive catalog of official documentation resources, structural concepts, and local project configurations for the Vertex AI Memory Bank."
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/docs/reference/memory.md"
timestamp: "2026-06-17T20:58:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T20:58:00Z"
---

# Vertex AI Memory Bank Reference Guide

This document catalogs official documentation resources, structural concepts, and our active local project configurations for the **Vertex AI Memory Bank** (also integrated within the Gemini Enterprise Agent Platform).

---

## 1. Official Documentation Resources

Use these official Google Cloud documentation links to research features, APIs, and operational best practices for the Memory Bank:

*   **ADK Integration & Quickstart:**
    *   [Memory Bank ADK Quickstart](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank/adk-quickstart) (Primary developer guide for linking memory to Vertex AI Reasoning Engines).
*   **Architectural Overview:**
    *   [Memory Bank Core Concepts](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank/overview) (Explains session-based persistence, cross-session memory consolidation, and automatic extraction mechanics).
*   **Configuration & Custom Topics:**
    *   [Configuring Memory Topics](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank/configure-topics) (Guidance on defining custom schemas and labeling topics to instruct the model on what specific information is meaningful to persist).
*   **Managing Memories (Console & API):**
    *   [Managing Persisted Memories](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank/manage-memories) (CRUD operations, manual memory pruning, and session-level memory injection via Google Cloud Console or REST APIs).
*   **Security & Data Governance:**
    *   [Memory Bank Security & Privacy](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank/security-and-privacy) (IAM roles, access controls, data encryption keys, and residency/compliance configurations for enterprise memory storage).

---

## 2. Active Local Project Configuration

Our Orchestrator (`agent_soc_manager`) and remote specialists are pre-configured with a highly optimized set of custom memory topics. This allows the agents to capture and persist critical context across multiple independent security incidents.

The active configuration is defined in the project codebase under [agent_soc_manager/agent.py](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/agent_soc_manager/agent.py#L2336-L2400):

| Topic Label | Purpose / Description | Mapped Use Cases |
| :--- | :--- | :--- |
| `analyst_notes` | Tactical notes and insights provided by human security analysts. | Analyst-in-the-Loop context handover. |
| `investigation_patterns` | Recurring tactical patterns, known false positive indicators, or common genuine threats. | Triage acceleration. |
| `approved_exceptions` | Authorized administrative tools, routine scanner IPs, VIP context, and baseline configurations. | Noise reduction and false positive suppression. |
| `active_campaign_intelligence`| Ongoing context regarding active APT campaigns, recurring IOCs, or malware families. | Cyber Threat Intelligence (CTI) grounding. |
| `asset_context` | Mappings of specific IP schemas to business units and identification of business-critical servers. | Asset severity and impact calculation. |
| `siem_query_snippets` | Successful, highly-optimized Chronicle/UDM search query strings and syntactic workarounds. | Query efficiency and self-correction. |
| `containment_strategies` | Historical records of specific remediation or containment actions that were successful. | Tier 2 Incident Response acceleration. |
| `escalation_preferences` | Mappings of specific individuals, departments, or Tier 2/3 analysts for particular alert categories. | Coordinated escalation routing. |
| `detection_rule_feedback` | Feedback on overly noisy or poorly calibrated detection rules within the SIEM. | Detection engineering lifecycle feedback. |
| `incident_response_status` | The ongoing lifecycle status, assigned owners, and recent developments of active Incident Response Plans. | Multi-shift/multi-day incident handovers. |

---

## 3. How to Use Memory Programmatically (ADK)

When developing or modifying agents in this repository, interact with the Memory Bank using the following patterns:

### A. Automatic Extraction (System Prompt Guided)
The easiest way to persist memory is to instruct the agent in its system prompt to output findings destined for a specific topic. The Vertex AI Memory Bank will automatically parse the agent's final response and extract relevant concepts:
> "If this investigation yielded a successful containment action, summarize it clearly under the topic `containment_strategies`."

### B. Explicit Tool Execution
You can register tools that allow the agent to explicitly search or write to memory:
*   `load_memory(topic: str)`: Retrieves historical memories associated with the specified topic.
*   `save_memory(topic: str, content: str)`: Explicitly writes a new memory record under the specified topic.
