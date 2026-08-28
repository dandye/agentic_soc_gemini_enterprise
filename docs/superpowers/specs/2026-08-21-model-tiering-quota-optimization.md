---
type: "Architecture"
title: "Model Tiering & Quota Optimization Specification"
description: "Multi-tiered LLM routing architecture to optimize inference throughput, minimize latency, and prevent 429 quota exhaustion across SOC agents"
resource: "docs/superpowers/specs/2026-08-21-model-tiering-quota-optimization.md"
timestamp: "2026-08-21T20:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-08-21T20:50:00Z"
---

# Architecture Specification: Model Tiering & Quota Optimization

## 1. Executive Summary

This specification defines the **Multi-Tier Model Routing & Quota Optimization Architecture** for the Google ADK Agentic SOC platform.

Deploying homogeneous frontier models across all autonomous agents creates severe bottlenecks:
1. High token consumption on repetitive checklist workflows.
2. Rapid exhaustion of regional Vertex AI RPM/TPM quotas resulting in `429 RESOURCE_EXHAUSTED` errors.
3. Unnecessary latency on high-volume, procedural alert triage tasks.

This architecture introduces a balanced **3-Tier Model Strategy**:
- **Tier 1: Orchestration & Complex Reasoning** (`gemini-3.7-flash` / `gemini-3.1-pro-preview`)
- **Tier 2: Domain Specialists** (`gemini-3.7-flash`)
- **Tier 3: High-Volume Procedural Triage** (`gemini-2.5-flash-lite`)

## 2. Model Tiering Matrix

| Agent Role | Model Default | Environment Variable | Primary Workload Characteristics |
| :--- | :--- | :--- | :--- |
| **SOC Orchestrator** | `gemini-3.7-flash` | `ORCHESTRATOR_MODEL` | Multi-agent coordination, investigation planning, hypothesis synthesis |
| **CTI Researcher** | `gemini-3.7-flash` | `CTI_RESEARCHER_MODEL` | Threat actor profiling, IOC attribution, campaign synthesis |
| **Detection Engineer** | `gemini-3.7-flash` | `DETECTION_ENGINEER_MODEL` | YARA-L 2.0 rule writing, compilation validation, TDO analysis |
| **Threat Hunter** | `gemini-3.7-flash` | `THREAT_HUNTER_MODEL` | Graph traversal, UDM hunting logic, prevalence queries |
| **Tier 2 Responder** | `gemini-3.7-flash` | `TIER2_RESPONDER_MODEL` | Playbook execution, containment safety, SOAR actions |
| **Tier 1 SOC Analyst** | `gemini-2.5-flash-lite` | `TIER1_ANALYST_MODEL` | High-volume alert queue triage, entity lookups, duplicate deduplication |

## 3. Configuration Hierarchy & Fallback

Each agent respects the following resolution order:
1. Explicit environment variable in `.env` (e.g. `ORCHESTRATOR_MODEL=gemini-3.1-pro-preview`).
2. Code-level default configured per specialist tier.
3. Vertex AI region/location overrides for global routing availability.
