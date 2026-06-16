---
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T14:45:00Z"
---
# Welcome & Overview

Welcome to the official developer documentation for the **Agentic Security Operations Center (SOC) System**. This project implements a state-of-the-art **Coordinated Multi-Agent Network** designed using the Google Vertex AI Agent Development Kit (ADK).

## Introduction

Modern security operations centers are overwhelmed by high alert volumes, complex threat telemetry, and manual containment playbooks. This system addresses those challenges by deploying a network of five specialized, autonomous AI agents to Google Cloud Platform, coordinating their investigations in real-time.

## Key System Goals

- **Autonomous Triaging:** In-process Tier 1 agents analyze incoming Chronicle SIEM alerts instantly, filtering out noise and false positives.
- **Deep Investigations:** Proactive Threat Hunter and CTI Researcher agents map out lateral movements, compile complete incident timelines, and profile threat actors.
- **Automated Containment:** The Tier 2 Responder agent executes containment actions, isolating compromised hosts and blocking malicious command-and-control (C2) domains.
- **Robust Grounding:** Bypasses vector database retrieval limitations by querying high-performance Elasticsearch runbook indexes and Neo4j threat relationship graphs directly.
