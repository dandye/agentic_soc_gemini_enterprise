---
type: "Architecture"
title: "1P CTI NLP Document Processor and FastMCP Integration"
description: "Architecture, tool definitions, span validators, text normalization, and FastMCP server for CTI document ingestion powered by dandye/nlp_capstone"
resource: "docs/cti_nlp_mcp_integration.md"
timestamp: "2026-08-31T18:45:00Z"
provenance:
  source_type: "manual"
  source_tool: "Antigravity"
  timestamp: "2026-08-31T18:45:00Z"
---

# 1P CTI NLP Document Processor and FastMCP Integration

## Overview

This module provides a first-party, private Cyber Threat Intelligence (CTI) document processing and Named Entity Recognition (NER) pipeline and FastMCP server for the Agentic SOC environment. It replaces third-party hosted document transformation services with 1P deterministic text normalization, grammatical span validation, and entity extraction algorithms developed in [dandye/nlp_capstone](https://github.com/dandye/nlp_capstone) (tracked as a git submodule in `external/nlp_capstone`).

## Core Capabilities

1. **Deterministic Text Normalization (`normalize_cti_document`)**:
   - Strips repeated boilerplate furniture (TLP banners, product IDs, pagination lines).
   - Rejoins line-wrapped hexadecimal hash fragments split across lines in PDF tables.
   - Detects code and script regions to suppress false positive indicator extraction.

2. **Grammatical Span Validation (`extract_and_validate_iocs`)**:
   - Strictly validates candidate indicators against domain grammars to eliminate noise.
   - Categorizes and validates:
     - IPv4 and IPv6 addresses (with octet range bounds checking).
     - File hashes (MD5, SHA1, SHA256, SHA512) verifying exact hex length.
     - Common Vulnerabilities and Exposures (CVE) IDs.
     - Common Weakness Enumeration (CWE) IDs.
     - MITRE ATT&CK Technique IDs (T-codes, e.g., `T1190`, `T1059.001`) and Tactic codes (TA-codes, e.g., `TA0001`).
     - TLP classification markings (`TLP:CLEAR`, `TLP:AMBER+STRICT`, `TLP:RED`).
     - Email addresses and domain names.
   - Automatically handles defanged indicator syntax (`1.2.3[.]4`, `hxxp://`, `user[@]domain[.]com`).

3. **In-Process Neural Entity Extraction (`extract_entities_with_securebert`)**:
   - Ingests text directly into memory (CPU) via `pzryathzsdhc/cti-ner-securebert` without external network overhead.
   - Extracts semantic CTI entities without strict deterministic grammars (threat actors, malware families, offensive hacking tools, affected products).
   - Uses sliding-window paragraph chunking and confidence score filtering.

4. **Multi-Format Document Parsing (`parse_security_document`)**:
   - Ingests local PDF files (via `pypdf`), HTML advisories (via `BeautifulSoup`), Markdown files, and plaintext documents.
   - Normalizes text and extracts categorized IOC collections in a single operation.

5. **Direct CISA Advisory Ingestion (`fetch_and_parse_cisa_advisory`)**:
   - Directly fetches CISA cybersecurity advisories by slug (e.g., `aa24-038a`) or URL, parses the HTML body, normalizes the text, and extracts structured IOCs.

6. **FastMCP Server & ADK Agent**:
   - Can be run as a standalone FastMCP server over STDIO or SSE.
   - Provides `create_cti_nlp_agent()` for immediate integration as an in-process Google ADK Specialist Agent.

## Architecture

```text
+-----------------------------------------------------------------------------------+
|                            Agentic SOC Architecture                               |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |             CTI Document & NER Specialist Agent (Google ADK)                |  |
|  +-----------------------------------------------------------------------------+  |
|         |                     |                             |             |       |
|         | 1. parse_doc        | 2. normalize_doc            | 3. fetch    | 4. bert
|         v                     v                             v             v       |
|  +-----------------------------------------------------------------------------+  |
|  |                1P CTI NLP FastMCP Server / In-Process Tools                 |  |
|  |                   (agent_soc_manager/tools/cti_nlp_tools.py)                |  |
|  +-----------------------------------------------------------------------------+  |
|         |                        |                     |                 |        |
|         | PDF / HTML / MD        | Text Normalizer     | Grammar IOCs    | In-Proc|
|         v                        v                     v                 v        |
|  +-----------------------+ +--------------------+ +------------------+ +--------+ |
|  | pypdf / BeautifulSoup | | nlp_capstone.ner   | | nlp_capstone.ner | | Secure | |
|  | Document Readers      | | .text_normalize    | | .span_validators | | BERT   | |
|  +-----------------------+ +--------------------+ +------------------+ +--------+ |
|                                                        |                 |        |
|                                                        v                 v        |
|                                                     +-------------------------------+
|                                                     | Categorized & Validated CTI   |
|                                                     | Threat Actors, Malware, IOCs  |
|                                                     +-------------------------------+
+-----------------------------------------------------------------------------------+
```

## CLI Usage

### Running Document Ingestion & IOC Extraction

```bash
# Parse a CISA advisory by slug:
.venv/bin/python investigations/run_cti_document_ingest.py --cisa aa24-038a

# Parse a local security report (PDF, MD, HTML):
.venv/bin/python investigations/run_cti_document_ingest.py --file /path/to/threat_report.pdf

# Normalize and extract from raw text:
.venv/bin/python investigations/run_cti_document_ingest.py --text "Observed C2 IP 198.51.100.22 targeting CVE-2024-1709 and technique T1190."

# Launch FastMCP Server (STDIO):
.venv/bin/python investigations/run_cti_document_ingest.py --serve --transport stdio

# Launch FastMCP Server (SSE on port 8000):
.venv/bin/python investigations/run_cti_document_ingest.py --serve --transport sse --port 8000
```

### Running Unit Tests

```bash
.venv/bin/pytest tests/test_cti_nlp_tools.py
```
