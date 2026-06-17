---
type: "Documentation"
title: "External Reference & Literature Catalog"
description: "Index and structural catalog of external research papers, industry standards, methodologies, and playbooks used to ground the Agentic SOC development."
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/docs/reference/README.md"
timestamp: "2026-06-17T20:30:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T20:30:00Z"
---

# External Reference & Literature Catalog

This directory serves as the centralized repository for external documentation, academic/industry research papers, best practices, and technical methodologies. Saving literature here allows both human engineers and AI agents to ground their designs and reasoning in established scientific and industry standards.

---

## 1. Directory Structure

To keep reference materials organized and easily searchable, please use the following directory layout:

```text
docs/reference/
├── README.md                 # This index and catalog catalog
├── papers/                   # Academic, corporate, or independent research papers (PDF, HTML, or Markdown summaries)
│   └── raw/                  # Subdirectory for raw source files (PDFs, EPUBs - Git ignored if large)
├── industry/                 # Standards and playbooks from recognized security and technology organizations
│   ├── cisa/                 # CISA security playbooks, directives, and operational standards
│   ├── gcp/                  # Google Cloud Platform security designs, IAM best practices, and blueprints
│   ├── mitre/                # MITRE ATT&CK, D3FEND, and Shield frameworks/research
│   └── nist/                 # NIST Special Publications (e.g., SP 800-61r2 for Incident Handling)
├── methodologies/            # Architectural patterns, algorithms, and design principles
│   ├── cognitive_agents/     # Cognitive architectures, agent-to-agent (A2A) networks, and prompt engineering
│   ├── graph_rag/            # Graph-based retrieval-augmented generation and Neo4j modeling
│   └── threat_hunting/       # Telemetry parsing, indicators of compromise (IOCs), and prevalence hunting
└── playbooks/                # Reference incident response playbooks, runbook templates, and disaster recovery plans
```

---

## 2. Catalog Index

Use the table below to index reference materials as you add them:

| Category | Title / Resource | Author / Source | Key Concepts | Local Path |
| :--- | :--- | :--- | :--- | :--- |
| **Cognitive Agents** | Vertex AI Agent Development Kit Documentation | Google Cloud | Reasoning Engines, Session Management, Agent Tooling | [adk_docs](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/docs/architecture.md) |
| **Graph RAG** | GraphRAG: Retrieval-Augmented Generation with Graphs | Microsoft Research | Entities correlation, global summarization, community detection | [papers/graph_rag.md](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/docs/reference/papers/graph_rag.md) (Placeholder) |
| **Incident Response** | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide | NIST | Triage, containment, eradication, and post-incident recovery | [industry/nist/sp_800_61_r2.md](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/docs/reference/industry/nist/sp_800_61_r2.md) (Placeholder) |

---

## 3. Best Practices for Saving References

To ensure maximum utility, follow these guidelines when adding materials:

1. **Create a Markdown Summary:** For every raw PDF, EPUB, or external web link, create a corresponding `.md` file in the appropriate subdirectory. The markdown file should contain:
   * **Metadata:** YAML frontmatter conforming to the Open Knowledge Format (OKF) with type "Documentation".
   * **Executive Summary:** A 2-3 paragraph synthesis of the resource.
   * **Key Takeaways for AI Agents:** Bullet points highlighting how the material applies to our SOC multi-agent architecture (e.g., "Use this prompt structure for reasoning...").
   * **Link to Source:** A clickable markdown link to the local raw file or the public URL.
2. **Track or Git-Ignore Large Files:** Small markdown summaries should always be committed. Large raw PDFs (greater than 5MB) should be added to the `.gitignore` under `docs/reference/*/raw/` to avoid bloating the repository size.
3. **Link to Agent System Prompts:** If a specific paper or standard dictates how an agent should operate, update the agent's instructions (e.g., in `agent.py`) to reference the local markdown file path (e.g., "Follow the containment principles documented in `docs/reference/industry/nist/sp_800_61_r2.md`").
