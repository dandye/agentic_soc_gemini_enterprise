---
type: "Evaluation Report"
title: "MLOps Experiment 004: Graph RAG & Cypher Translation Hardening"
description: "Proposing a systematic prompt optimization campaign to inject structural schema context and few-shot examples into the Threat Hunter specialist to eliminate Neo4j Cypher syntax errors and optimize graph traversals."
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/experiments/004_graph_rag_cypher_hardening.md"
timestamp: "2026-06-17T20:26:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T20:26:00Z"
---

# MLOps Experiment 004: Graph RAG & Cypher Translation Hardening

## 1. Context & Problem Statement
The integration of the Neo4j Security Operations Graph Database (`query_neo4j_graph` tool) has significantly enhanced the agent's ability to correlate entities and trace complex attack paths (e.g., matching users to compromised hosts, and identifying lateral movement vectors). However, our evaluations show that:
*   **The Issue:** The Threat Hunter and Orchestrator frequently generate syntactically incorrect Cypher queries (e.g., using SQL-style syntax, using invalid node labels, or referencing non-existent relationship directions).
*   **The Impact:** When a Cypher query fails with a syntax error, the agent must spend multiple turns attempting to correct its query or, worse, fallback to empty/incorrect conclusions. This increases token overhead, increases latency, and degrades the overall scorecard.
*   **The Root Cause:** The Threat Hunter's system prompt does not contain a formal definition of the active Neo4j graph schema, leaving the agent to guess the node labels (Host, User, File, etc.) and relationship types (LOGGED_ON_TO, CONNECTED_TO).

---

## 2. Hypothesis & Goals
*   **Target Agent:** Threat Hunter (`agent_a2a_threat_hunter`) & Orchestrator (`agent_soc_manager`)
*   **Evaluation Set:** Threat Hunting (`threat_hunting.evalset.json`)
*   **Hypothesis:** If we inject a formal structural graph schema context block and three high-quality few-shot Cypher translation examples into the Threat Hunter's system instructions, then we will eliminate 100% of Cypher syntax errors and optimize graph query efficiency, reducing turn footprints by 40%+ and lifting the threat hunting scorecard to **90.0%+**.
*   **Target Score:** **90.0%+**

---

## 3. Implementation Plan
*   **Variables to Modify:** Threat Hunter system prompt in `agent_a2a_threat_hunter/agent.py`
*   **Proposed Prompt Addition (Schema & Few-Shot Context):**
    ```markdown
    ### NEO4J GRAPH DATABASE SCHEMA CONTEXT:
    Use the following schema definitions to construct highly accurate, read-only Cypher queries. Do NOT guess labels or relationship types.

    **Nodes:**
    - `Host` {name: "WRK-...", ip: "..."}
    - `User` {name: "john.doe", role: "..."}
    - `File` {name: "payload.exe", sha256: "..."}
    - `Domain` {name: "malicious.com"}
    - `Alert` {id: "...", name: "..."}
    - `Investigation` {id: "...", verdict: "..."}

    **Relationships:**
    - `(u:User)-[:LOGGED_ON_TO]->(h:Host)`
    - `(h:Host)-[:CONNECTED_TO]->(d:Domain)`
    - `(i:Investigation)-[:INVOLVES]->(h:Host|u:User|f:File)`
    - `(a:Alert)-[:TRIGGERED_ON]->(h:Host)`

    **Few-Shot Examples:**
    1. Query: Check what hosts the user michelle.wright logged on to.
       Cypher: MATCH (u:User {name: 'michelle.wright'})-[:LOGGED_ON_TO]->(h:Host) RETURN h.name, h.ip
    2. Query: Find if there are any active investigations involving the file avl.exe.
       Cypher: MATCH (f:File {name: 'avl.exe'})<-[:INVOLVES]-(i:Investigation) RETURN i.id, i.verdict
    3. Query: Trace domain connections from host WRK-PACMAN.
       Cypher: MATCH (h:Host {name: 'WRK-PACMAN'})-[:CONNECTED_TO]->(d:Domain) RETURN d.name
    ```

---

## 4. Empirical Results & Scorecard
*   **New Commit:** `ee20b6f` (with prompt hardening)
*   **New Score:** **100.0%** (Proactive Threat Hunting Workflows scorecard)
*   **Score Delta:** **+60.7%** (compared to the baseline `3836bd4` score of 39.3%)
*   **Raw Run Ledger:** [report_threat_hunting_20260617T213651Z_ee20b6f.md](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_threat_hunting_20260617T213651Z_ee20b6f.md)

### Trajectory Turn Footprint Comparison:
*   **Before Hardening (Commit `3836bd4`):**
    *   **Case 1 (C2 Beaconing):** The agent was caught in a correction loop, calling `query_neo4j_graph` 4 times with syntax errors before failing back to search.
    *   **Case 2 (AD Lateral Movement):** The agent called `query_neo4j_graph` **9 times** in a row trying to recover from syntax errors, consuming excessive tokens and causing massive latency.
*   **After Hardening (Commit `ee20b6f`):**
    *   **Case 1 (C2 Beaconing):** The agent called `query_neo4j_graph` exactly 3 times. All queries were syntactically correct. It resolved the nodes, recognized they weren't in the graph, and pivoted to SIEM cleanly.
    *   **Case 2 (AD Lateral Movement):** The agent called `query_neo4j_graph` **exactly 2 times**! The queries were perfect on the first try, leading to an **unbelievable 78% reduction in graph query turn footprint**!

---

## 5. Conclusion & Action Items
*   **Verdict:** **SUCCESS (Highly Recommended)**
*   **Findings:**
    1. Injecting the formal Neo4j graph schema context and few-shot translation examples completely eliminated Cypher query syntax errors.
    2. Escaping the curly braces `{{}}` inside the Orchestrator's f-string instructions resolved all Python compilation/interpolation issues.
    3. Providing structural query patterns allowed the agent to retrieve graph relationships directly, reducing query turns by **78%** on lateral movement tracing.
*   **Next Steps:** Proceed to **Experiment 005: Concurrent Specialist Delegation** to optimize multi-agent orchestration and latency.
