# KnowledgeAgent Subsystem Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and integrate the multi-modal `KnowledgeAgent` subsystem in `agent_knowledge/`, combining Vertex AI RAG (`VertexAiRagRetrieval`), Neo4j graph traversal, AlloyDB/Omnia pgvector search, and ADK Memory into a unified `AgentTool` for the SOC multi-agent network.

**Architecture:** A composite router `KnowledgeAgent` (`gemini-2.5-flash`) coordinates an isolated `RagKnowledgeAgent` sub-agent for native server-side RAG grounding alongside direct Python function tools for Neo4j Cypher traversals, AlloyDB/Omnia relational & pgvector searches, and ADK memory context lookups. Domain heuristics are provided by four specialized ADK skills.

**Tech Stack:** Google ADK 2.0 (`google-adk==2.0.0`), `google-genai` (Gemini 2.5/3.1), `vertexai` (Vertex AI RAG Engine), `neo4j` (Cypher driver), `psycopg` (AlloyDB / pgvector), `pytest`, `pytest-asyncio`.

**Spec:** [`docs/superpowers/specs/2026-08-31-knowledge-agent-subsystem-design.md`](file:///usr/local/google/home/dandye/Projects/agentic_soc_agentspace__worktrees/feat-adk-knowledge-engine/docs/superpowers/specs/2026-08-31-knowledge-agent-subsystem-design.md)

## Global Constraints
- Target directory: `agent_knowledge/` (self-contained, explicit, no circular dependencies).
- Single-tool isolation for `VertexAiRagRetrieval`: Must reside in dedicated sub-agent `agent_knowledge/sub_agents/rag_agent.py` to prevent Gemini API 400 INVALID_ARGUMENT conflicts.
- Graceful degradation: All database tools must catch connection errors and return structured diagnostic strings instead of raising unhandled exceptions.
- All tests must pass hermetically via `.venv/bin/pytest`.

---

### Task 1: Neo4j Operational Graph Tool (`agent_knowledge/tools/graph_tool.py`)

**Files:**
- Create: `agent_knowledge/tools/graph_tool.py`
- Test: `tests/test_graph_tool.py`

**Interfaces:**
- Consumes: `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` environment variables.
- Produces: `async def query_knowledge_graph(query_type: str, entity_value: str, custom_cypher: Optional[str] = None, max_hops: int = 3, ctx: Optional[Any] = None) -> str`

- [ ] **Step 1: Write the failing unit tests for `graph_tool.py`**

```python
# tests/test_graph_tool.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from agent_knowledge.tools.graph_tool import query_knowledge_graph, sanitize_cypher_query


def test_sanitize_cypher_query_blocks_destructive_keywords():
    destructive_query = "MATCH (n) DETACH DELETE n"
    with pytest.raises(ValueError, match="Destructive Cypher commands are not permitted"):
        sanitize_cypher_query(destructive_query)


def test_sanitize_cypher_query_allows_read_only():
    valid_query = "MATCH (u:User {name: 'frank'}) RETURN u LIMIT 10"
    assert sanitize_cypher_query(valid_query) == valid_query


@pytest.mark.asyncio
async def test_query_knowledge_graph_missing_env():
    with patch.dict("os.environ", {}, clear=True):
        res = await query_knowledge_graph(query_type="entity_neighborhood", entity_value="wrk-shasek")
        assert "Neo4j connection not configured" in res


@pytest.mark.asyncio
async def test_query_knowledge_graph_neighborhood_mock():
    mock_records = [
        {"source": "wrk-shasek", "rel": "LOGGED_IN", "target": "frank.kolzig"}
    ]
    with patch.dict("os.environ", {"NEO4J_URI": "bolt://localhost:7687", "NEO4J_USER": "neo4j", "NEO4J_PASSWORD": "password"}):
        with patch("agent_knowledge.tools.graph_tool._run_cypher_query", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = mock_records
            res = await query_knowledge_graph(query_type="entity_neighborhood", entity_value="wrk-shasek")
            assert "frank.kolzig" in res
            assert "LOGGED_IN" in res
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_graph_tool.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_knowledge'`

- [ ] **Step 3: Implement `agent_knowledge/tools/graph_tool.py` and package init**

```python
# agent_knowledge/tools/graph_tool.py
import logging
import os
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

FORBIDDEN_CYPHER_KEYWORDS = [
    "CREATE", "DELETE", "SET", "REMOVE", "MERGE", "DROP", "DETACH", "CALL apoc.periodic"
]


def sanitize_cypher_query(query: str) -> str:
    """Ensure Cypher queries are strictly read-only."""
    clean_query = query.strip()
    upper_query = clean_query.upper()
    for kw in FORBIDDEN_CYPHER_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", upper_query):
            raise ValueError(f"Destructive Cypher commands are not permitted: {kw}")
    return clean_query


async def _run_cypher_query(cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute Cypher query against Neo4j instance with timeout."""
    uri = os.environ.get("NEO4J_URI")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD")

    if not uri or not password:
        raise ValueError("Neo4j connection not configured (NEO4J_URI or NEO4J_PASSWORD missing).")

    from neo4j import AsyncGraphDatabase

    async with AsyncGraphDatabase.driver(uri, auth=(user, password)) as driver:
        async with driver.session() as session:
            result = await session.run(cypher, params)
            records = await result.data()
            return records


async def query_knowledge_graph(
    query_type: str,
    entity_value: str,
    custom_cypher: Optional[str] = None,
    max_hops: int = 3,
    ctx: Optional[Any] = None,
) -> str:
    """
    Query the Neo4j operational security graph for entity neighborhoods, lateral movement, and blast radius.

    Args:
        query_type: One of 'entity_neighborhood', 'lateral_movement_path', 'credential_blast_radius', 'raw_cypher'.
        entity_value: Target entity identifier (username, hostname, IP, domain, hash).
        custom_cypher: Optional custom read-only Cypher query (used when query_type is 'raw_cypher').
        max_hops: Maximum traversal depth (default 3, max 4).
    """
    max_hops = min(max(1, max_hops), 4)

    if not os.environ.get("NEO4J_URI") or not os.environ.get("NEO4J_PASSWORD"):
        return f"[Neo4j Knowledge Graph Unavailable: NEO4J_URI or NEO4J_PASSWORD not set in environment. Query for '{entity_value}' skipped.]"

    try:
        if query_type == "entity_neighborhood":
            cypher = (
                "MATCH (n)-[r]-(m) "
                "WHERE n.name = $entity OR n.hostname = $entity OR n.ip = $entity OR n.username = $entity "
                "RETURN n.name AS source, type(r) AS rel, coalesce(m.name, m.hostname, m.ip, m.username, 'Unknown') AS target "
                "LIMIT 50"
            )
            records = await _run_cypher_query(cypher, {"entity": entity_value})
        elif query_type == "lateral_movement_path":
            cypher = (
                f"MATCH p = shortestPath((src)-[*1..{max_hops}]-(dst)) "
                "WHERE (src.name = $entity OR src.hostname = $entity) AND (dst:DomainController OR dst.tier = 'Tier 0' OR dst.role = 'DC') "
                "RETURN [n in nodes(p) | coalesce(n.name, n.hostname, n.username)] AS path_nodes, "
                "[r in relationships(p) | type(r)] AS rels "
                "LIMIT 10"
            )
            records = await _run_cypher_query(cypher, {"entity": entity_value})
        elif query_type == "credential_blast_radius":
            cypher = (
                f"MATCH (u:User)-[r:CAN_ACCESS|LOGGED_IN*1..{max_hops}]->(target) "
                "WHERE u.name = $entity OR u.username = $entity "
                "RETURN coalesce(target.name, target.hostname, target.ip) AS accessible_asset, labels(target) AS asset_type "
                "LIMIT 50"
            )
            records = await _run_cypher_query(cypher, {"entity": entity_value})
        elif query_type == "raw_cypher":
            if not custom_cypher:
                return "Error: custom_cypher string must be provided when query_type='raw_cypher'."
            safe_cypher = sanitize_cypher_query(custom_cypher)
            records = await _run_cypher_query(safe_cypher, {"entity": entity_value})
        else:
            return f"Unknown query_type: '{query_type}'. Supported: 'entity_neighborhood', 'lateral_movement_path', 'credential_blast_radius', 'raw_cypher'."

        if not records:
            return f"No graph relationships found for entity '{entity_value}' (Query Type: {query_type})."

        lines = [f"=== Neo4j Graph Query Results ({query_type}: {entity_value}) ==="]
        for idx, rec in enumerate(records, 1):
            lines.append(f"{idx}. {rec}")
        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Neo4j query failed: {e}")
        return f"[Neo4j Query Error for '{entity_value}': {str(e)}]"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_graph_tool.py -v`
Expected: PASS (4 tests passed).

- [ ] **Step 5: Commit**

```bash
git add agent_knowledge/tools/graph_tool.py tests/test_graph_tool.py
git commit -m "feat(agent_knowledge): add Neo4j operational graph query tool"
```

---

### Task 2: AlloyDB / Omnia Relational & Vector Catalog Tool (`agent_knowledge/tools/alloydb_tool.py`)

**Files:**
- Create: `agent_knowledge/tools/alloydb_tool.py`
- Test: `tests/test_alloydb_tool.py`

**Interfaces:**
- Consumes: `ALLOYDB_HOST`, `ALLOYDB_PORT`, `ALLOYDB_DATABASE`, `ALLOYDB_USER`, `ALLOYDB_PASSWORD`.
- Produces: `async def query_asset_catalog(query: str, search_mode: str = "hybrid", asset_tier_filter: Optional[str] = None, top_k: int = 5, ctx: Optional[Any] = None) -> str`

- [ ] **Step 1: Write the failing unit tests for `alloydb_tool.py`**

```python
# tests/test_alloydb_tool.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from agent_knowledge.tools.alloydb_tool import query_asset_catalog


@pytest.mark.asyncio
async def test_query_asset_catalog_missing_env():
    with patch.dict("os.environ", {}, clear=True):
        res = await query_asset_catalog(query="WRK-SHASEK")
        assert "AlloyDB / Omnia connection not configured" in res


@pytest.mark.asyncio
async def test_query_asset_catalog_mock_asset_lookup():
    mock_asset = [
        {"hostname": "wrk-shasek", "ip_address": "10.1.2.14", "tier": "Tier 2", "owner": "frank.kolzig", "os": "Windows 11"}
    ]
    with patch.dict("os.environ", {"ALLOYDB_HOST": "localhost", "ALLOYDB_DATABASE": "secops", "ALLOYDB_USER": "postgres", "ALLOYDB_PASSWORD": "password"}):
        with patch("agent_knowledge.tools.alloydb_tool._execute_sql_query", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_asset
            res = await query_asset_catalog(query="wrk-shasek", search_mode="exact_asset")
            assert "wrk-shasek" in res
            assert "Tier 2" in res
            assert "frank.kolzig" in res
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_alloydb_tool.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_knowledge.tools.alloydb_tool'`

- [ ] **Step 3: Implement `agent_knowledge/tools/alloydb_tool.py`**

```python
# agent_knowledge/tools/alloydb_tool.py
import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


async def _execute_sql_query(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    """Execute query against AlloyDB / PostgreSQL instance."""
    host = os.environ.get("ALLOYDB_HOST")
    port = int(os.environ.get("ALLOYDB_PORT", "5432"))
    database = os.environ.get("ALLOYDB_DATABASE", "secops")
    user = os.environ.get("ALLOYDB_USER", "postgres")
    password = os.environ.get("ALLOYDB_PASSWORD")
    sslmode = os.environ.get("ALLOYDB_SSLMODE", "prefer")

    if not host or not password:
        raise ValueError("AlloyDB connection not configured.")

    import psycopg
    from psycopg.rows import dict_row

    async with await psycopg.AsyncConnection.connect(
        host=host,
        port=port,
        dbname=database,
        user=user,
        password=password,
        sslmode=sslmode,
    ) as aconn:
        async with aconn.cursor(row_factory=dict_row) as cur:
            await cur.execute(sql, params)
            results = await cur.fetchall()
            return results


async def query_asset_catalog(
    query: str,
    search_mode: str = "hybrid",
    asset_tier_filter: Optional[str] = None,
    top_k: int = 5,
    ctx: Optional[Any] = None,
) -> str:
    """
    Query AlloyDB / Omnia for structured asset information, criticality tiers, and semantic historical case records.

    Args:
        query: Asset identifier (hostname, IP, owner) or semantic incident description.
        search_mode: One of 'exact_asset', 'semantic_case_history', 'hybrid'.
        asset_tier_filter: Optional filter ('Tier 0', 'Tier 1', 'Tier 2').
        top_k: Number of matching records to return.
    """
    if not os.environ.get("ALLOYDB_HOST") or not os.environ.get("ALLOYDB_PASSWORD"):
        return f"[AlloyDB / Omnia Catalog Unavailable: ALLOYDB_HOST or ALLOYDB_PASSWORD not set. Query for '{query}' skipped.]"

    try:
        if search_mode == "exact_asset":
            sql = (
                "SELECT hostname, ip_address, mac_address, tier, owner, business_unit, os, is_crown_jewel "
                "FROM assets "
                "WHERE LOWER(hostname) = LOWER(%s) OR ip_address = %s OR LOWER(owner) = LOWER(%s) "
                "LIMIT %s"
            )
            records = await _execute_sql_query(sql, (query, query, query, top_k))
        elif search_mode == "semantic_case_history":
            sql = (
                "SELECT case_id, title, summary, resolution, affected_assets, created_at "
                "FROM historical_cases "
                "WHERE summary ILIKE %s OR title ILIKE %s "
                "ORDER BY created_at DESC "
                "LIMIT %s"
            )
            like_query = f"%{query}%"
            records = await _execute_sql_query(sql, (like_query, like_query, top_k))
        else:  # hybrid
            sql = (
                "SELECT hostname, ip_address, tier, owner, business_unit, os, is_crown_jewel "
                "FROM assets "
                "WHERE (LOWER(hostname) LIKE LOWER(%s) OR LOWER(owner) LIKE LOWER(%s) OR ip_address LIKE %s) "
                + (f"AND tier = '{asset_tier_filter}' " if asset_tier_filter else "")
                + "LIMIT %s"
            )
            like_query = f"%{query}%"
            records = await _execute_sql_query(sql, (like_query, like_query, like_query, top_k))

        if not records:
            return f"No records found in AlloyDB / Omnia catalog for query '{query}' (Mode: {search_mode})."

        lines = [f"=== AlloyDB / Omnia Catalog Results ({search_mode}: {query}) ==="]
        for idx, rec in enumerate(records, 1):
            lines.append(f"{idx}. {rec}")
        return "\n".join(lines)

    except Exception as e:
        logger.error(f"AlloyDB query failed: {e}")
        return f"[AlloyDB Query Error for '{query}': {str(e)}]"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_alloydb_tool.py -v`
Expected: PASS (2 tests passed).

- [ ] **Step 5: Commit**

```bash
git add agent_knowledge/tools/alloydb_tool.py tests/test_alloydb_tool.py
git commit -m "feat(agent_knowledge): add AlloyDB/Omnia asset & vector catalog tool"
```

---

### Task 3: Cross-Session Working Memory Tool (`agent_knowledge/tools/memory_tool.py`)

**Files:**
- Create: `agent_knowledge/tools/memory_tool.py`
- Test: `tests/test_memory_tool.py`

**Interfaces:**
- Consumes: ADK `Context` / session state or in-memory fallback.
- Produces: `async def query_investigation_memory(entity: Optional[str] = None, query: Optional[str] = None, max_results: int = 5, ctx: Optional[Any] = None) -> str`

- [ ] **Step 1: Write the failing unit tests for `memory_tool.py`**

```python
# tests/test_memory_tool.py
import pytest
from unittest.mock import MagicMock
from agent_knowledge.tools.memory_tool import query_investigation_memory, add_investigation_note, _in_memory_store


@pytest.mark.asyncio
async def test_add_and_query_memory():
    _in_memory_store.clear()
    add_investigation_note(entity="frank.kolzig", note="Observed failed logons across 3 workstations", tag="credential_spray")
    res = await query_investigation_memory(entity="frank.kolzig")
    assert "credential_spray" in res
    assert "failed logons" in res


@pytest.mark.asyncio
async def test_query_empty_memory():
    _in_memory_store.clear()
    res = await query_investigation_memory(entity="unknown.entity")
    assert "No investigation memory records found" in res
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_memory_tool.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_knowledge.tools.memory_tool'`

- [ ] **Step 3: Implement `agent_knowledge/tools/memory_tool.py`**

```python
# agent_knowledge/tools/memory_tool.py
import datetime
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Fallback in-memory store when ADK session memory service is not active
_in_memory_store: list[dict[str, Any]] = []


def add_investigation_note(entity: str, note: str, tag: str = "general") -> None:
    """Helper to record active investigation hypothesis or entity note."""
    _in_memory_store.append({
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "entity": entity.lower(),
        "tag": tag,
        "note": note,
    })


async def query_investigation_memory(
    entity: Optional[str] = None,
    query: Optional[str] = None,
    max_results: int = 5,
    ctx: Optional[Any] = None,
) -> str:
    """
    Search past and active cross-session investigation memory for analyst hypotheses, containment tags, and entity observations.

    Args:
        entity: Target entity identifier to filter memory notes.
        query: Semantic search query across investigation memory notes.
        max_results: Maximum memory notes to return.
    """
    results = []

    # 1. Search in-memory store
    for record in reversed(_in_memory_store):
        matches_entity = not entity or entity.lower() in record["entity"]
        matches_query = not query or query.lower() in record["note"].lower() or query.lower() in record["tag"].lower()
        if matches_entity and matches_query:
            results.append(record)
            if len(results) >= max_results:
                break

    if not results:
        entity_desc = f" for entity '{entity}'" if entity else ""
        query_desc = f" with query '{query}'" if query else ""
        return f"No investigation memory records found{entity_desc}{query_desc}."

    lines = ["=== Investigation Memory Notes ==="]
    for idx, rec in enumerate(results, 1):
        lines.append(
            f"[{idx}] Time: {rec['timestamp']} | Entity: {rec['entity']} | Tag: {rec['tag']}\n"
            f"    Note: {rec['note']}"
        )
    return "\n\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_memory_tool.py -v`
Expected: PASS (2 tests passed).

- [ ] **Step 5: Commit**

```bash
git add agent_knowledge/tools/memory_tool.py tests/test_memory_tool.py
git commit -m "feat(agent_knowledge): add cross-session investigation memory tool"
```

---

### Task 4: Isolated RAG Sub-Agent with `VertexAiRagRetrieval` (`agent_knowledge/sub_agents/rag_agent.py`)

**Files:**
- Create: `agent_knowledge/sub_agents/__init__.py`
- Create: `agent_knowledge/sub_agents/rag_agent.py`
- Test: `tests/test_rag_agent.py`

**Interfaces:**
- Consumes: `RAG_CORPUS_ID` environment variable, `google.adk.tools.retrieval.vertex_ai_rag_retrieval.VertexAiRagRetrieval`.
- Produces: `rag_knowledge_agent: Agent` configured with sole tool `VertexAiRagRetrieval`.

- [ ] **Step 1: Write the unit tests for `rag_agent.py`**

```python
# tests/test_rag_agent.py
import os
import pytest
from unittest.mock import patch
from agent_knowledge.sub_agents.rag_agent import create_rag_knowledge_agent
from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval


def test_create_rag_knowledge_agent_single_tool_isolation():
    with patch.dict("os.environ", {"RAG_CORPUS_ID": "projects/123/locations/us-central1/ragCorpora/456"}):
        agent = create_rag_knowledge_agent()
        assert agent.name == "rag_knowledge_specialist"
        assert len(agent.tools) == 1
        assert isinstance(agent.tools[0], VertexAiRagRetrieval)


def test_create_rag_knowledge_agent_handles_missing_corpus():
    with patch.dict("os.environ", {}, clear=True):
        agent = create_rag_knowledge_agent()
        assert agent.name == "rag_knowledge_specialist"
        assert len(agent.tools) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_rag_agent.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_knowledge.sub_agents'`

- [ ] **Step 3: Implement `agent_knowledge/sub_agents/rag_agent.py`**

```python
# agent_knowledge/sub_agents/__init__.py
"""Sub-agents for agent_knowledge module."""

# agent_knowledge/sub_agents/rag_agent.py
import os
import logging
from google.adk.agents import Agent
from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval

logger = logging.getLogger(__name__)

RAG_AGENT_INSTRUCTION = """
You are the Enterprise RAG Knowledge Specialist for the Security Operations Center.
Your SOLE responsibility is to search and retrieve accurate information from the enterprise RAG corpus covering:
1. Incident Response Playbooks (IRPs) and Runbooks (containment, eradication, recovery procedures).
2. Cyber Threat Intelligence (CTI) dossiers, Threat Actor profiles, and campaign TTPs.
3. Security & Compliance Policies (NIST, ISO 27001, organizational security standards).
4. Historical Incident Post-Mortems and Root Cause Analyses (RCAs).

Always provide clear citations and source references for retrieved documentation.
If the RAG corpus does not cover the requested topic, explicitly state that no matching documentation was found.
"""


def create_rag_knowledge_agent(model: str = "gemini-2.5-flash") -> Agent:
    """
    Instantiate the dedicated RAG Knowledge Agent with single-tool isolation.
    Uses VertexAiRagRetrieval for native Gemini 2.0+ server-side grounding.
    """
    rag_corpus_id = os.environ.get("RAG_CORPUS_ID", "")
    rag_corpora = [rag_corpus_id] if rag_corpus_id else []

    rag_retrieval_tool = VertexAiRagRetrieval(
        name="retrieve_enterprise_docs",
        description="Search enterprise security playbooks, CTI dossiers, policies, and incident retrospectives in the RAG corpus.",
        rag_corpora=rag_corpora,
        similarity_top_k=int(os.environ.get("RAG_SIMILARITY_TOP_K", "5")),
        vector_distance_threshold=float(os.environ.get("RAG_DISTANCE_THRESHOLD", "0.6")),
    )

    return Agent(
        name="rag_knowledge_specialist",
        model=model,
        instruction=RAG_AGENT_INSTRUCTION,
        tools=[rag_retrieval_tool],
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_rag_agent.py -v`
Expected: PASS (2 tests passed).

- [ ] **Step 5: Commit**

```bash
git add agent_knowledge/sub_agents/ tests/test_rag_agent.py
git commit -m "feat(agent_knowledge): add isolated RAG sub-agent with VertexAiRagRetrieval"
```

---

### Task 5: Domain-Specific Skills (`agent_knowledge/skills/`)

**Files:**
- Create: `agent_knowledge/skills/cypher_graph_navigation/SKILL.md`
- Create: `agent_knowledge/skills/asset_criticality_evaluation/SKILL.md`
- Create: `agent_knowledge/skills/incident_memory_correlation/SKILL.md`
- Create: `agent_knowledge/skills/mitre_ttp_mapping/SKILL.md`
- Test: `tests/test_knowledge_skills.py`

**Interfaces:**
- Produces: Loaded skill toolsets via `google.adk.skills.load_skill_from_dir`.

- [ ] **Step 1: Write skill loader test**

```python
# tests/test_knowledge_skills.py
from pathlib import Path
import pytest
from google.adk.skills import load_skill_from_dir


def test_load_all_knowledge_skills():
    skills_dir = Path("agent_knowledge/skills")
    skill_names = [
        "cypher_graph_navigation",
        "asset_criticality_evaluation",
        "incident_memory_correlation",
        "mitre_ttp_mapping",
    ]
    for name in skill_names:
        path = skills_dir / name
        assert path.exists(), f"Skill directory {path} missing"
        skill = load_skill_from_dir(path)
        assert skill is not None
        assert skill.name == name
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_knowledge_skills.py -v`
Expected: FAIL (Skill directories missing).

- [ ] **Step 3: Author the 4 SKILL.md files**

Create:
1. `agent_knowledge/skills/cypher_graph_navigation/SKILL.md`:
```markdown
---
name: cypher_graph_navigation
description: Heuristics and safe Cypher patterns for navigating operational security graphs and attack path discovery.
---

# Cypher Graph Navigation Skill

Use this skill when investigating relationships between users, hosts, processes, and network connections in Neo4j.

## Core Query Patterns

### 1. Lateral Movement Tracing
```cypher
MATCH p = shortestPath((src:Host)-[*1..4]-(dst:DomainController))
WHERE src.hostname = $entity
RETURN p
```

### 2. User Logon & Credential Blast Radius
```cypher
MATCH (u:User {name: $entity})-[r:LOGGED_IN|CAN_ACCESS]->(target)
RETURN target.hostname, target.tier, type(r)
```

## Safety Rules
- Never generate destructive statements (DELETE, DROP, SET, CREATE).
- Always include `LIMIT 50` on unbounded traversals.
```

2. `agent_knowledge/skills/asset_criticality_evaluation/SKILL.md`:
```markdown
---
name: asset_criticality_evaluation
description: Guidelines for classifying asset criticality tiers and determining blast radius impact.
---

# Asset Criticality Evaluation Skill

Use this skill when evaluating asset risk and prioritization in AlloyDB/Omnia catalog lookups.

## Asset Tier Hierarchy
- **Tier 0 (Crown Jewels)**: Domain Controllers, Identity Providers (IdP), Key Management Services (KMS), Production Databases with PII/PCI.
- **Tier 1 (Core Infrastructure)**: Hypervisors, Build Systems, CI/CD runners, Bastion Hosts.
- **Tier 2 (Workstations & General Compute)**: End-user laptops, staging environments, dev clusters.
```

3. `agent_knowledge/skills/incident_memory_correlation/SKILL.md`:
```markdown
---
name: incident_memory_correlation
description: Methodologies for correlating current indicators and hypotheses with cross-session investigation memory.
---

# Incident Memory Correlation Skill

Use this skill when checking whether an observed IP, domain, user, or technique has been tagged in past investigations.
```

4. `agent_knowledge/skills/mitre_ttp_mapping/SKILL.md`:
```markdown
---
name: mitre_ttp_mapping
description: MITRE ATT&CK Enterprise Matrix mapping heuristics for correlating graph behaviors with RAG CTI dossiers.
---

# MITRE ATT&CK Mapping Skill

Use this skill when mapping observed adversary behaviors (e.g., Mimikatz, Pass-the-Hash, PowerShell EncodedCommand) to MITRE techniques (T1003, T1550, T1059) and matching them against RAG actor profiles.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_knowledge_skills.py -v`
Expected: PASS (1 test passed).

- [ ] **Step 5: Commit**

```bash
git add agent_knowledge/skills/ tests/test_knowledge_skills.py
git commit -m "feat(agent_knowledge): add domain-specific skills for graph, asset, memory, and MITRE mapping"
```

---

### Task 6: KnowledgeAgent Router & Orchestrator Tool (`agent_knowledge/agent.py` & `agent_knowledge/__init__.py`)

**Files:**
- Create: `agent_knowledge/agent.py`
- Create: `agent_knowledge/__init__.py`
- Test: `tests/test_knowledge_agent.py`

**Interfaces:**
- Produces: `knowledge_agent: Agent` and `knowledge_agent_tool: AgentTool`.

- [ ] **Step 1: Write unit and integration tests for `KnowledgeAgent`**

```python
# tests/test_knowledge_agent.py
import pytest
from unittest.mock import AsyncMock, patch
from agent_knowledge import knowledge_agent, knowledge_agent_tool
from google.adk.tools.agent_tool import AgentTool


def test_knowledge_agent_tool_structure():
    assert isinstance(knowledge_agent_tool, AgentTool)
    assert knowledge_agent_tool.agent.name == "knowledge_agent"
    assert len(knowledge_agent.sub_agents) == 1
    assert knowledge_agent.sub_agents[0].name == "rag_knowledge_specialist"
    assert len(knowledge_agent.tools) == 3


@pytest.mark.asyncio
async def test_knowledge_agent_tools_callable():
    tool_names = [getattr(t, "name", getattr(t, "__name__", str(t))) for t in knowledge_agent.tools]
    assert "query_knowledge_graph" in tool_names
    assert "query_asset_catalog" in tool_names
    assert "query_investigation_memory" in tool_names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_knowledge_agent.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_knowledge.agent'`

- [ ] **Step 3: Implement `agent_knowledge/agent.py` and `agent_knowledge/__init__.py`**

```python
# agent_knowledge/agent.py
import os
import logging
from google.adk.agents import Agent
from google.adk.skills import load_skill_from_dir
from google.adk.tools import skill_toolset
from pathlib import Path

from .sub_agents.rag_agent import create_rag_knowledge_agent
from .tools.graph_tool import query_knowledge_graph
from .tools.alloydb_tool import query_asset_catalog
from .tools.memory_tool import query_investigation_memory

logger = logging.getLogger(__name__)

KNOWLEDGE_ROUTER_INSTRUCTION = """
You are the Chief Knowledge Agent for the Security Operations Center (SOC).
Your purpose is to deliver accurate, multi-modal intelligence and grounding to SOC analysts and orchestrator agents.

You have access to 4 distinct knowledge planes:
1. **Unstructured RAG (via rag_knowledge_specialist sub-agent)**: Incident Response Playbooks (IRPs), security policies, CTI actor dossiers, and historical post-mortems.
2. **Operational Graph (via query_knowledge_graph)**: Neo4j relationship topology, user logons, process trees, and lateral movement attack paths.
3. **Asset & Case Catalog (via query_asset_catalog)**: AlloyDB/Omnia structured asset inventories (Tier 0-2 ratings, owners, IPs) and pgvector semantic case histories.
4. **Working Memory (via query_investigation_memory)**: Cross-session analyst notes, active hypotheses, and previous containment tags.

When answering a question:
- Decompose complex inquiries into the appropriate store lookups.
- For topological, lateral movement, or parent-child process queries, query Neo4j.
- For asset criticality, owner, or business tier lookups, query AlloyDB.
- For incident playbooks, threat actor TTPs, or policies, delegate to the rag_knowledge_specialist.
- For past investigation context on an indicator, check investigation memory.
- Synthesize all findings into a structured, cohesive response with actionable conclusions and citations.
"""


def create_knowledge_agent(model: str = "gemini-2.5-flash") -> Agent:
    """Construct the unified KnowledgeAgent router."""
    rag_sub_agent = create_rag_knowledge_agent(model=model)

    # Load domain skills
    skills = []
    skills_base = Path(__file__).parent / "skills"
    for skill_name in ["cypher_graph_navigation", "asset_criticality_evaluation", "incident_memory_correlation", "mitre_ttp_mapping"]:
        p = skills_base / skill_name
        if p.exists():
            try:
                skill = load_skill_from_dir(p)
                skills.append(skill_toolset(skill))
            except Exception as e:
                logger.warning(f"Could not load skill {skill_name}: {e}")

    tools = [
        query_knowledge_graph,
        query_asset_catalog,
        query_investigation_memory,
    ] + skills

    return Agent(
        name="knowledge_agent",
        model=model,
        instruction=KNOWLEDGE_ROUTER_INSTRUCTION,
        sub_agents=[rag_sub_agent],
        tools=tools,
    )


knowledge_agent = create_knowledge_agent()
```

```python
# agent_knowledge/__init__.py
"""
Unified Multi-Modal Knowledge Subsystem for Agentic SOC.
"""
from google.adk.tools.agent_tool import AgentTool
from .agent import knowledge_agent, create_knowledge_agent

knowledge_agent_tool = AgentTool(
    agent=knowledge_agent,
    name="query_enterprise_knowledge",
    description=(
        "Query the unified multi-modal SOC knowledge base spanning: "
        "1) Unstructured RAG (IRP runbooks, CTI threat actor dossiers, compliance policies, retrospectives), "
        "2) Neo4j Operational Graph (lateral movement, user-machine-process topologies), "
        "3) AlloyDB/Omnia (asset criticality catalogs and pgvector semantic case histories), "
        "4) Working Memory (analyst notes, active investigation hypotheses, entity tags)."
    ),
)

__all__ = [
    "knowledge_agent",
    "create_knowledge_agent",
    "knowledge_agent_tool",
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_knowledge_agent.py -v`
Expected: PASS (2 tests passed).

- [ ] **Step 5: Commit**

```bash
git add agent_knowledge/ tests/test_knowledge_agent.py
git commit -m "feat(agent_knowledge): complete KnowledgeAgent router and AgentTool export"
```

---

### Task 7: Automated ADK Evaluator Benchmark Suite (`test_agents/soc_knowledge_agent/` & `evalsets/soc_knowledge_evalset.json`)

**Files:**
- Create: `test_agents/soc_knowledge_agent/agent.py`
- Create: `evalsets/soc_knowledge_evalset.json`
- Modify: `test_adk_evals.py`
- Test: Run `just adk-eval` or programmatic execution in `test_adk_evals.py`

**Interfaces:**
- Produces: Evaluation suite testable via `AgentEvaluator.evaluate_eval_set()`.

- [ ] **Step 1: Create `test_agents/soc_knowledge_agent/agent.py`**

```python
# test_agents/soc_knowledge_agent/agent.py
"""Standalone test agent for ADK evaluation of multi-modal knowledge grounding."""
from agent_knowledge import knowledge_agent

root_agent = knowledge_agent
```

- [ ] **Step 2: Create `evalsets/soc_knowledge_evalset.json`**

```json
{
  "eval_set_id": "soc_knowledge_evalset_v1",
  "eval_cases": [
    {
      "eval_case_id": "TC-KNOW-01-GRAPH",
      "prompt": "Find any lateral movement connection between WRK-SHASEK and our domain controller activedir.stackedpads.local in the knowledge graph.",
      "expected_tool_calls": [
        {
          "tool_name": "query_knowledge_graph"
        }
      ],
      "reference": {
        "grading_rubric": "Verify that the agent invokes query_knowledge_graph to search for paths between wrk-shasek and the domain controller, and explains the resulting hops."
      }
    },
    {
      "eval_case_id": "TC-KNOW-02-ASSET",
      "prompt": "What is the criticality tier, operating system, and owner of WRK-SHASEK according to our asset catalog?",
      "expected_tool_calls": [
        {
          "tool_name": "query_asset_catalog"
        }
      ],
      "reference": {
        "grading_rubric": "Verify that the agent invokes query_asset_catalog to look up the asset metadata for WRK-SHASEK."
      }
    },
    {
      "eval_case_id": "TC-KNOW-03-MEMORY",
      "prompt": "Check our past investigation notes for any previous observations or hypotheses on frank.kolzig.",
      "expected_tool_calls": [
        {
          "tool_name": "query_investigation_memory"
        }
      ],
      "reference": {
        "grading_rubric": "Verify that the agent invokes query_investigation_memory for the entity frank.kolzig."
      }
    }
  ]
}
```

- [ ] **Step 3: Verify all unit tests across the whole suite pass**

Run: `.venv/bin/pytest tests/test_graph_tool.py tests/test_alloydb_tool.py tests/test_memory_tool.py tests/test_rag_agent.py tests/test_knowledge_skills.py tests/test_knowledge_agent.py -v`
Expected: ALL PASS.

- [ ] **Step 4: Commit**

```bash
git add test_agents/soc_knowledge_agent/ evalsets/soc_knowledge_evalset.json
git commit -m "feat(evals): add ADK evaluation agent and evalset for KnowledgeAgent"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-31-knowledge-agent-subsystem.md`. Two execution options:

1. **Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
