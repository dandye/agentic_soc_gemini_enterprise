import logging
import os
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

FORBIDDEN_CYPHER_KEYWORDS = [
    "CREATE",
    "DELETE",
    "SET",
    "REMOVE",
    "MERGE",
    "DROP",
    "DETACH",
    "CALL APOC.PERIODIC",
]


def sanitize_cypher_query(query: str) -> str:
    """Ensure Cypher queries are strictly read-only."""
    clean_query = query.strip()
    upper_query = clean_query.upper()
    for kw in FORBIDDEN_CYPHER_KEYWORDS:
        kw_upper = kw.upper()
        pattern = r"\b" + r"\s+".join(re.escape(part) for part in kw_upper.split()) + r"\b"
        if re.search(pattern, upper_query):
            raise ValueError(f"Destructive Cypher commands are not permitted: {kw}")
    return clean_query


async def _run_cypher_query(cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute Cypher query against Neo4j instance with timeout."""
    uri = os.environ.get("NEO4J_URI")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD")

    if not uri or not password:
        raise ValueError(
            "Neo4j connection not configured (NEO4J_URI or NEO4J_PASSWORD missing)."
        )

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
        ctx: Optional ADK agent context.
    """
    max_hops = min(max(1, max_hops), 4)

    if not os.environ.get("NEO4J_URI") or not os.environ.get("NEO4J_PASSWORD"):
        return (
            f"[Neo4j Knowledge Graph Unavailable: NEO4J_URI or NEO4J_PASSWORD not set in environment. "
            f"Query for '{entity_value}' skipped.]"
        )

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
            return (
                f"Unknown query_type: '{query_type}'. Supported: "
                f"'entity_neighborhood', 'lateral_movement_path', 'credential_blast_radius', 'raw_cypher'."
            )

        if not records:
            return f"No graph relationships found for entity '{entity_value}' (Query Type: {query_type})."

        lines = [f"=== Neo4j Graph Query Results ({query_type}: {entity_value}) ==="]
        for idx, rec in enumerate(records, 1):
            lines.append(f"{idx}. {rec}")
        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Neo4j query failed: {e}")
        return f"[Neo4j Query Error for '{entity_value}': {str(e)}]"
