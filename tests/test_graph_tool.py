import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from agent_knowledge.tools.graph_tool import (
    query_knowledge_graph,
    sanitize_cypher_query,
    _run_cypher_query,
    FORBIDDEN_CYPHER_KEYWORDS,
)


def test_sanitize_cypher_query_blocks_destructive_keywords():
    destructive_queries = [
        "MATCH (n) DETACH DELETE n",
        "MATCH (n) DELETE n",
        "CREATE (n:Test {name: 'bad'})",
        "MATCH (n:User) SET n.admin = true",
        "MATCH (n:User) REMOVE n.admin",
        "MERGE (n:User {name: 'bad'})",
        "DROP INDEX ON :User(name)",
        "CALL apoc.periodic.iterate('MATCH (n) RETURN n', 'DETACH DELETE n', {batchSize:100})",
    ]
    for q in destructive_queries:
        with pytest.raises(ValueError, match="Destructive Cypher commands are not permitted"):
            sanitize_cypher_query(q)


def test_sanitize_cypher_query_allows_read_only():
    valid_queries = [
        "MATCH (u:User {name: 'frank'}) RETURN u LIMIT 10",
        "MATCH (n)-[r]->(m) WHERE n.name = $entity RETURN n, r, m",
        "MATCH p = shortestPath((src)-[*1..3]-(dst)) RETURN p",
    ]
    for q in valid_queries:
        assert sanitize_cypher_query(q) == q.strip()


@pytest.mark.asyncio
async def test_query_knowledge_graph_missing_env():
    with patch.dict("os.environ", {}, clear=True):
        res = await query_knowledge_graph(
            query_type="entity_neighborhood",
            entity_value="wrk-shasek",
        )
        assert "Neo4j Knowledge Graph Unavailable: NEO4J_URI or NEO4J_PASSWORD not set" in res


@pytest.mark.asyncio
async def test_query_knowledge_graph_neighborhood_mock():
    mock_records = [
        {"source": "wrk-shasek", "rel": "LOGGED_IN", "target": "frank.kolzig"}
    ]
    with patch.dict(
        "os.environ",
        {
            "NEO4J_URI": "bolt://localhost:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "password",
        },
    ):
        with patch(
            "agent_knowledge.tools.graph_tool._run_cypher_query",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = mock_records
            res = await query_knowledge_graph(
                query_type="entity_neighborhood",
                entity_value="wrk-shasek",
            )
            assert "=== Neo4j Graph Query Results (entity_neighborhood: wrk-shasek) ===" in res
            assert "frank.kolzig" in res
            assert "LOGGED_IN" in res
            mock_run.assert_awaited_once()


@pytest.mark.asyncio
async def test_query_knowledge_graph_lateral_movement_mock():
    mock_records = [
        {"path_nodes": ["wrk-shasek", "srv-app01", "dc-root01"], "rels": ["CONNECTED_TO", "ADMINISTERS"]}
    ]
    with patch.dict(
        "os.environ",
        {
            "NEO4J_URI": "bolt://localhost:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "password",
        },
    ):
        with patch(
            "agent_knowledge.tools.graph_tool._run_cypher_query",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = mock_records
            res = await query_knowledge_graph(
                query_type="lateral_movement_path",
                entity_value="wrk-shasek",
                max_hops=3,
            )
            assert "dc-root01" in res
            assert "ADMINISTERS" in res
            # Check cypher interpolation for max_hops
            call_cypher = mock_run.call_args[0][0]
            assert "*1..3" in call_cypher


@pytest.mark.asyncio
async def test_query_knowledge_graph_credential_blast_radius_mock():
    mock_records = [
        {"accessible_asset": "dc-root01", "asset_type": ["DomainController"]}
    ]
    with patch.dict(
        "os.environ",
        {
            "NEO4J_URI": "bolt://localhost:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "password",
        },
    ):
        with patch(
            "agent_knowledge.tools.graph_tool._run_cypher_query",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = mock_records
            res = await query_knowledge_graph(
                query_type="credential_blast_radius",
                entity_value="frank.kolzig",
                max_hops=2,
            )
            assert "dc-root01" in res
            assert "DomainController" in res
            call_cypher = mock_run.call_args[0][0]
            assert "*1..2" in call_cypher


@pytest.mark.asyncio
async def test_query_knowledge_graph_raw_cypher_mock():
    mock_records = [
        {"u.name": "frank.kolzig", "u.tier": "Tier 2"}
    ]
    custom_q = "MATCH (u:User {name: $entity}) RETURN u.name, u.tier"
    with patch.dict(
        "os.environ",
        {
            "NEO4J_URI": "bolt://localhost:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "password",
        },
    ):
        with patch(
            "agent_knowledge.tools.graph_tool._run_cypher_query",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = mock_records
            res = await query_knowledge_graph(
                query_type="raw_cypher",
                entity_value="frank.kolzig",
                custom_cypher=custom_q,
            )
            assert "frank.kolzig" in res
            assert "Tier 2" in res
            mock_run.assert_awaited_once_with(custom_q, {"entity": "frank.kolzig"})


@pytest.mark.asyncio
async def test_query_knowledge_graph_raw_cypher_missing_query():
    with patch.dict(
        "os.environ",
        {
            "NEO4J_URI": "bolt://localhost:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "password",
        },
    ):
        res = await query_knowledge_graph(
            query_type="raw_cypher",
            entity_value="frank.kolzig",
            custom_cypher=None,
        )
        assert "custom_cypher string must be provided" in res


@pytest.mark.asyncio
async def test_query_knowledge_graph_unknown_query_type():
    with patch.dict(
        "os.environ",
        {
            "NEO4J_URI": "bolt://localhost:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "password",
        },
    ):
        res = await query_knowledge_graph(
            query_type="invalid_type",
            entity_value="frank.kolzig",
        )
        assert "Unknown query_type: 'invalid_type'" in res


@pytest.mark.asyncio
async def test_query_knowledge_graph_no_records():
    with patch.dict(
        "os.environ",
        {
            "NEO4J_URI": "bolt://localhost:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "password",
        },
    ):
        with patch(
            "agent_knowledge.tools.graph_tool._run_cypher_query",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = []
            res = await query_knowledge_graph(
                query_type="entity_neighborhood",
                entity_value="unknown_host",
            )
            assert "No graph relationships found for entity 'unknown_host'" in res


@pytest.mark.asyncio
async def test_query_knowledge_graph_handles_execution_exception():
    with patch.dict(
        "os.environ",
        {
            "NEO4J_URI": "bolt://localhost:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "password",
        },
    ):
        with patch(
            "agent_knowledge.tools.graph_tool._run_cypher_query",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.side_effect = ConnectionError("Failed to connect to Neo4j bolt server")
            res = await query_knowledge_graph(
                query_type="entity_neighborhood",
                entity_value="wrk-shasek",
            )
            assert "[Neo4j Query Error for 'wrk-shasek': Failed to connect to Neo4j bolt server]" in res


@pytest.mark.asyncio
async def test_query_knowledge_graph_max_hops_clamping():
    with patch.dict(
        "os.environ",
        {
            "NEO4J_URI": "bolt://localhost:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "password",
        },
    ):
        with patch(
            "agent_knowledge.tools.graph_tool._run_cypher_query",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = [{"result": "ok"}]
            # Test max_hops > 4 clamps to 4
            await query_knowledge_graph(
                query_type="lateral_movement_path",
                entity_value="wrk-shasek",
                max_hops=10,
            )
            assert "*1..4" in mock_run.call_args[0][0]

            # Test max_hops < 1 clamps to 1
            await query_knowledge_graph(
                query_type="lateral_movement_path",
                entity_value="wrk-shasek",
                max_hops=0,
            )
            assert "*1..1" in mock_run.call_args[0][0]


@pytest.mark.asyncio
async def test_run_cypher_query_driver_execution():
    mock_driver = MagicMock()
    mock_session = AsyncMock()
    mock_result = AsyncMock()
    mock_result.data = AsyncMock(return_value=[{"col": "val"}])
    mock_session.run = AsyncMock(return_value=mock_result)

    # Context manager setup for driver and session
    mock_session_ctx = AsyncMock()
    mock_session_ctx.__aenter__.return_value = mock_session
    mock_session_ctx.__aexit__.return_value = None
    mock_driver.session.return_value = mock_session_ctx

    mock_driver_ctx = AsyncMock()
    mock_driver_ctx.__aenter__.return_value = mock_driver
    mock_driver_ctx.__aexit__.return_value = None

    with patch.dict(
        "os.environ",
        {
            "NEO4J_URI": "bolt://localhost:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_PASSWORD": "password",
        },
    ):
        with patch("neo4j.AsyncGraphDatabase.driver", return_value=mock_driver_ctx):
            records = await _run_cypher_query("MATCH (n) RETURN n LIMIT 1", {"entity": "test"})
            assert records == [{"col": "val"}]


@pytest.mark.asyncio
async def test_run_cypher_query_missing_credentials():
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(ValueError, match="Neo4j connection not configured"):
            await _run_cypher_query("MATCH (n) RETURN n", {})
