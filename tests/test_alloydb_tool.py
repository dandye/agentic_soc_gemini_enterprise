import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from agent_knowledge.tools.alloydb_tool import (
    query_asset_catalog,
    _execute_sql_query,
)


@pytest.mark.asyncio
async def test_query_asset_catalog_missing_env():
    with patch.dict("os.environ", {}, clear=True):
        res = await query_asset_catalog(query="WRK-SHASEK")
        assert "AlloyDB / Omnia Catalog Unavailable: ALLOYDB_HOST or ALLOYDB_PASSWORD not set" in res
        assert "WRK-SHASEK" in res


@pytest.mark.asyncio
async def test_query_asset_catalog_missing_host():
    with patch.dict("os.environ", {"ALLOYDB_PASSWORD": "secret"}, clear=True):
        res = await query_asset_catalog(query="WRK-SHASEK")
        assert "AlloyDB / Omnia Catalog Unavailable: ALLOYDB_HOST or ALLOYDB_PASSWORD not set" in res


@pytest.mark.asyncio
async def test_query_asset_catalog_missing_password():
    with patch.dict("os.environ", {"ALLOYDB_HOST": "localhost"}, clear=True):
        res = await query_asset_catalog(query="WRK-SHASEK")
        assert "AlloyDB / Omnia Catalog Unavailable: ALLOYDB_HOST or ALLOYDB_PASSWORD not set" in res


@pytest.mark.asyncio
async def test_query_asset_catalog_exact_asset_mock():
    mock_records = [
        {
            "hostname": "wrk-shasek",
            "ip_address": "10.1.2.14",
            "mac_address": "00:1A:2B:3C:4D:5E",
            "tier": "Tier 2",
            "owner": "frank.kolzig",
            "business_unit": "Engineering",
            "os": "Windows 11 Enterprise",
            "is_crown_jewel": False,
        }
    ]
    with patch.dict(
        "os.environ",
        {
            "ALLOYDB_HOST": "10.0.0.5",
            "ALLOYDB_PORT": "5432",
            "ALLOYDB_DATABASE": "secops",
            "ALLOYDB_USER": "postgres",
            "ALLOYDB_PASSWORD": "password123",
            "ALLOYDB_SSLMODE": "require",
        },
    ):
        with patch(
            "agent_knowledge.tools.alloydb_tool._execute_sql_query",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = mock_records
            res = await query_asset_catalog(
                query="wrk-shasek",
                search_mode="exact_asset",
                top_k=5,
            )
            assert "=== AlloyDB / Omnia Catalog Results (exact_asset: wrk-shasek) ===" in res
            assert "wrk-shasek" in res
            assert "10.1.2.14" in res
            assert "Tier 2" in res
            assert "frank.kolzig" in res
            assert "Engineering" in res
            assert "Windows 11 Enterprise" in res

            mock_exec.assert_awaited_once()
            sql, params = mock_exec.call_args[0]
            assert "SELECT hostname, ip_address, mac_address, tier, owner, business_unit, os, is_crown_jewel" in sql
            assert "FROM assets" in sql
            assert "LOWER(hostname) = LOWER(%s) OR ip_address = %s OR LOWER(owner) = LOWER(%s)" in sql
            assert params == ("wrk-shasek", "wrk-shasek", "wrk-shasek", 5)


@pytest.mark.asyncio
async def test_query_asset_catalog_semantic_case_history_mock():
    mock_records = [
        {
            "case_id": "SEC-2026-0812",
            "title": "Suspected Pass-the-Hash on WRK-SHASEK",
            "summary": "Credential dumping via Mimikatz detected targeting Tier 2 workstations.",
            "resolution": "Isolated host, revoked Kerberos tickets, and re-imaged endpoint.",
            "affected_assets": ["wrk-shasek", "srv-app01"],
            "created_at": "2026-08-12T14:32:00Z",
        }
    ]
    with patch.dict(
        "os.environ",
        {
            "ALLOYDB_HOST": "10.0.0.5",
            "ALLOYDB_PASSWORD": "password123",
        },
    ):
        with patch(
            "agent_knowledge.tools.alloydb_tool._execute_sql_query",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = mock_records
            res = await query_asset_catalog(
                query="Pass-the-Hash Mimikatz",
                search_mode="semantic_case_history",
                top_k=3,
            )
            assert "=== AlloyDB / Omnia Catalog Results (semantic_case_history: Pass-the-Hash Mimikatz) ===" in res
            assert "SEC-2026-0812" in res
            assert "Mimikatz" in res
            assert "Isolated host" in res

            mock_exec.assert_awaited_once()
            sql, params = mock_exec.call_args[0]
            assert "FROM historical_cases" in sql
            assert "WHERE summary ILIKE %s OR title ILIKE %s" in sql
            assert "ORDER BY created_at DESC" in sql
            assert params == ("%Pass-the-Hash Mimikatz%", "%Pass-the-Hash Mimikatz%", 3)


@pytest.mark.asyncio
async def test_query_asset_catalog_hybrid_mock_without_tier_filter():
    mock_records = [
        {
            "hostname": "srv-db01",
            "ip_address": "10.1.5.20",
            "tier": "Tier 0",
            "owner": "data-platform",
            "business_unit": "Payments",
            "os": "Ubuntu 24.04 LTS",
            "is_crown_jewel": True,
        }
    ]
    with patch.dict(
        "os.environ",
        {
            "ALLOYDB_HOST": "10.0.0.5",
            "ALLOYDB_PASSWORD": "password123",
        },
    ):
        with patch(
            "agent_knowledge.tools.alloydb_tool._execute_sql_query",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = mock_records
            res = await query_asset_catalog(
                query="srv-db",
                search_mode="hybrid",
                top_k=10,
            )
            assert "=== AlloyDB / Omnia Catalog Results (hybrid: srv-db) ===" in res
            assert "srv-db01" in res
            assert "Tier 0" in res
            assert "Payments" in res

            mock_exec.assert_awaited_once()
            sql, params = mock_exec.call_args[0]
            assert "FROM assets" in sql
            assert "LOWER(hostname) LIKE LOWER(%s)" in sql
            assert "tier =" not in sql
            assert params == ("%srv-db%", "%srv-db%", "%srv-db%", 10)


@pytest.mark.asyncio
async def test_query_asset_catalog_hybrid_mock_with_tier_filter():
    mock_records = [
        {
            "hostname": "dc-root01",
            "ip_address": "10.0.1.10",
            "tier": "Tier 0",
            "owner": "identity-ops",
            "business_unit": "Infrastructure",
            "os": "Windows Server 2022",
            "is_crown_jewel": True,
        }
    ]
    with patch.dict(
        "os.environ",
        {
            "ALLOYDB_HOST": "10.0.0.5",
            "ALLOYDB_PASSWORD": "password123",
        },
    ):
        with patch(
            "agent_knowledge.tools.alloydb_tool._execute_sql_query",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = mock_records
            res = await query_asset_catalog(
                query="dc-root",
                search_mode="hybrid",
                asset_tier_filter="Tier 0",
                top_k=5,
            )
            assert "=== AlloyDB / Omnia Catalog Results (hybrid: dc-root) ===" in res
            assert "dc-root01" in res
            assert "Tier 0" in res
            assert "identity-ops" in res

            mock_exec.assert_awaited_once()
            sql, params = mock_exec.call_args[0]
            assert "FROM assets" in sql
            assert "AND tier = %s" in sql
            assert params == ("%dc-root%", "%dc-root%", "%dc-root%", "Tier 0", 5)


@pytest.mark.asyncio
async def test_query_asset_catalog_no_records():
    with patch.dict(
        "os.environ",
        {
            "ALLOYDB_HOST": "10.0.0.5",
            "ALLOYDB_PASSWORD": "password123",
        },
    ):
        with patch(
            "agent_knowledge.tools.alloydb_tool._execute_sql_query",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = []
            res = await query_asset_catalog(
                query="unknown_asset",
                search_mode="exact_asset",
            )
            assert "No records found in AlloyDB / Omnia catalog for query 'unknown_asset' (Mode: exact_asset)." in res


@pytest.mark.asyncio
async def test_query_asset_catalog_unknown_search_mode():
    with patch.dict(
        "os.environ",
        {
            "ALLOYDB_HOST": "10.0.0.5",
            "ALLOYDB_PASSWORD": "password123",
        },
    ):
        res = await query_asset_catalog(
            query="srv-app01",
            search_mode="unsupported_mode",
        )
        assert "Unknown search_mode: 'unsupported_mode'" in res
        assert "Supported: 'exact_asset', 'semantic_case_history', 'hybrid'" in res


@pytest.mark.asyncio
async def test_query_asset_catalog_handles_database_exception():
    with patch.dict(
        "os.environ",
        {
            "ALLOYDB_HOST": "10.0.0.5",
            "ALLOYDB_PASSWORD": "password123",
        },
    ):
        with patch(
            "agent_knowledge.tools.alloydb_tool._execute_sql_query",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.side_effect = ConnectionError("AlloyDB pool connection timeout")
            res = await query_asset_catalog(
                query="wrk-shasek",
                search_mode="exact_asset",
            )
            assert "[AlloyDB Query Error for 'wrk-shasek': AlloyDB pool connection timeout]" in res


@pytest.mark.asyncio
async def test_execute_sql_query_missing_credentials():
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(ValueError, match="AlloyDB connection not configured"):
            await _execute_sql_query("SELECT 1", ())


@pytest.mark.asyncio
async def test_execute_sql_query_missing_password_only():
    with patch.dict("os.environ", {"ALLOYDB_HOST": "localhost"}, clear=True):
        with pytest.raises(ValueError, match="AlloyDB connection not configured"):
            await _execute_sql_query("SELECT 1", ())


@pytest.mark.asyncio
async def test_execute_sql_query_driver_execution():
    mock_cursor = AsyncMock()
    mock_cursor.fetchall = AsyncMock(return_value=[{"hostname": "srv-01"}])
    mock_cursor.execute = AsyncMock()

    mock_cursor_ctx = AsyncMock()
    mock_cursor_ctx.__aenter__.return_value = mock_cursor
    mock_cursor_ctx.__aexit__.return_value = None

    mock_conn = MagicMock()
    mock_conn.cursor = MagicMock(return_value=mock_cursor_ctx)

    mock_conn_ctx = AsyncMock()
    mock_conn_ctx.__aenter__.return_value = mock_conn
    mock_conn_ctx.__aexit__.return_value = None

    mock_async_connect = AsyncMock(return_value=mock_conn_ctx)

    mock_psycopg = MagicMock()
    mock_psycopg.AsyncConnection.connect = mock_async_connect

    mock_rows = MagicMock()
    mock_dict_row = MagicMock()
    mock_rows.dict_row = mock_dict_row

    with patch.dict(
        "os.environ",
        {
            "ALLOYDB_HOST": "10.0.0.5",
            "ALLOYDB_PORT": "5433",
            "ALLOYDB_DATABASE": "secops_db",
            "ALLOYDB_USER": "secops_user",
            "ALLOYDB_PASSWORD": "secure_password",
            "ALLOYDB_SSLMODE": "require",
        },
    ):
        with patch.dict(
            "sys.modules",
            {
                "psycopg": mock_psycopg,
                "psycopg.rows": mock_rows,
            },
        ):
            results = await _execute_sql_query("SELECT hostname FROM assets WHERE hostname = %s", ("srv-01",))
            assert results == [{"hostname": "srv-01"}]
            mock_async_connect.assert_awaited_once_with(
                host="10.0.0.5",
                port=5433,
                dbname="secops_db",
                user="secops_user",
                password="secure_password",
                sslmode="require",
            )
            mock_conn.cursor.assert_called_once_with(row_factory=mock_dict_row)
            mock_cursor.execute.assert_awaited_once_with(
                "SELECT hostname FROM assets WHERE hostname = %s",
                ("srv-01",),
            )
            mock_cursor.fetchall.assert_awaited_once()
