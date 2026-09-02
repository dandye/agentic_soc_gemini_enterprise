import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


async def _execute_sql_query(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    """Execute query against AlloyDB / PostgreSQL instance using AsyncConnection and dict_row."""
    host = os.environ.get("ALLOYDB_HOST")
    port = int(os.environ.get("ALLOYDB_PORT", "5432"))
    database = os.environ.get("ALLOYDB_DATABASE", "postgres")
    user = os.environ.get("ALLOYDB_USER", "postgres")
    password = os.environ.get("ALLOYDB_PASSWORD")
    sslmode = os.environ.get("ALLOYDB_SSLMODE", "prefer")

    if not host or not password:
        raise ValueError(
            "AlloyDB connection not configured (ALLOYDB_HOST or ALLOYDB_PASSWORD missing)."
        )

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
        ctx: Optional ADK agent context.
    """
    if not os.environ.get("ALLOYDB_HOST") or not os.environ.get("ALLOYDB_PASSWORD"):
        return (
            f"[AlloyDB / Omnia Catalog Unavailable: ALLOYDB_HOST or ALLOYDB_PASSWORD not set in environment. "
            f"Query for '{query}' skipped.]"
        )

    try:
        if search_mode == "exact_asset":
            try:
                sql = (
                    "SELECT hostname, ip_address, mac_address, tier, owner, business_unit, os, is_crown_jewel "
                    "FROM assets "
                    "WHERE LOWER(hostname) = LOWER(%s) OR ip_address = %s OR LOWER(owner) = LOWER(%s) "
                    "LIMIT %s"
                )
                records = await _execute_sql_query(sql, (query, query, query, top_k))
            except Exception as table_err:
                err_str = str(table_err).lower()
                if "relation \"assets\" does not exist" in err_str or "assets" in err_str:
                    sql = (
                        "SELECT de.entity_value AS asset_identifier, de.entity_type, de.context, "
                        "dr.id AS related_case_id, dr.display_name AS related_case, dr.verdict, dr.confidence "
                        "FROM detection_entities de "
                        "LEFT JOIN detection_reports dr ON de.investigation_id = dr.id "
                        "WHERE LOWER(de.entity_value) LIKE LOWER(%s) "
                        "LIMIT %s"
                    )
                    like_query = f"%{query}%"
                    records = await _execute_sql_query(sql, (like_query, top_k))
                else:
                    raise
        elif search_mode == "semantic_case_history":
            like_query = f"%{query}%"
            try:
                sql = (
                    "SELECT case_id, title, summary, resolution, affected_assets, created_at "
                    "FROM historical_cases "
                    "WHERE summary ILIKE %s OR title ILIKE %s "
                    "ORDER BY created_at DESC "
                    "LIMIT %s"
                )
                records = await _execute_sql_query(sql, (like_query, like_query, top_k))
            except Exception as table_err:
                err_str = str(table_err).lower()
                if "relation \"historical_cases\" does not exist" in err_str or "historical_cases" in err_str:
                    sql = (
                        "SELECT id AS case_id, display_name AS title, verdict, confidence, "
                        "LEFT(summary, 500) AS summary, created_at "
                        "FROM detection_reports "
                        "WHERE summary ILIKE %s OR display_name ILIKE %s "
                        "ORDER BY created_at DESC "
                        "LIMIT %s"
                    )
                    records = await _execute_sql_query(sql, (like_query, like_query, top_k))
                else:
                    raise
        elif search_mode == "hybrid":
            like_query = f"%{query}%"
            try:
                if asset_tier_filter:
                    sql = (
                        "SELECT hostname, ip_address, tier, owner, business_unit, os, is_crown_jewel "
                        "FROM assets "
                        "WHERE (LOWER(hostname) LIKE LOWER(%s) OR LOWER(owner) LIKE LOWER(%s) OR ip_address LIKE %s) "
                        "AND tier = %s "
                        "LIMIT %s"
                    )
                    records = await _execute_sql_query(
                        sql, (like_query, like_query, like_query, asset_tier_filter, top_k)
                    )
                else:
                    sql = (
                        "SELECT hostname, ip_address, tier, owner, business_unit, os, is_crown_jewel "
                        "FROM assets "
                        "WHERE (LOWER(hostname) LIKE LOWER(%s) OR LOWER(owner) LIKE LOWER(%s) OR ip_address LIKE %s) "
                        "LIMIT %s"
                    )
                    records = await _execute_sql_query(
                        sql, (like_query, like_query, like_query, top_k)
                    )
            except Exception as table_err:
                err_str = str(table_err).lower()
                if "relation \"assets\" does not exist" in err_str or "assets" in err_str:
                    sql = (
                        "SELECT id AS case_id, display_name AS title, verdict, confidence, "
                        "LEFT(summary, 300) AS summary_preview, created_at "
                        "FROM detection_reports "
                        "WHERE summary ILIKE %s OR display_name ILIKE %s "
                        "ORDER BY created_at DESC "
                        "LIMIT %s"
                    )
                    records = await _execute_sql_query(sql, (like_query, like_query, top_k))
                else:
                    raise
        else:
            return (
                f"Unknown search_mode: '{search_mode}'. Supported: "
                f"'exact_asset', 'semantic_case_history', 'hybrid'."
            )

        if not records:
            return f"No records found in AlloyDB / Omnia catalog for query '{query}' (Mode: {search_mode})."

        lines = [f"=== AlloyDB / Omnia Catalog Results ({search_mode}: {query}) ==="]
        for idx, rec in enumerate(records, 1):
            lines.append(f"{idx}. {rec}")
        return "\n".join(lines)

    except Exception as e:
        logger.error(f"AlloyDB query failed: {e}")
        return f"[AlloyDB Query Error for '{query}': {str(e)}]"
