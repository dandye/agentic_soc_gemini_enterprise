import logging
import math
import os
import re
from typing import Any


logger = logging.getLogger(__name__)

_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "in",
        "is",
        "it",
        "of",
        "on",
        "or",
        "that",
        "the",
        "to",
        "was",
        "were",
        "will",
        "with",
    }
)

# Matches SecOps tokens: MITRE TTPs (T1059.001), CVEs (CVE-2025-53770), IPs, hostnames/filenames, and words
_TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*")


def tokenize_security_text(text: str) -> list[str]:
    """Tokenize security text while preserving MITRE IDs, CVEs, IPs, filenames, and hostnames."""
    if not text:
        return []
    raw_tokens = _TOKEN_PATTERN.findall(text.lower())
    return [t for t in raw_tokens if t and t not in _STOPWORDS]


def compute_bm25_scores(
    query: str,
    documents: list[dict[str, Any]],
    k1: float = 1.5,
    b: float = 0.75,
    title_boost: float = 2.0,
) -> dict[str, float]:
    """Compute normalized Okapi BM25 scores in [0.0, 1.0] across candidate documents.

    Applies field boosting (`title_boost`) to `title` / `display_name` relative to
    `summary`, `resolution`, and `markdown_report`.
    """
    if not documents:
        return {}

    query_tokens = tokenize_security_text(query)
    doc_ids: list[str] = []
    doc_token_lists: list[list[str]] = []

    for idx, doc in enumerate(documents):
        doc_id = str(
            doc.get("id")
            or doc.get("case_id")
            or doc.get("hostname")
            or doc.get("asset_identifier")
            or f"doc-{idx}"
        )
        doc_ids.append(doc_id)

        title_text = str(doc.get("title") or doc.get("display_name") or "")
        body_parts = [
            str(doc.get("summary") or doc.get("summary_preview") or ""),
            str(doc.get("resolution") or ""),
            str(doc.get("markdown_report") or ""),
            str(doc.get("context") or ""),
        ]
        title_tokens = tokenize_security_text(title_text)
        body_tokens = tokenize_security_text(" ".join(body_parts))

        boost_reps = max(1, int(round(title_boost)))
        combined_tokens = (title_tokens * boost_reps) + body_tokens
        doc_token_lists.append(combined_tokens)

    if not query_tokens:
        return dict.fromkeys(doc_ids, 0.0)

    n_docs = len(doc_token_lists)
    avgdl = sum(len(tokens) for tokens in doc_token_lists) / max(1, n_docs)
    if avgdl <= 0:
        return dict.fromkeys(doc_ids, 0.0)

    # Document frequency for each unique query term
    unique_q_terms = set(query_tokens)
    doc_freq: dict[str, int] = dict.fromkeys(unique_q_terms, 0)
    for tokens in doc_token_lists:
        token_set = set(tokens)
        for term in unique_q_terms:
            if term in token_set:
                doc_freq[term] += 1

    raw_scores: dict[str, float] = {}
    for did, tokens in zip(doc_ids, doc_token_lists, strict=False):
        dl = len(tokens)
        tf_counts: dict[str, int] = {}
        for t in tokens:
            if t in unique_q_terms:
                tf_counts[t] = tf_counts.get(t, 0) + 1

        score = 0.0
        for term in query_tokens:
            tf = tf_counts.get(term, 0)
            if tf == 0:
                continue
            df = doc_freq.get(term, 0)
            # Standard Robertson-Spärck Jones BM25 IDF (non-negative floor)
            idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
            denom = tf + k1 * (1.0 - b + b * (dl / avgdl))
            score += idf * ((tf * (k1 + 1.0)) / denom)
        raw_scores[did] = score

    max_score = max(raw_scores.values(), default=0.0)
    if max_score <= 0.0:
        return dict.fromkeys(doc_ids, 0.0)

    return {did: round(val / max_score, 4) for did, val in raw_scores.items()}


def reciprocal_rank_fusion(
    query: str,
    candidates: list[dict[str, Any]],
    rrf_k: int = 60,
    k1: float = 1.5,
    b: float = 0.75,
) -> list[dict[str, Any]]:
    """Fuse dense vector similarity rankings and Okapi BM25 rankings using RRF (k=60)."""
    if not candidates:
        return []

    bm25_map = compute_bm25_scores(query=query, documents=candidates, k1=k1, b=b)

    enriched: list[dict[str, Any]] = []
    for idx, item in enumerate(candidates):
        row = dict(item)
        doc_id = str(
            row.get("id")
            or row.get("case_id")
            or row.get("hostname")
            or row.get("asset_identifier")
            or f"doc-{idx}"
        )
        row["_doc_id"] = doc_id
        row["bm25_score"] = bm25_map.get(doc_id, 0.0)
        vec_sim = row.get("similarity_score")
        if vec_sim is None:
            vec_sim = row.get("semantic_score")
        row["_vec_score"] = float(vec_sim) if vec_sim is not None else -1.0
        row["_orig_idx"] = idx
        enriched.append(row)

    # Vector rank (1-indexed): sort by _vec_score DESC, falling back to original SQL order
    vec_sorted = sorted(
        enriched,
        key=lambda r: (r["_vec_score"], -r["_orig_idx"]),
        reverse=True,
    )
    vec_ranks = {r["_doc_id"]: rank for rank, r in enumerate(vec_sorted, 1)}

    # BM25 rank (1-indexed): sort by bm25_score DESC, falling back to fts_rank_score / original order
    bm25_sorted = sorted(
        enriched,
        key=lambda r: (
            r["bm25_score"],
            float(r.get("fts_rank_score") or 0.0),
            -r["_orig_idx"],
        ),
        reverse=True,
    )
    bm25_ranks = {r["_doc_id"]: rank for rank, r in enumerate(bm25_sorted, 1)}

    fused: list[dict[str, Any]] = []
    for row in enriched:
        did = row["_doc_id"]
        v_rank = vec_ranks[did]
        b_rank = bm25_ranks[did]
        rrf_val = (1.0 / (rrf_k + v_rank)) + (1.0 / (rrf_k + b_rank))
        clean_row = {
            k: v for k, v in row.items() if k not in ("_doc_id", "_vec_score", "_orig_idx")
        }
        clean_row["bm25_score"] = row["bm25_score"]
        clean_row["vector_rank"] = v_rank
        clean_row["bm25_rank"] = b_rank
        clean_row["rrf_score"] = round(rrf_val, 6)
        fused.append(clean_row)

    fused.sort(
        key=lambda r: (r["rrf_score"], r["bm25_score"], float(r.get("similarity_score") or 0.0)),
        reverse=True,
    )
    return fused


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
    asset_tier_filter: str | None = None,
    top_k: int = 5,
    ctx: Any | None = None,
) -> str:
    """
    Query AlloyDB / Omnia for structured asset information, criticality tiers, and semantic/BM25 historical case records.

    Args:
        query: Asset identifier (hostname, IP, owner) or semantic/lexical incident description.
        search_mode: One of 'exact_asset', 'semantic_case_history', 'hybrid', 'bm25_case_history', 'hybrid_rrf'.
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
                        "LEFT(summary, 500) AS summary, publish_time AS created_at, "
                        "ts_rank_cd("
                        "  to_tsvector('english', coalesce(display_name, '') || ' ' || coalesce(summary, '')),"
                        "  plainto_tsquery('english', %s)"
                        ") AS fts_rank_score "
                        "FROM detection_reports "
                        "WHERE to_tsvector('english', coalesce(display_name, '') || ' ' || coalesce(summary, '')) "
                        "@@ plainto_tsquery('english', %s) "
                        "OR summary ILIKE %s OR display_name ILIKE %s "
                        "ORDER BY fts_rank_score DESC NULLS LAST, publish_time DESC "
                        "LIMIT %s"
                    )
                    records = await _execute_sql_query(
                        sql, (query, query, like_query, like_query, max(top_k * 3, 15))
                    )
                else:
                    raise
            if len(records) > 1:
                records = reciprocal_rank_fusion(query=query, candidates=records)[:top_k]
        elif search_mode in ("bm25_case_history", "hybrid_rrf"):
            like_query = f"%{query}%"
            pool_limit = max(top_k * 4, 20)
            try:
                sql = (
                    "SELECT id AS case_id, display_name AS title, verdict, confidence, "
                    "LEFT(summary, 500) AS summary, publish_time AS created_at, "
                    "ts_rank_cd("
                    "  to_tsvector('english', coalesce(display_name, '') || ' ' || coalesce(summary, '')),"
                    "  plainto_tsquery('english', %s)"
                    ") AS fts_rank_score "
                    "FROM detection_reports "
                    "WHERE to_tsvector('english', coalesce(display_name, '') || ' ' || coalesce(summary, '')) "
                    "@@ plainto_tsquery('english', %s) "
                    "OR summary ILIKE %s OR display_name ILIKE %s "
                    "ORDER BY fts_rank_score DESC NULLS LAST, publish_time DESC "
                    "LIMIT %s"
                )
                records = await _execute_sql_query(
                    sql, (query, query, like_query, like_query, pool_limit)
                )
            except Exception:
                sql = (
                    "SELECT case_id, title, summary, resolution, affected_assets, created_at "
                    "FROM historical_cases "
                    "WHERE summary ILIKE %s OR title ILIKE %s "
                    "ORDER BY created_at DESC "
                    "LIMIT %s"
                )
                records = await _execute_sql_query(sql, (like_query, like_query, pool_limit))
            records = reciprocal_rank_fusion(query=query, candidates=records)[:top_k]
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
                        "LEFT(summary, 300) AS summary_preview, publish_time AS created_at, "
                        "ts_rank_cd("
                        "  to_tsvector('english', coalesce(display_name, '') || ' ' || coalesce(summary, '')),"
                        "  plainto_tsquery('english', %s)"
                        ") AS fts_rank_score "
                        "FROM detection_reports "
                        "WHERE to_tsvector('english', coalesce(display_name, '') || ' ' || coalesce(summary, '')) "
                        "@@ plainto_tsquery('english', %s) "
                        "OR summary ILIKE %s OR display_name ILIKE %s "
                        "ORDER BY fts_rank_score DESC NULLS LAST, publish_time DESC "
                        "LIMIT %s"
                    )
                    records = await _execute_sql_query(
                        sql, (query, query, like_query, like_query, max(top_k * 3, 15))
                    )
                else:
                    raise
            if len(records) > 1:
                records = reciprocal_rank_fusion(query=query, candidates=records)[:top_k]
        else:
            return (
                f"Unknown search_mode: '{search_mode}'. Supported: "
                f"'exact_asset', 'semantic_case_history', 'hybrid', 'bm25_case_history', 'hybrid_rrf'."
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
