"""Unit tests for Okapi BM25, Reciprocal Rank Fusion (RRF), and hybrid case similarity."""

import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_knowledge.tools.alloydb_tool import (
    compute_bm25_scores,
    query_asset_catalog,
    reciprocal_rank_fusion,
    tokenize_security_text,
)
from agent_soc_manager.manage_alloydb import SIMILARITY_PROFILES, AlloyDBManager


def test_tokenize_security_text_preserves_secops_identifiers():
    text = (
        "Detected T1059.001 PowerShell execution on WRK-SHASEK (10.1.2.14) "
        "exploiting CVE-2025-53770 via cmd.exe."
    )
    tokens = tokenize_security_text(text)
    assert "t1059.001" in tokens
    assert "wrk-shasek" in tokens
    assert "10.1.2.14" in tokens
    assert "cve-2025-53770" in tokens
    assert "cmd.exe" in tokens
    assert "powershell" in tokens


def test_compute_bm25_scores_ranks_exact_technique_and_title_boost():
    docs = [
        {
            "id": "doc-1",
            "title": "General Network Anomaly",
            "summary": "Unusual outbound traffic observed on workstation.",
        },
        {
            "id": "doc-2",
            "title": "Encoded PowerShell T1059.001 Execution",
            "summary": "Adversary used T1059.001 encoded PowerShell payload on host wins-d19.",
        },
        {
            "id": "doc-3",
            "title": "Scheduled Task Persistence",
            "summary": " mentions powershell once in passing without technique match.",
        },
    ]
    scores = compute_bm25_scores(
        query="T1059.001 PowerShell",
        documents=docs,
        k1=1.5,
        b=0.75,
        title_boost=2.0,
    )
    assert len(scores) == 3
    # doc-2 has both T1059.001 and PowerShell in title and summary -> normalized top score 1.0
    assert scores["doc-2"] == pytest.approx(1.0)
    assert scores["doc-2"] > scores["doc-3"] > scores["doc-1"]
    assert scores["doc-1"] == 0.0


def test_reciprocal_rank_fusion_combines_vector_and_bm25_rankings():
    # doc-vec is #1 in vector but #3 in BM25
    # doc-bm25 is #3 in vector but #1 in BM25
    # doc-both is #2 in vector and #2 in BM25 -> should win or tie at top under RRF
    candidates = [
        {
            "id": "doc-vec",
            "title": "Conceptual LOLBin execution bypass",
            "summary": "Living off the land binary execution.",
            "similarity_score": 0.92,
        },
        {
            "id": "doc-both",
            "title": "MSBuildShell T1127.001 LOLBin Abuse",
            "summary": "MSBuild.exe used to execute T1127.001 payload.",
            "similarity_score": 0.88,
        },
        {
            "id": "doc-bm25",
            "title": "T1127.001 MSBuild.exe build log",
            "summary": "T1127.001 MSBuild.exe invoked during developer build.",
            "similarity_score": 0.51,
        },
    ]

    fused = reciprocal_rank_fusion(
        query="T1127.001 MSBuild.exe",
        candidates=candidates,
        rrf_k=60,
    )

    assert len(fused) == 3
    for item in fused:
        assert "rrf_score" in item
        assert "bm25_score" in item
        assert "vector_rank" in item
        assert "bm25_rank" in item

    # doc-both (rank 2 vector + rank 2 bm25 -> 2/(60+2) = 0.032258)
    # vs doc-vec (rank 1 vector + rank 3 bm25 -> 1/61 + 1/63 = 0.032266)
    # Both doc-both and doc-bm25 get boosted above pure single-channel noise
    ids = [r["id"] for r in fused]
    assert set(ids) == {"doc-vec", "doc-both", "doc-bm25"}
    assert fused[0]["rrf_score"] >= fused[1]["rrf_score"] >= fused[2]["rrf_score"]


@pytest.mark.asyncio
async def test_query_asset_catalog_bm25_case_history_reranks_candidates():
    mock_records = [
        {
            "case_id": "case-1",
            "title": "Routine Login Event",
            "summary": "Normal authentication on workstation.",
            "created_at": "2026-08-15T10:00:00Z",
        },
        {
            "case_id": "case-2",
            "title": "Mimikatz T1003 Credential Dumping on wins-d19",
            "summary": "Detected Mimikatz T1003 lsass memory dump on wins-d19.",
            "created_at": "2026-08-10T10:00:00Z",
        },
    ]
    with patch.dict(
        "os.environ",
        {
            "ALLOYDB_HOST": "10.0.0.5",
            "ALLOYDB_PASSWORD": "mock_unit_test_value",  # pragma: allowlist secret
        },
    ):
        with patch(
            "agent_knowledge.tools.alloydb_tool._execute_sql_query",
            new_callable=AsyncMock,
        ) as mock_exec:
            mock_exec.return_value = mock_records
            res = await query_asset_catalog(
                query="Mimikatz T1003 wins-d19",
                search_mode="bm25_case_history",
                top_k=2,
            )
            assert "=== AlloyDB / Omnia Catalog Results (bm25_case_history: Mimikatz T1003 wins-d19) ===" in res
            # Verify case-2 is ranked #1 ahead of case-1 due to BM25 + RRF score
            idx_case2 = res.index("case-2")
            idx_case1 = res.index("case-1")
            assert idx_case2 < idx_case1
            assert "bm25_score" in res


def test_alloydb_manager_find_similar_includes_bm25_breakdown_and_hybrid_rrf_profile():
    assert "hybrid-rrf" in SIMILARITY_PROFILES
    assert "lexical-bm25" in SIMILARITY_PROFILES
    assert "bm25" in SIMILARITY_PROFILES["hybrid-rrf"]["weights"]

    mgr = AlloyDBManager.__new__(AlloyDBManager)
    mock_cur = MagicMock()
    now = datetime.datetime(2026, 8, 15, 12, 0, tzinfo=datetime.UTC)

    target_row = {
        "id": "inv-target",
        "display_name": "Encoded PowerShell T1059.001 Network Connection",
        "verdict": "TRUE_POSITIVE",
        "confidence": "HIGH_CONFIDENCE",
        "status": "COMPLETED",
        "publish_time": now,
        "summary": "PowerShell executed encoded command downloading payload from 198.51.100.44.",
        "alert_ids": ["alert-1"],
        "investigation_steps": [],
        "entities": [],
        "embedding": "[0.1, 0.2]",
    }

    cand_rows = [
        {
            "id": "inv-cand-1",
            "display_name": "Encoded PowerShell T1059.001 Beacon",
            "verdict": "TRUE_POSITIVE",
            "confidence": "HIGH_CONFIDENCE",
            "status": "COMPLETED",
            "publish_time": now,
            "summary": "PowerShell executed encoded command downloading payload from 198.51.100.44.",
            "alert_ids": ["alert-2"],
            "investigation_steps": [],
            "entities": [],
            "semantic_score": 0.91,
            "fts_rank_score": 0.85,
        },
        {
            "id": "inv-cand-2",
            "display_name": "Unrelated Firewall Drop",
            "verdict": "FALSE_POSITIVE",
            "confidence": "LOW_CONFIDENCE",
            "status": "COMPLETED",
            "publish_time": now,
            "summary": "Blocked ICMP ping on perimeter firewall.",
            "alert_ids": ["alert-3"],
            "investigation_steps": [],
            "entities": [],
            "semantic_score": 0.20,
            "fts_rank_score": 0.0,
        },
    ]

    # Sequence of cursor fetchone/fetchall calls inside find_similar
    mock_cur.fetchone.side_effect = [
        target_row,  # 1. target report
        {"total": 258},  # 4. total reports count
    ]
    mock_cur.fetchall.side_effect = [
        [{"alert_id": "a1", "display_name": "PS", "severity": "HIGH", "mitre_tactics": ["TA0002"], "mitre_techniques": ["T1059.001"]}],  # 2. target alerts
        [{"entity_type": "HOST", "entity_value": "wins-d19", "context": ""}],  # 3. target entities
        [{"entity_value": "wins-d19", "doc_freq": 5}],  # 4b. entity idf
        [{"id": "inv-cand-1"}, {"id": "inv-cand-2"}],  # 5A. vector KNN
        [{"investigation_id": "inv-cand-1"}],  # 5B. entity sharing
        [{"id": "inv-cand-1"}],  # 5C. FTS / BM25 lexical candidates
        cand_rows,  # 6. candidate_rows
        [{"investigation_id": "inv-cand-1", "alert_id": "a2", "display_name": "PS", "severity": "HIGH", "mitre_tactics": ["TA0002"], "mitre_techniques": ["T1059.001"]}],  # cand alerts
        [{"investigation_id": "inv-cand-1", "entity_type": "HOST", "entity_value": "wins-d19", "context": ""}],  # cand entities
    ]

    mock_conn = MagicMock()
    mock_conn.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mgr.get_connection = MagicMock(return_value=mock_conn)

    results = mgr.find_similar("inv-target", limit=2, profile="hybrid-rrf")
    assert len(results) == 2
    top = results[0]
    assert top["id"] == "inv-cand-1"
    assert "bm25" in top["breakdown"]
    assert "rrf_score" in top
    assert top["breakdown"]["bm25"] > results[1]["breakdown"]["bm25"]
