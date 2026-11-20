import pytest
from unittest.mock import MagicMock
from agent_knowledge.tools.memory_tool import (
    add_investigation_note,
    query_investigation_memory,
    _in_memory_store,
)
import agent_knowledge.tools as tools_pkg


@pytest.fixture(autouse=True)
def clean_memory_store():
    """Ensure in-memory store is clean before and after each test."""
    _in_memory_store.clear()
    yield
    _in_memory_store.clear()


@pytest.mark.asyncio
async def test_add_and_query_memory_by_entity():
    add_investigation_note(
        entity="frank.kolzig",
        note="Observed failed logons across 3 workstations",
        tag="credential_spray",
    )
    add_investigation_note(
        entity="srv-app01",
        note="Outbound beaconing to suspicious IP 198.51.100.24",
        tag="c2_traffic",
    )

    res_frank = await query_investigation_memory(entity="frank.kolzig")
    assert "=== Investigation Memory Notes ===" in res_frank
    assert "credential_spray" in res_frank
    assert "Observed failed logons" in res_frank
    assert "frank.kolzig" in res_frank
    assert "srv-app01" not in res_frank

    # Case-insensitivity test
    res_caps = await query_investigation_memory(entity="FRANK.KOLZIG")
    assert "credential_spray" in res_caps
    assert "frank.kolzig" in res_caps


@pytest.mark.asyncio
async def test_query_by_semantic_keyword():
    add_investigation_note(
        entity="srv-dc01",
        note="Pass-the-Hash attack detected targeting KRBTGT account",
        tag="lateral_movement",
    )
    add_investigation_note(
        entity="wrk-dev09",
        note="Developer installed unsigned debugging tool",
        tag="shadow_it",
    )

    res = await query_investigation_memory(query="Pass-the-Hash")
    assert "=== Investigation Memory Notes ===" in res
    assert "Pass-the-Hash attack detected" in res
    assert "srv-dc01" in res
    assert "wrk-dev09" not in res


@pytest.mark.asyncio
async def test_query_by_tag():
    add_investigation_note(
        entity="10.0.1.50",
        note="Host isolated via CrowdStrike Falcon containment policy",
        tag="containment",
    )
    add_investigation_note(
        entity="10.0.1.50",
        note="Initial memory dump collected via LiME",
        tag="forensics",
    )

    res = await query_investigation_memory(query="containment")
    assert "containment" in res
    assert "Host isolated via CrowdStrike" in res
    assert "LiME" not in res


@pytest.mark.asyncio
async def test_query_combined_entity_and_query():
    add_investigation_note(
        entity="wrk-shasek",
        note="Mimikatz memory dump attempted",
        tag="credential_access",
    )
    add_investigation_note(
        entity="wrk-shasek",
        note="User reported phishing email with macro attachment",
        tag="initial_access",
    )
    add_investigation_note(
        entity="wrk-other",
        note="Mimikatz detected in Temp directory",
        tag="credential_access",
    )

    res = await query_investigation_memory(entity="wrk-shasek", query="Mimikatz")
    assert "Mimikatz memory dump attempted" in res
    assert "User reported phishing email" not in res
    assert "wrk-other" not in res


@pytest.mark.asyncio
async def test_query_empty_memory():
    # Empty store, no filters
    res_none = await query_investigation_memory()
    assert res_none == "No investigation memory records found."

    # Empty store, entity only
    res_entity = await query_investigation_memory(entity="srv-dc01")
    assert res_entity == "No investigation memory records found for entity 'srv-dc01'."

    # Empty store, query only
    res_query = await query_investigation_memory(query="ransomware")
    assert res_query == "No investigation memory records found with query 'ransomware'."

    # Empty store, both entity and query
    res_both = await query_investigation_memory(entity="srv-dc01", query="ransomware")
    assert (
        res_both
        == "No investigation memory records found for entity 'srv-dc01' with query 'ransomware'."
    )


@pytest.mark.asyncio
async def test_query_max_results_and_clamping():
    for i in range(10):
        add_investigation_note(
            entity=f"host-{i}",
            note=f"Investigation observation note number {i}",
            tag="triage",
        )

    # Limit to 3 results
    res_3 = await query_investigation_memory(max_results=3)
    assert res_3.count("Time:") == 3

    # Clamping negative / 0 max_results to at least 1
    res_0 = await query_investigation_memory(max_results=0)
    assert res_0.count("Time:") == 1

    res_neg = await query_investigation_memory(max_results=-5)
    assert res_neg.count("Time:") == 1

    # Large max_results returns all available
    res_all = await query_investigation_memory(max_results=50)
    assert res_all.count("Time:") == 10


@pytest.mark.asyncio
async def test_query_ordering_most_recent_first():
    add_investigation_note(entity="host-a", note="First observation", tag="step1")
    add_investigation_note(entity="host-b", note="Second observation", tag="step2")
    add_investigation_note(entity="host-c", note="Third observation", tag="step3")

    res = await query_investigation_memory()
    idx_third = res.find("Third observation")
    idx_second = res.find("Second observation")
    idx_first = res.find("First observation")

    assert idx_third != -1 and idx_second != -1 and idx_first != -1
    assert idx_third < idx_second < idx_first


@pytest.mark.asyncio
async def test_adk_context_session_state():
    mock_session = MagicMock()
    mock_session.state = {}
    mock_ctx = MagicMock()
    mock_ctx.session = mock_session

    add_investigation_note(
        entity="srv-ad01",
        note="Kerberoasting ticket request detected",
        tag="t1558",
        ctx=mock_ctx,
    )

    assert "investigation_memory" in mock_session.state
    assert len(mock_session.state["investigation_memory"]) == 1
    assert mock_session.state["investigation_memory"][0]["entity"] == "srv-ad01"

    # Query with context
    res = await query_investigation_memory(entity="srv-ad01", ctx=mock_ctx)
    assert "Kerberoasting ticket request detected" in res
    assert "srv-ad01" in res


@pytest.mark.asyncio
async def test_adk_context_invocation_context_state():
    mock_session = MagicMock()
    mock_session.state = {
        "investigation_memory": [
            {
                "timestamp": "2026-08-31T20:00:00+00:00",
                "entity": "admin_alice",
                "tag": "privileged_access",
                "note": "Session established from unauthorized VPN gateway",
            }
        ]
    }
    mock_inv_ctx = MagicMock()
    mock_inv_ctx.session = mock_session
    mock_ctx = MagicMock(spec=["_invocation_context"])
    mock_ctx._invocation_context = mock_inv_ctx

    res = await query_investigation_memory(entity="admin_alice", ctx=mock_ctx)
    assert "admin_alice" in res
    assert "Session established from unauthorized VPN gateway" in res
    assert "privileged_access" in res


def test_add_investigation_note_default_tag():
    add_investigation_note(entity="srv-web01", note="Port 443 cert renewed")
    assert len(_in_memory_store) == 1
    assert _in_memory_store[0]["tag"] == "general"
    assert _in_memory_store[0]["entity"] == "srv-web01"
    assert _in_memory_store[0]["note"] == "Port 443 cert renewed"
    assert "timestamp" in _in_memory_store[0]


def test_tools_init_exports():
    assert hasattr(tools_pkg, "add_investigation_note")
    assert hasattr(tools_pkg, "query_investigation_memory")
    assert "add_investigation_note" in tools_pkg.__all__
    assert "query_investigation_memory" in tools_pkg.__all__
