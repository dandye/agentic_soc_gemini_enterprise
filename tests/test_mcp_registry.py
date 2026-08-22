import asyncio
from typing import Any

import pytest

from agent_soc_manager.tools.mcp_registry import MCPToolMetadata, MCPToolRegistry


def test_registry_registration_and_normalization():
    """Verify tool registration with dual-key kebab-case and snake_case normalization."""
    registry = MCPToolRegistry()

    meta = MCPToolMetadata(
        name="soar_get_case",
        server="soar",
        description="Retrieve security case from SOAR.",
        input_schema={"type": "object", "properties": {"case_id": {"type": "string"}}},
    )
    registry.register_tool(meta)

    # Lookup by exact name
    assert registry.get_tool("soar_get_case") is not None
    assert registry.get_tool("soar_get_case").server == "soar"

    # Lookup by kebab-case
    assert registry.get_tool("soar-get-case") is not None
    assert registry.get_tool("soar-get-case").name == "soar_get_case"

    # Lookup with leading/trailing whitespace
    assert registry.get_tool("  soar_get_case  ") is not None

    # Lookup non-existent
    assert registry.get_tool("non_existent_tool") is None
    assert registry.get_tool("") is None


def test_registry_search():
    """Verify keyword and server search indexing."""
    registry = MCPToolRegistry()
    registry.register_tool(
        MCPToolMetadata(
            name="soar_get_case", server="soar", description="Get SOAR case."
        )
    )
    registry.register_tool(
        MCPToolMetadata(
            name="soar_close_case", server="soar", description="Close SOAR case."
        )
    )
    registry.register_tool(
        MCPToolMetadata(
            name="gti_lookup_ioc", server="gti", description="Enrich IOC reputation."
        )
    )
    registry.register_tool(
        MCPToolMetadata(
            name="siem_search_events",
            server="siem",
            description="Search Chronicle events.",
        )
    )

    # Search by keyword in name
    case_tools = registry.search_tools(query="case")
    assert len(case_tools) == 2
    assert all(t["server"] == "soar" for t in case_tools)

    # Search by keyword in description
    reputation_tools = registry.search_tools(query="reputation")
    assert len(reputation_tools) == 1
    assert reputation_tools[0]["name"] == "gti_lookup_ioc"

    # Search by server filter
    siem_tools = registry.search_tools(server="siem")
    assert len(siem_tools) == 1
    assert siem_tools[0]["name"] == "siem_search_events"

    # Search with combined query and server
    soar_close = registry.search_tools(query="close", server="soar")
    assert len(soar_close) == 1
    assert soar_close[0]["name"] == "soar_close_case"

    # Search with unmatched query
    empty = registry.search_tools(query="nonexistent_keyword")
    assert empty == []


def test_registry_get_tool_schema():
    """Verify tool schema retrieval and formatting."""
    registry = MCPToolRegistry()
    schema = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Chronicle UDM filter expression",
            },
            "limit": {
                "type": "integer",
                "description": "Max events to return",
                "default": 50,
            },
        },
        "required": ["query"],
    }
    registry.register_tool(
        MCPToolMetadata(
            name="siem_search_events",
            server="siem",
            description="Search Chronicle SIEM events.",
            input_schema=schema,
        )
    )

    retrieved = registry.get_tool_schema("siem_search_events")
    assert retrieved is not None
    assert retrieved["name"] == "siem_search_events"
    assert retrieved["server"] == "siem"
    assert retrieved["description"] == "Search Chronicle SIEM events."
    assert retrieved["input_schema"] == schema

    # Normalized lookup for schema
    retrieved_kebab = registry.get_tool_schema("siem-search-events")
    assert retrieved_kebab is not None
    assert retrieved_kebab["name"] == "siem_search_events"

    # Missing tool returns None
    assert registry.get_tool_schema("missing_tool") is None


def test_registry_get_compact_catalog():
    """Verify compact markdown catalog generation."""
    registry = MCPToolRegistry()
    registry.register_tool(
        MCPToolMetadata(
            name="soar_get_case",
            server="soar",
            description="Retrieve case from SOAR.",
            input_schema={},
        )
    )
    registry.register_tool(
        MCPToolMetadata(
            name="siem_search_events",
            server="siem",
            description="Query Chronicle UDM security events.",
            input_schema={},
        )
    )

    full_catalog = registry.get_compact_catalog()
    assert (
        "- **siem_search_events** (siem): Query Chronicle UDM security events."
        in full_catalog
    )
    assert "- **soar_get_case** (soar): Retrieve case from SOAR." in full_catalog

    # Filtered catalog by server
    soar_catalog = registry.get_compact_catalog(server="soar")
    assert "soar_get_case" in soar_catalog
    assert "siem_search_events" not in soar_catalog

    # Empty registry catalog
    empty_registry = MCPToolRegistry()
    assert empty_registry.get_compact_catalog() == ""


def test_registry_execute_tool_sync():
    """Verify synchronous tool execution and parameter validation."""
    registry = MCPToolRegistry()

    def mock_executor(case_id: str, priority: str = "medium") -> dict[str, Any]:
        return {"status": "success", "case_id": case_id, "priority": priority}

    schema = {
        "type": "object",
        "properties": {
            "case_id": {"type": "string"},
            "priority": {"type": "string", "default": "medium"},
        },
        "required": ["case_id"],
    }
    registry.register_tool(
        MCPToolMetadata(
            name="soar_update_case",
            server="soar",
            description="Update case priority.",
            input_schema=schema,
            executor=mock_executor,
        )
    )

    # Valid execution
    res = registry.execute_tool(
        "soar_update_case", {"case_id": "CASE-101", "priority": "high"}
    )
    assert res == {"status": "success", "case_id": "CASE-101", "priority": "high"}

    # Execution with default argument
    res_default = registry.execute_tool("soar-update-case", {"case_id": "CASE-102"})
    assert res_default == {
        "status": "success",
        "case_id": "CASE-102",
        "priority": "medium",
    }

    # Missing required argument raises ValueError
    with pytest.raises(ValueError, match="Missing required argument 'case_id'"):
        registry.execute_tool("soar_update_case", {})

    # Unknown tool raises ValueError
    with pytest.raises(ValueError, match="Tool 'nonexistent' not found in registry"):
        registry.execute_tool("nonexistent", {})


def test_registry_execute_tool_async():
    """Verify asynchronous tool execution."""
    registry = MCPToolRegistry()

    async def async_executor(query: str) -> list[str]:
        await asyncio.sleep(0.01)
        return [f"event_match_for_{query}"]

    registry.register_tool(
        MCPToolMetadata(
            name="siem_query",
            server="siem",
            description="Async SIEM query.",
            input_schema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
            executor=async_executor,
        )
    )

    async def runner():
        res = registry.execute_tool(
            "siem_query", {"query": "principal.ip = '10.0.0.1'"}
        )
        if asyncio.iscoroutine(res):
            res = await res
        return res

    result = asyncio.run(runner())
    assert result == ["event_match_for_principal.ip = '10.0.0.1'"]
