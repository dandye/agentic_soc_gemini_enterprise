import asyncio
import json
from unittest.mock import patch

import pytest

from agent_soc_manager.tools.mcp_registry import MCPToolMetadata, MCPToolRegistry
from agent_soc_manager.tools.progressive_mcp_tools import (
    execute_mcp_tool,
    get_mcp_tool_schema,
    get_progressive_mcp_meta_tools,
    global_mcp_registry,
    search_mcp_tools,
)


@pytest.fixture
def mock_registry():
    registry = MCPToolRegistry()

    def mock_soar_close(case_id: str, root_cause: str = "Resolved") -> dict:
        return {"status": "closed", "case_id": case_id, "root_cause": root_cause}

    async def mock_siem_search(query: str, limit: int = 10) -> list:
        await asyncio.sleep(0.01)
        return [{"id": "E1", "query": query, "limit": limit}]

    def mock_gti_lookup(ioc: str) -> dict:
        if ioc == "malicious.com":
            return {"verdict": "malicious", "score": 95}
        return {"verdict": "clean", "score": 0}

    registry.register_tool(
        MCPToolMetadata(
            name="soar_close_case",
            server="soar",
            description="Closes a security incident case in SecOps SOAR.",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "The unique case ID."},
                    "root_cause": {
                        "type": "string",
                        "description": "Reason for closure.",
                        "default": "Resolved",
                    },
                },
                "required": ["case_id"],
            },
            executor=mock_soar_close,
        )
    )

    registry.register_tool(
        MCPToolMetadata(
            name="siem_search_events",
            server="siem",
            description="Executes a UDM filter query against Chronicle SIEM events.",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "UDM filter string."},
                    "limit": {
                        "type": "integer",
                        "description": "Max results.",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
            executor=mock_siem_search,
        )
    )

    registry.register_tool(
        MCPToolMetadata(
            name="gti_lookup_ioc",
            server="gti",
            description="Queries VirusTotal / GTI threat intelligence for IOC reputation.",
            input_schema={
                "type": "object",
                "properties": {
                    "ioc": {"type": "string", "description": "Domain, IP, or hash."},
                },
                "required": ["ioc"],
            },
            executor=mock_gti_lookup,
        )
    )

    return registry


def test_global_mcp_registry_instance():
    assert global_mcp_registry is not None
    assert isinstance(global_mcp_registry, MCPToolRegistry)


def test_search_mcp_tools(mock_registry):
    with patch(
        "agent_soc_manager.tools.progressive_mcp_tools.global_mcp_registry",
        mock_registry,
    ):
        all_tools = search_mcp_tools()
        assert "soar_close_case" in all_tools
        assert "siem_search_events" in all_tools
        assert "gti_lookup_ioc" in all_tools
        assert "### Discovered MCP Security Tools" in all_tools

        soar_tools = search_mcp_tools(server="soar")
        assert "soar_close_case" in soar_tools
        assert "siem_search_events" not in soar_tools

        gti_tools = search_mcp_tools(query="reputation")
        assert "gti_lookup_ioc" in gti_tools
        assert "soar_close_case" not in gti_tools

        empty_res = search_mcp_tools(query="nonexistent_service")
        assert "No MCP tools found" in empty_res


def test_get_mcp_tool_schema(mock_registry):
    with patch(
        "agent_soc_manager.tools.progressive_mcp_tools.global_mcp_registry",
        mock_registry,
    ):
        schema_str = get_mcp_tool_schema("soar_close_case")
        parsed = json.loads(schema_str)
        assert parsed["name"] == "soar_close_case"
        assert parsed["server"] == "soar"
        assert "case_id" in parsed["input_schema"]["properties"]
        assert "case_id" in parsed["input_schema"]["required"]

        schema_kebab = get_mcp_tool_schema("soar-close-case")
        parsed_kebab = json.loads(schema_kebab)
        assert parsed_kebab["name"] == "soar_close_case"

        missing = get_mcp_tool_schema("nonexistent_tool")
        assert "Error: MCP tool 'nonexistent_tool' not found" in missing


def test_execute_mcp_tool_sync(mock_registry):
    with patch(
        "agent_soc_manager.tools.progressive_mcp_tools.global_mcp_registry",
        mock_registry,
    ):
        res_str = execute_mcp_tool(
            "soar_close_case", {"case_id": "CASE-999", "root_cause": "False Positive"}
        )
        res = json.loads(res_str)
        assert res["status"] == "closed"
        assert res["case_id"] == "CASE-999"
        assert res["root_cause"] == "False Positive"

        json_args = json.dumps({"case_id": "CASE-888"})
        res_str2 = execute_mcp_tool("soar-close-case", json_args)
        res2 = json.loads(res_str2)
        assert res2["status"] == "closed"
        assert res2["case_id"] == "CASE-888"
        assert res2["root_cause"] == "Resolved"

        err_res = execute_mcp_tool("soar_close_case", {})
        assert "Error executing tool" in err_res
        assert "Missing required argument 'case_id'" in err_res

        err_missing = execute_mcp_tool("unknown_tool", {})
        assert "Error executing tool 'unknown_tool'" in err_missing

        err_json = execute_mcp_tool("soar_close_case", "{invalid_json")
        assert "Error parsing arguments JSON" in err_json


def test_execute_mcp_tool_async(mock_registry):
    with patch(
        "agent_soc_manager.tools.progressive_mcp_tools.global_mcp_registry",
        mock_registry,
    ):
        res_str = execute_mcp_tool(
            "siem_search_events",
            {"query": "metadata.event_type = 'USER_LOGIN'", "limit": 5},
        )
        res = json.loads(res_str)
        assert isinstance(res, list)
        assert len(res) == 1
        assert res[0]["id"] == "E1"
        assert res[0]["limit"] == 5


def test_get_progressive_mcp_meta_tools():
    meta_tools = get_progressive_mcp_meta_tools()
    tool_names = [t.__name__ for t in meta_tools]
    assert "search_mcp_tools" in tool_names
    assert "get_mcp_tool_schema" in tool_names
    assert "execute_mcp_tool" in tool_names
