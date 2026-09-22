"""Unit tests verifying create_feed and update_feed are disabled when OneMCP is used."""

import pickle
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset

from agent_a2a_cti_researcher import agent as cti_researcher_agent
from agent_a2a_detection_engineer import agent as detection_engineer_agent
from agent_a2a_threat_hunter import agent as threat_hunter_agent
from agent_a2a_tier2 import agent as tier2_agent
from agent_soc_manager import agent as soc_manager_agent


class _DummyTool:

    def __init__(self, name: str):
        self.name = name
        self._mcp_tool = SimpleNamespace(name=name)


class TestSocManagerRemoteOneMcpToolset:
    """Tests for create_remote_secops_toolset and OneMCP filtering in agent_soc_manager."""

    def test_disabled_onemcp_tools_constant_defined(self):
        assert hasattr(soc_manager_agent, "DISABLED_ONEMCP_TOOLS")
        assert "create_feed" in soc_manager_agent.DISABLED_ONEMCP_TOOLS
        assert "update_feed" in soc_manager_agent.DISABLED_ONEMCP_TOOLS

    def test_default_none_tool_filter_disables_feed_tools(self):
        toolset = soc_manager_agent.create_remote_secops_toolset("us", tool_filter=None)
        assert not toolset._is_tool_selected(_DummyTool("create_feed"), None)
        assert not toolset._is_tool_selected(_DummyTool("update_feed"), None)
        assert toolset._is_tool_selected(_DummyTool("list_rules"), None)
        assert toolset._is_tool_selected(_DummyTool("udm_search"), None)

    def test_list_tool_filter_blocks_create_and_update_feed(self):
        toolset = soc_manager_agent.create_remote_secops_toolset(
            "us",
            tool_filter=["list_rules", "create_feed", "update_feed", "udm_search"],
        )
        assert not toolset._is_tool_selected(_DummyTool("create_feed"), None)
        assert not toolset._is_tool_selected(_DummyTool("update_feed"), None)
        assert toolset._is_tool_selected(_DummyTool("list_rules"), None)
        assert toolset._is_tool_selected(_DummyTool("udm_search"), None)
        assert not toolset._is_tool_selected(_DummyTool("delete_feed"), None)

    def test_list_with_only_disabled_tools_selects_nothing(self):
        toolset = soc_manager_agent.create_remote_secops_toolset(
            "us",
            tool_filter=["create_feed", "update_feed"],
        )
        assert not toolset._is_tool_selected(_DummyTool("create_feed"), None)
        assert not toolset._is_tool_selected(_DummyTool("update_feed"), None)
        assert not toolset._is_tool_selected(_DummyTool("list_rules"), None)

    def test_callable_predicate_tool_filter_still_blocks_feed_tools(self):
        def allow_all_predicate(tool, readonly_context=None) -> bool:
            return True

        toolset = soc_manager_agent.create_remote_secops_toolset(
            "us",
            tool_filter=allow_all_predicate,
        )
        assert not toolset._is_tool_selected(_DummyTool("create_feed"), None)
        assert not toolset._is_tool_selected(_DummyTool("update_feed"), None)
        assert toolset._is_tool_selected(_DummyTool("list_rules"), None)

    def test_tool_filter_remains_natively_picklable(self):
        toolset = soc_manager_agent.create_remote_secops_toolset("us", tool_filter=None)
        dumped = pickle.dumps(toolset.tool_filter)
        loaded_filter = pickle.loads(dumped)  # noqa: S301
        assert loaded_filter is None
        assert not toolset._is_tool_selected(_DummyTool("create_feed"), None)
        assert not toolset._is_tool_selected(_DummyTool("update_feed"), None)
        assert toolset._is_tool_selected(_DummyTool("list_rules"), None)

    def test_local_dynamic_mcp_toolset_also_blocks_feed_tools(self):
        local_toolset = threat_hunter_agent.DynamicMcpToolset(
            mcp_module="secops_mcp.server", target_env={}
        )
        assert not local_toolset._is_tool_selected(_DummyTool("create_feed"), None)
        assert not local_toolset._is_tool_selected(_DummyTool("update_feed"), None)
        assert local_toolset._is_tool_selected(_DummyTool("udm_search"), None)

    @pytest.mark.asyncio
    async def test_before_tool_cache_blocks_create_and_update_feed(self):
        ctx = SimpleNamespace(state={})
        res_create = await soc_manager_agent.before_tool_cache(
            _DummyTool("create_feed"), {"displayName": "test"}, ctx
        )
        res_update = await soc_manager_agent.before_tool_cache(
            _DummyTool("update_feed"), {"feedId": "123"}, ctx
        )
        assert isinstance(res_create, dict)
        assert "error" in res_create
        assert "create_feed" in res_create["error"]
        assert isinstance(res_update, dict)
        assert "error" in res_update
        assert "update_feed" in res_update["error"]


class TestDetectionEngineerRemoteOneMcpToolset:
    """Tests for RemoteOneMcpToolset in agent_a2a_detection_engineer."""

    def test_disabled_onemcp_tools_constant_defined(self):
        assert hasattr(detection_engineer_agent, "DISABLED_ONEMCP_TOOLS")
        assert "create_feed" in detection_engineer_agent.DISABLED_ONEMCP_TOOLS
        assert "update_feed" in detection_engineer_agent.DISABLED_ONEMCP_TOOLS

    @pytest.mark.asyncio
    async def test_remote_onemcp_get_tools_without_filter_excludes_feed_tools(self):
        toolset = detection_engineer_agent.RemoteOneMcpToolset(
            region="us", project_id="test-project"
        )
        toolset._is_dynamic_initialized = True
        mock_tools = [
            _DummyTool("list_rules"),
            _DummyTool("validate_rule"),
            _DummyTool("create_feed"),
            _DummyTool("update_feed"),
        ]
        with patch.object(
            McpToolset, "get_tools", new=AsyncMock(return_value=mock_tools)
        ):
            tools = await toolset.get_tools()
            names = [t.name for t in tools]
            assert "create_feed" not in names
            assert "update_feed" not in names
            assert "list_rules" in names
            assert "validate_rule" in names

    @pytest.mark.asyncio
    async def test_remote_onemcp_get_tools_with_filter_strips_feed_tools(self):
        toolset = detection_engineer_agent.RemoteOneMcpToolset(
            region="us",
            project_id="test-project",
            tool_filter=["list_rules", "create_feed", "update_feed"],
        )
        toolset._is_dynamic_initialized = True

        mock_tools = [
            _DummyTool("list_rules"),
            _DummyTool("validate_rule"),
            _DummyTool("create_feed"),
            _DummyTool("update_feed"),
        ]
        with patch.object(
            McpToolset, "get_tools", new=AsyncMock(return_value=mock_tools)
        ):
            tools = await toolset.get_tools()
            names = [t.name for t in tools]
            assert names == ["list_rules"]

    def test_remote_onemcp_list_with_only_disabled_tools_selects_nothing(self):
        toolset = detection_engineer_agent.RemoteOneMcpToolset(
            region="us",
            project_id="test-project",
            tool_filter=["create_feed", "update_feed"],
        )
        assert not toolset._is_tool_selected(_DummyTool("create_feed"), None)
        assert not toolset._is_tool_selected(_DummyTool("update_feed"), None)
        assert not toolset._is_tool_selected(_DummyTool("list_rules"), None)

    @pytest.mark.asyncio
    async def test_before_tool_cache_blocks_create_and_update_feed(self):
        ctx = SimpleNamespace(state={})
        res_create = await detection_engineer_agent.before_tool_cache(
            _DummyTool("create_feed"), {"displayName": "test"}, ctx
        )
        res_update = await detection_engineer_agent.before_tool_cache(
            _DummyTool("update_feed"), {"feedId": "123"}, ctx
        )
        assert isinstance(res_create, dict)
        assert "error" in res_create
        assert isinstance(res_update, dict)
        assert "error" in res_update


class TestAllSpecialistAgentsBlockDisabledFeedTools:
    """Verify CTI Researcher, Threat Hunter, and Tier 2 Responder also block create_feed and update_feed."""

    @pytest.mark.parametrize(
        "agent_mod",
        [
            cti_researcher_agent,
            threat_hunter_agent,
            tier2_agent,
        ],
    )
    def test_disabled_onemcp_tools_defined_across_specialists(self, agent_mod):
        assert hasattr(agent_mod, "DISABLED_ONEMCP_TOOLS")
        assert "create_feed" in agent_mod.DISABLED_ONEMCP_TOOLS
        assert "update_feed" in agent_mod.DISABLED_ONEMCP_TOOLS

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "agent_mod",
        [
            cti_researcher_agent,
            threat_hunter_agent,
            tier2_agent,
        ],
    )
    async def test_before_tool_cache_blocks_across_specialists(self, agent_mod):
        ctx = SimpleNamespace(state={})
        res_create = await agent_mod.before_tool_cache(
            _DummyTool("create_feed"), {"displayName": "test"}, ctx
        )
        res_update = await agent_mod.before_tool_cache(
            _DummyTool("update_feed"), {"feedId": "123"}, ctx
        )
        assert isinstance(res_create, dict)
        assert "error" in res_create
        assert "create_feed" in res_create["error"]
        assert isinstance(res_update, dict)
        assert "error" in res_update
        assert "update_feed" in res_update["error"]
