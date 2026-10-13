"""Unit tests for Phase 1: OpenTelemetry unblocking and AQuA BigQuery telemetry ingestion."""

import contextvars
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_agent_soc_manager_no_hardcoded_telemetry_false():
    """Verify agent_soc_manager/agent.py does not hardcode telemetry env vars to False."""
    agent_py = (REPO_ROOT / "agent_soc_manager" / "agent.py").read_text(
        encoding="utf-8"
    )
    assert (
        'os.environ["GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY"] = "False"'
        not in agent_py
    )
    assert '"GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY": "False"' not in agent_py
    assert (
        '"OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "False"' not in agent_py
    )


@pytest.mark.asyncio
async def test_patched_record_agent_invocation_records_spans_and_handles_context_switch():
    """Verify patched_record_agent_invocation creates a real span and suppresses cross-context detach ValueError."""
    import agent_soc_manager.agent as soc_agent
    import google.adk.telemetry._instrumentation as adk_inst

    dummy_agent = SimpleNamespace(name="tier1_analyst", description="Tier 1", model="gemini-2.5-flash")
    dummy_session = SimpleNamespace(id="sess-123", events=[])
    dummy_ctx = SimpleNamespace(
        session=dummy_session,
        user_content=None,
        invocation_id="inv-123",
    )

    # 1. Normal invocation records otel_context and span
    async with adk_inst.record_agent_invocation(dummy_ctx, dummy_agent) as tel_ctx:
        assert tel_ctx.otel_context is not None
        assert tel_ctx.span is not None

    # 2. Cross-context exit (simulating async generator context switch in delegate_concurrently)
    cm = adk_inst.record_agent_invocation(dummy_ctx, dummy_agent)
    tel_ctx = await cm.__aenter__()
    assert tel_ctx.otel_context is not None

    other_ctx = contextvars.copy_context()

    async def exit_in_other_context():
        await cm.__aexit__(None, None, None)

    # Should not raise ValueError("... was created in a different Context")
    await other_ctx.run(exit_in_other_context)
    assert hasattr(soc_agent, "patched_record_agent_invocation")


@pytest.mark.asyncio
async def test_patched_record_tool_execution_records_spans_and_handles_context_switch():
    """Verify patched_record_tool_execution traces tool calls and suppresses cross-context detach ValueError."""
    import google.adk.telemetry._instrumentation as adk_inst

    dummy_tool = SimpleNamespace(
        name="udm_search",
        description="Run UDM query",
        is_long_running=False,
    )
    dummy_agent = SimpleNamespace(name="tier1_analyst")
    func_args = {"query": 'principal.hostname = "wks-01"', "project_id": "secops-demo-env"}

    with patch.object(adk_inst.tracing, "trace_tool_call") as mock_trace_tool:
        cm = adk_inst.record_tool_execution(dummy_tool, dummy_agent, func_args)
        tel_ctx = await cm.__aenter__()
        assert tel_ctx.otel_context is not None
        assert tel_ctx.span is not None

        other_ctx = contextvars.copy_context()

        async def exit_in_other_context():
            await cm.__aexit__(None, None, None)

        await other_ctx.run(exit_in_other_context)
        mock_trace_tool.assert_called_once()


def test_per_agent_otel_service_name_mapping():
    """Verify manage_agent_engine maps each agent runtime to a distinct OTEL_SERVICE_NAME."""
    from installation_scripts.manage_agent_engine import get_otel_service_name

    assert get_otel_service_name("agent_soc_manager") == "adk-soc-manager"
    assert get_otel_service_name("agent_a2a_tier2") == "adk-a2a-tier2"
    assert get_otel_service_name("agent_a2a_threat_hunter") == "adk-a2a-threat-hunter"
    assert (
        get_otel_service_name("agent_a2a_detection_engineer")
        == "adk-a2a-detection-engineer"
    )
    assert (
        get_otel_service_name("agent_a2a_cti_researcher") == "adk-a2a-cti-researcher"
    )


def test_aqua_telemetry_ingestion_modes():
    """Verify AQuA telemetry config supports cloud_logging, cloud_ops, and big_query modes."""
    from installation_scripts.manage_agent_engine import (
        build_aqua_telemetry_config,
        maybe_build_bigquery_analytics_plugin,
    )

    cfg_logging = build_aqua_telemetry_config(
        "agent_soc_manager", {"AQUA_TELEMETRY_MODE": "cloud_logging"}
    )
    assert cfg_logging["AQUA_TELEMETRY_SOURCE"] == "cloud_logging"
    assert cfg_logging["AQUA_TELEMETRY_DATASET"] == "telemetry"
    assert cfg_logging["AQUA_TELEMETRY_TABLE"] == "agent_telemetry_data"
    assert (
        cfg_logging["AQUA_LOG_FILTER"]
        == "gen_ai_client_inference_operation_details"
    )
    assert cfg_logging["OTEL_SERVICE_NAME"] == "adk-soc-manager"

    cfg_ops = build_aqua_telemetry_config(
        "agent_a2a_threat_hunter", {"AQUA_TELEMETRY_MODE": "cloud_ops"}
    )
    assert cfg_ops["AQUA_TELEMETRY_SOURCE"] == "cloud_ops"
    assert cfg_ops["AQUA_TELEMETRY_TABLE"] == "_AllSpans"
    assert cfg_ops["OTEL_SERVICE_NAME"] == "adk-a2a-threat-hunter"

    cfg_bq = build_aqua_telemetry_config(
        "agent_a2a_tier2", {"AQUA_TELEMETRY_MODE": "big_query"}
    )
    assert cfg_bq["AQUA_TELEMETRY_SOURCE"] == "big_query"
    assert cfg_bq["BIGQUERY_AGENT_ANALYTICS_ENABLED"] == "TRUE"

    # When big_query mode is disabled, plugin builder returns None
    assert (
        maybe_build_bigquery_analytics_plugin(
            "agent_soc_manager", {"AQUA_TELEMETRY_MODE": "cloud_logging"}
        )
        is None
    )

    # When big_query mode is enabled, plugin builder either instantiates plugin or gracefully handles missing bq_storage
    plugin = maybe_build_bigquery_analytics_plugin(
        "agent_soc_manager",
        {"AQUA_TELEMETRY_MODE": "big_query", "GCP_PROJECT_ID": "secops-demo-env"},
    )
    assert plugin is None or hasattr(plugin, "name")
