"""Unit tests for Phase 1: OpenTelemetry unblocking and AQuA BigQuery telemetry ingestion."""

import contextvars
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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
    import google.adk.telemetry._instrumentation as adk_inst

    import agent_soc_manager.agent as soc_agent

    dummy_agent = SimpleNamespace(
        name="tier1_analyst", description="Tier 1", model="gemini-2.5-flash"
    )
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
    func_args = {
        "query": 'principal.hostname = "wks-01"',
        "project_id": "secops-demo-env",
    }

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
    assert get_otel_service_name("agent_a2a_cti_researcher") == "adk-a2a-cti-researcher"


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
    assert cfg_logging["AQUA_LOG_FILTER"] == "gen_ai_client_inference_operation_details"
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


@pytest.mark.asyncio
async def test_http_response_stream_parser_handles_unbalanced_braces_in_json_strings():
    """Verify Monkeypatch #9 parses NDJSON lines containing unbalanced '{' inside JSON string literals."""
    import json
    import httpx
    from google.genai import _api_client as genai_api_client
    import agent_soc_manager.agent as soc_agent

    assert hasattr(soc_agent, "_drain_complete_json_chunks")

    # Simulate a truncated list_cases tool response containing unbalanced '{' inside a JSON string literal
    truncated_cases_str = (
        '{"cases": [{"id": "758", "displayName": "Case_test", '
        + '{"nested": ' * 18
        + "\n... [TRUNCATED due to large size] ..."
    )
    event1 = {
        "content": {
            "role": "user",
            "parts": [
                {
                    "function_response": {
                        "id": "adk-1",
                        "name": "list_cases",
                        "response": {
                            "content": [{"type": "text", "text": truncated_cases_str}]
                        },
                    }
                }
            ],
        },
        "author": "threat_hunter_specialist",
    }
    event2 = {
        "content": {
            "role": "model",
            "parts": [
                {
                    "function_call": {
                        "name": "get_case_full_details",
                        "args": {"case_id": "758"},
                    },
                    "thought_signature": "base64_thought_sig_" * 50,
                }
            ],
        },
        "author": "threat_hunter_specialist",
    }
    event3 = {
        "content": {
            "role": "model",
            "parts": [{"text": "Case 758 involves host WKSTN-FIN-042 and PsExec."}],
        },
        "author": "threat_hunter_specialist",
    }

    ndjson_payload = (
        json.dumps(event1) + "\n" + json.dumps(event2) + "\n" + json.dumps(event3) + "\n"
    )

    httpx_resp = httpx.Response(200, content=ndjson_payload.encode("utf-8"))
    http_response = genai_api_client.HttpResponse(headers={}, response_stream=httpx_resp)

    parsed_events = []
    async for raw_chunk in http_response._aiter_response_stream():
        parsed_events.append(
            genai_api_client.HttpResponse._load_json_from_response(raw_chunk)
        )

    assert len(parsed_events) == 3
    assert (
        parsed_events[2]["content"]["parts"][0]["text"]
        == "Case 758 involves host WKSTN-FIN-042 and PsExec."
    )

    # Also verify synchronous _iter_response_stream()
    httpx_resp_sync = httpx.Response(200, content=ndjson_payload.encode("utf-8"))
    http_response_sync = genai_api_client.HttpResponse(
        headers={}, response_stream=httpx_resp_sync
    )
    sync_events = [
        genai_api_client.HttpResponse._load_json_from_response(c)
        for c in http_response_sync._iter_response_stream()
    ]
    assert len(sync_events) == 3

    # Also verify _load_json_from_response handles concatenated JSON objects
    concatenated = json.dumps(event1) + json.dumps(event2) + json.dumps(event3)
    merged = genai_api_client.HttpResponse._load_json_from_response(concatenated)
    assert isinstance(merged, dict)
    merged_str = json.dumps(merged)
    assert "Case 758 involves host WKSTN-FIN-042 and PsExec." in merged_str
    assert "function_response" not in merged_str
    assert "thought_signature" not in merged_str


def test_summarize_telemetry_compresses_list_cases_wrapped_in_cases_key():
    """Verify summarize_telemetry recognizes {'cases': [...]} from list_cases and summarizes it."""
    import json
    import agent_soc_manager.agent as soc_agent

    cases_payload = {
        "cases": [
            {
                "id": str(758 - i),
                "displayName": f"Suspicious Lateral Movement Case {758 - i}",
                "priority": "PRIORITY_HIGH",
                "status": "OPENED",
                "createTime": "2026-04-12T22:55:21.258Z",
                "extraPadding": "X" * 900,
            }
            for i in range(25)
        ]
    }
    raw_text = json.dumps(cases_payload)
    assert len(raw_text) > 15000

    summarized = soc_agent.summarize_telemetry(raw_text, "list_cases")
    assert len(summarized) < 2500
    assert "### [SEMANTIC SUMMARY] SOAR Cases (Source: list_cases)" in summarized
    assert "**Total Cases Found:** 25" in summarized
    assert "Suspicious Lateral Movement Case 758" in summarized
    assert "PRIORITY_HIGH" in summarized


@pytest.mark.asyncio
async def test_consume_remote_a2a_stream_salvage_and_deduplication(monkeypatch):
    """Verify _consume_remote_a2a_stream salvages Raw response events, strips thought_signature/function_response, and caches per session."""
    import json
    import agent_soc_manager.agent as soc_agent

    monkeypatch.setattr(
        soc_agent,
        "get_secret",
        lambda key: "projects/secops-demo-env/locations/us-central1/reasoningEngines/999",
    )

    event_fr = {
        "content": {
            "role": "user",
            "parts": [
                {
                    "function_response": {
                        "name": "list_cases",
                        "response": {"result": "huge_raw_tool_dump_" * 500},
                    }
                }
            ],
        }
    }
    event_fc = {
        "content": {
            "role": "model",
            "parts": [
                {
                    "function_call": {
                        "name": "get_case_full_details",
                        "args": {"case_id": "758"},
                    },
                    "thought_signature": "secret_thought_sig_" * 200,
                }
            ],
        }
    }
    event_txt = {
        "content": {
            "role": "model",
            "parts": [
                {
                    "text": "Completed investigation of Case 758: Lateral movement confirmed."
                }
            ],
        }
    }
    raw_concat = json.dumps(event_fr) + "\n" + json.dumps(event_fc) + "\n" + json.dumps(event_txt)

    call_counter = {"count": 0}

    class FakeRemoteEngine:
        async def async_stream_query(self, **kwargs):
            call_counter["count"] += 1
            if False:
                yield {}
            raise RuntimeError(
                f"Failed to parse response as JSON. Raw response: {raw_concat}"
            )

    class FakeClient:
        def __init__(self, **kwargs):
            self.agent_engines = SimpleNamespace(get=lambda name: FakeRemoteEngine())

    monkeypatch.setattr(soc_agent.vertexai, "Client", FakeClient)

    dummy_ctx = SimpleNamespace(
        state={},
        _invocation_context=SimpleNamespace(
            user_id="sim-user",
            session=SimpleNamespace(id="sess-salvage-1"),
        ),
    )

    # First call should salvage the stream from the exception without leaking function_response or thought_signature
    res1 = await soc_agent.delegate_to_threat_hunter(
        "Retrieve full details for Case 758", dummy_ctx
    )
    assert "Completed investigation of Case 758: Lateral movement confirmed." in res1
    assert "get_case_full_details" in res1
    assert "huge_raw_tool_dump_" not in res1
    assert "secret_thought_sig_" not in res1
    assert call_counter["count"] == 1

    # Second identical call in the same session should hit the per-session cache without invoking remote_engine again
    res2 = await soc_agent.delegate_to_threat_hunter(
        "Retrieve full details for Case 758", dummy_ctx
    )
    assert res2 == res1
    assert call_counter["count"] == 1

