"""Unit tests for Workflow 2: Progressive MCP Tool & SOC Runbook Pruning."""

from __future__ import annotations

import asyncio
import json
import pathlib
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from google.genai import types

from governed_agents.shared_decision_guards import progressive_tool_pruner as pruner
from scripts.governance.workflows import run_workflow2_tool_pruning as wf2


def test_catalog_and_question_builder_with_dynamic_descriptions() -> None:
    assert 30 <= len(pruner.SOC_TOOL_CATALOG) <= 45
    assert "general_triage" in pruner.SOC_RUNBOOKS
    assert len(pruner.SOC_RUNBOOKS) == 6

    tool_names = [entry.name for entry in pruner.SOC_TOOL_CATALOG] + [
        "custom_onemcp_timeline_export"
    ]
    questions = pruner.build_pruning_questions(
        tool_names,
        tool_descriptions={
            "custom_onemcp_timeline_export": "Export chronological UDM timeline CSV."
        },
    )

    assert len(questions) == 1 + len(tool_names)
    assert questions["select_runbook"]["type"] == "choice"
    assert "general_triage" in questions["select_runbook"]["criteria"]
    assert (
        "Export chronological UDM timeline CSV."
        in questions["tool_needed_custom_onemcp_timeline_export"]["instructions"]
    )


def test_apply_decision_pruning_reduces_tools_and_runbooks() -> None:
    req = pruner.build_baseline_llm_request(
        "Look up SHA-256 hash in GTI and fetch threat collection."
    )
    tool_names = [entry.name for entry in pruner.SOC_TOOL_CATALOG]
    kept_expected = {"lookup_file_hash_reputation", "get_threat_collection"}
    answers: dict[str, Any] = {
        "select_runbook": {
            "type": "choice",
            "choice": "cti_enrichment",
            "confidence": 0.96,
        }
    }
    for name in tool_names:
        answers[f"tool_needed_{name}"] = {
            "type": "noul",
            "noul": 0.91 if name in kept_expected else 0.05,
            "confidence": 0.93,
        }

    result = pruner.apply_decision_pruning(
        req,
        {
            "enabled": True,
            "answers": answers,
            "usage": {"total_input_tokens": 1100, "total_output_tokens": 0},
        },
        tool_names=tool_names,
        threshold=0.50,
        decision_latency_ms=180.5,
    )

    assert result.enabled is True
    assert result.selected_runbook == "cti_enrichment"
    assert set(result.kept_tools) == kept_expected
    assert len(result.pruned_tools) == len(tool_names) - 2
    assert set(req.tools_dict.keys()) == kept_expected

    decl_names = [
        d.name
        for t in (req.config.tools or [])
        for d in (t.function_declarations or [])
    ]
    assert set(decl_names) == kept_expected
    assert '<runbook id="cti_enrichment">' in req.config.system_instruction
    assert '<runbook id="credential_dump_hunt">' not in req.config.system_instruction
    assert "<runbook_catalog>" not in req.config.system_instruction
    assert result.bytes_saved > 0
    assert result.reduction_pct > 70.0
    assert result.decision_output_tokens == 0


def test_min_tools_gate_and_canary_preservation() -> None:
    # 1. Narrow catalog (< min_tools_to_prune=12) skips Decision 1 RPC & pruning.
    narrow_tools = pruner.SOC_TOOL_CATALOG[:6]
    narrow_req = pruner.build_baseline_llm_request(
        "Search UDM logs", tools=narrow_tools
    )
    with patch.object(pruner, "aevaluate_decisions", new=AsyncMock()) as mock_eval:
        res_narrow = asyncio.run(
            pruner.prune_llm_request_async(narrow_req, min_tools_to_prune=12)
        )
    mock_eval.assert_not_awaited()
    assert res_narrow.enabled is False
    assert len(narrow_req.tools_dict) == 6

    # 2. Canary tools (e.g. ADVERTISED_DENIED_TOOLS) are preserved even at score 0.01.
    full_req = pruner.build_baseline_llm_request("Search UDM logs")
    tool_names = [entry.name for entry in pruner.SOC_TOOL_CATALOG]
    res_canary = pruner.apply_decision_pruning(
        full_req,
        {
            "enabled": True,
            "answers": {
                "select_runbook": {
                    "type": "choice",
                    "choice": "credential_dump_hunt",
                    "confidence": 0.9,
                },
                "tool_needed_udm_search": {
                    "type": "noul",
                    "noul": 0.9,
                    "confidence": 0.9,
                },
                "tool_needed_list_feeds": {
                    "type": "noul",
                    "noul": 0.01,
                    "confidence": 0.99,
                },
                "tool_needed_create_rule": {
                    "type": "noul",
                    "noul": 0.01,
                    "confidence": 0.99,
                },
            },
            "usage": {},
        },
        tool_names=tool_names,
        preserve_canary_tools=("list_feeds", "create_rule"),
    )
    assert set(res_canary.kept_tools) == {"udm_search", "list_feeds", "create_rule"}


def test_apply_decision_pruning_safety_floor_and_fallback() -> None:
    req = pruner.build_baseline_llm_request("Ambiguous request")
    tool_names = [entry.name for entry in pruner.SOC_TOOL_CATALOG]

    low_answers: dict[str, Any] = {
        "select_runbook": {
            "type": "choice",
            "choice": "unknown_runbook_id",
            "confidence": 0.40,
        }
    }
    for idx, name in enumerate(tool_names):
        low_answers[f"tool_needed_{name}"] = {
            "type": "noul",
            "noul": 0.01 * (idx + 1) if idx < 3 else 0.001,
            "confidence": 0.60,
        }

    res_fallback = pruner.apply_decision_pruning(
        req,
        {"enabled": True, "answers": low_answers, "usage": {}},
        tool_names=tool_names,
        threshold=0.50,
        fallback_top_k=3,
    )
    assert res_fallback.fallback_triggered is True
    assert res_fallback.selected_runbook == "general_triage"
    assert len(res_fallback.kept_tools) == 3


def test_apply_decision_pruning_bypasses_on_error() -> None:
    req = pruner.build_baseline_llm_request("Hunt LSASS")
    tool_names = [entry.name for entry in pruner.SOC_TOOL_CATALOG]

    result = pruner.apply_decision_pruning(
        req,
        {"enabled": True, "error": "TimeoutError: timed out", "answers": {}},
        tool_names=tool_names,
    )
    assert result.enabled is False
    assert result.error == "TimeoutError: timed out"
    assert len(result.kept_tools) == len(tool_names)
    assert len(req.tools_dict) == len(tool_names)


def test_multi_turn_session_pinning_preserves_kv_cache_prefix() -> None:
    prompt = "Validate YARA-L rule syntax."
    req1 = pruner.build_baseline_llm_request(prompt)
    req2 = pruner.build_baseline_llm_request(prompt)
    req2.contents.append(
        types.Content(
            role="model",
            parts=[
                types.Part(
                    function_call=types.FunctionCall(name="validate_rule", args={})
                )
            ],
        )
    )
    req2.contents.append(
        types.Content(
            role="user",
            parts=[
                types.Part(
                    function_response=types.FunctionResponse(
                        name="validate_rule", response={"valid": True}
                    )
                )
            ],
        )
    )

    mocked_response = {
        "enabled": True,
        "answers": {
            "select_runbook": {
                "type": "choice",
                "choice": "detection_rule_tuning",
                "confidence": 0.94,
            },
            "tool_needed_validate_rule": {
                "type": "noul",
                "noul": 0.95,
                "confidence": 0.96,
            },
        },
        "usage": {"total_input_tokens": 980, "total_output_tokens": 0},
    }
    ctx = SimpleNamespace(state={})

    with patch.object(
        pruner, "aevaluate_decisions", new=AsyncMock(return_value=mocked_response)
    ) as mock_eval:
        ret1 = asyncio.run(pruner.progressive_tool_pruner_callback(ctx, req1))  # type: ignore[arg-type]
        hash1 = pruner.compute_prefix_hash(req1)

        # Step 2: tool-response continuation -> 0 RPCs, 0.0 ms, byte-identical prefix!
        ret2 = asyncio.run(pruner.progressive_tool_pruner_callback(ctx, req2))  # type: ignore[arg-type]
        hash2 = pruner.compute_prefix_hash(req2)

    assert ret1 is None and ret2 is None
    assert mock_eval.await_count == 1
    assert hash1 == hash2
    assert list(req2.tools_dict.keys()) == ["validate_rule"]
    assert ctx.state["tool_pruner_last_metrics"]["cache_hit"] is True
    assert ctx.state["tool_pruner_last_metrics"]["rpc_count"] == 0
    assert ctx.state["tool_pruner_last_metrics"]["decision_latency_ms"] == 0.0

    # Step 3: A brand new user prompt invalidates the pin and calls Decision 1 once.
    req3 = pruner.build_baseline_llm_request("Isolate compromised host srv-ad-02.")
    with patch.object(
        pruner, "aevaluate_decisions", new=AsyncMock(return_value=mocked_response)
    ) as mock_eval2:
        asyncio.run(pruner.progressive_tool_pruner_callback(ctx, req3))  # type: ignore[arg-type]
    assert mock_eval2.await_count == 1


def test_workflow2_dry_run_end_to_end(tmp_path: pathlib.Path) -> None:
    out_file = tmp_path / "wf2_dry.json"
    payload = asyncio.run(wf2.run_workflow(dry_run=True, json_out=str(out_file)))

    assert out_file.exists()
    parsed = json.loads(out_file.read_text(encoding="utf-8"))
    summary = parsed["summary"]
    assert summary["mode"] == "dry_run"
    assert summary["scenarios_evaluated"] == 10
    assert summary["kv_cache_intact_count"] == 10
    assert summary["total_rpcs_across_30_steps"] == 10
    assert summary["runbook_accuracy"] == 1.0
    assert summary["mean_tool_recall"] == 1.0
    assert summary["total_decision_output_tokens"] == 0
    assert summary["mean_net_3step_tokens_saved"] > 0
    assert len(payload["scenarios"]) == 10
