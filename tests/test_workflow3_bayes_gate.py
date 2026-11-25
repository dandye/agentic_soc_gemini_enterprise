"""Unit tests for Workflow 3: Epistemic & Cost-Weighted Bayes Gate."""

from __future__ import annotations

import asyncio
import json
import pathlib
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from governed_agents.shared_decision_guards.bayes_containment_gate import (
    ASSET_TIER_LOSSES,
    EPISTEMIC_CHECK_KEYS,
    AssetTier,
    ContainmentAction,
    compute_expected_losses,
    compute_udm_window_bucket,
    decide_containment_action,
    evaluate_bayes_containment_gate,
    make_bayes_after_model_callback,
    make_bayes_epistemic_before_model_callback,
    normalize_asset_tier,
    run_epistemic_probe_loop,
)
from scripts.governance.workflows import run_workflow3_bayes_gate


def _make_d1_response(
    *,
    p_compromise: float = 0.05,
    confidence: float | None = None,
    checks: dict[str, float] | None = None,
) -> dict[str, Any]:
    check_probs = dict.fromkeys(EPISTEMIC_CHECK_KEYS, 0.95)
    if checks:
        check_probs.update(checks)
    resolved_conf = (
        max(p_compromise, 1.0 - p_compromise) if confidence is None else confidence
    )
    answers: dict[str, Any] = {
        "compromise_detected": {
            "type": "noul",
            "noul": p_compromise,
            "confidence": resolved_conf,
        }
    }
    for key, prob in check_probs.items():
        answers[key] = {
            "type": "noul",
            "noul": prob,
            "confidence": max(prob, 1.0 - prob),
        }
    return {"enabled": True, "model": "gemini-decision-1", "answers": answers}


def test_expected_loss_math_and_window_bucket() -> None:
    assert ASSET_TIER_LOSSES[AssetTier.LOW].l_fp == 500.0
    assert ASSET_TIER_LOSSES[AssetTier.LOW].l_fn == 10_000.0
    assert ASSET_TIER_LOSSES[AssetTier.STANDARD].l_fp == 5_000.0
    assert ASSET_TIER_LOSSES[AssetTier.STANDARD].l_fn == 50_000.0
    assert ASSET_TIER_LOSSES[AssetTier.HIGH].l_fp == 25_000.0
    assert ASSET_TIER_LOSSES[AssetTier.HIGH].l_fn == 150_000.0
    assert ASSET_TIER_LOSSES[AssetTier.CRITICAL].l_fp == 50_000.0
    assert ASSET_TIER_LOSSES[AssetTier.CRITICAL].l_fn == 250_000.0

    assert normalize_asset_tier("tier-0") == AssetTier.CRITICAL
    assert (
        ContainmentAction.ESCALATE_CHG_GATE
        is ContainmentAction.RECOMMEND_TIER0_CHG_ESCALATION
    )

    e_close, e_isolate, p_star = compute_expected_losses(0.80, AssetTier.STANDARD)
    assert e_close == 40_000.0
    assert e_isolate == 1_000.0
    assert p_star == pytest.approx(5_000.0 / 55_000.0)

    assert (
        compute_udm_window_bucket("2026-11-11T00:00:00Z", "2026-11-14T00:00:00Z")
        == "[COMPUTED_WINDOW_HOURS: 72]"
    )
    assert (
        compute_udm_window_bucket("2026-11-07T00:00:00Z", "2026-11-14T00:00:00Z")
        == "[COMPUTED_WINDOW_HOURS: 168]"
    )


def test_inverted_confidence_bug_fixed_p25_routes_to_force_probe_more() -> None:
    """P=0.25 gives Decisions API confidence=0.75 (in NO); must NOT isolate."""
    decision = decide_containment_action(
        asset_id="SRV-PROD-09",
        asset_tier=AssetTier.STANDARD,
        decision1_response=_make_d1_response(p_compromise=0.25, confidence=0.75),
    )
    assert decision.expected_loss_close_usd > decision.expected_loss_isolate_usd
    assert decision.action == ContainmentAction.FORCE_PROBE_MORE
    assert decision.reflection_prompt is not None
    assert "[EPISTEMIC_INVESTIGATION_ADVISORY]" in decision.reflection_prompt


def test_intermediate_band_between_p_star_and_close_max_p_forces_probe() -> None:
    """On STANDARD, P*=0.0909 < P=0.12 <= close_max_p=0.15 must probe more."""
    decision = decide_containment_action(
        asset_id="SRV-APP-19",
        asset_tier=AssetTier.STANDARD,
        decision1_response=_make_d1_response(p_compromise=0.12),
    )
    assert decision.action == ContainmentAction.FORCE_PROBE_MORE


def test_branch_auto_close_benign() -> None:
    decision = decide_containment_action(
        asset_id="SRV-WEB-04",
        asset_tier=AssetTier.STANDARD,
        decision1_response=_make_d1_response(p_compromise=0.04),
    )
    assert decision.action == ContainmentAction.AUTO_CLOSE_BENIGN
    assert decision.missing_epistemic_checks == []
    assert not decision.requires_chg_ticket
    assert decision.reflection_prompt is None


@pytest.mark.parametrize("missing_key", EPISTEMIC_CHECK_KEYS)
def test_branch_force_probe_more_on_missing_epistemic_check(missing_key: str) -> None:
    decision = decide_containment_action(
        asset_id="WS-FIN-112",
        asset_tier=AssetTier.HIGH,
        decision1_response=_make_d1_response(
            p_compromise=0.85,
            checks={missing_key: 0.20},
        ),
    )
    assert decision.action == ContainmentAction.FORCE_PROBE_MORE
    assert missing_key in decision.missing_epistemic_checks
    assert decision.reflection_prompt is not None


def test_branch_auto_isolate_contain_on_standard_asset() -> None:
    decision = decide_containment_action(
        asset_id="WS-ENG-089",
        asset_tier=AssetTier.STANDARD,
        decision1_response=_make_d1_response(p_compromise=0.92),
    )
    assert decision.action == ContainmentAction.AUTO_ISOLATE_CONTAIN
    assert decision.expected_loss_close_usd > decision.expected_loss_isolate_usd
    assert not decision.requires_chg_ticket


def test_branch_recommend_tier0_chg_escalation_on_critical() -> None:
    decision = decide_containment_action(
        asset_id="DC-PROD-01",
        asset_tier=AssetTier.CRITICAL,
        decision1_response=_make_d1_response(p_compromise=0.95),
    )
    assert decision.action == ContainmentAction.RECOMMEND_TIER0_CHG_ESCALATION
    assert decision.requires_chg_ticket is True
    assert decision.expected_loss_close_usd == 237_500.0
    assert decision.expected_loss_isolate_usd == 2_500.0


def test_single_decision1_call_evaluates_all_five_questions() -> None:
    mock_resp = _make_d1_response(p_compromise=0.03)
    with patch(
        "governed_agents.shared_decision_guards.bayes_containment_gate.evaluate_decisions",
        return_value=mock_resp,
    ) as mock_eval:
        decision = evaluate_bayes_containment_gate(
            'TOOL_RESPONSE cmdb_lookup: {"hostname": "SRV-WEB-04"}',
            asset_id="SRV-WEB-04",
            asset_tier="STANDARD",
        )
    assert mock_eval.call_count == 1
    questions = mock_eval.call_args.args[1]
    assert set(questions.keys()) == {"compromise_detected", *EPISTEMIC_CHECK_KEYS}
    assert all(q["type"] == "noul" for q in questions.values())
    assert decision.action == ContainmentAction.AUTO_CLOSE_BENIGN


def test_graceful_fallback_when_decision1_disabled_or_errors() -> None:
    disabled = decide_containment_action(
        asset_id="WS-01",
        asset_tier=AssetTier.LOW,
        decision1_response={"enabled": False, "reason": "unset", "answers": {}},
    )
    assert disabled.fallback is True
    assert disabled.action == ContainmentAction.FORCE_PROBE_MORE

    critical_err = decide_containment_action(
        asset_id="DC-PROD-01",
        asset_tier=AssetTier.CRITICAL,
        decision1_response={"enabled": True, "error": "TimeoutError", "answers": {}},
    )
    assert critical_err.fallback is True
    assert critical_err.action == ContainmentAction.RECOMMEND_TIER0_CHG_ESCALATION
    assert critical_err.requires_chg_ticket is True


def test_epistemic_before_model_callback_injects_advisory_before_generation() -> None:
    callback = make_bayes_epistemic_before_model_callback(
        default_asset_id="WS-FIN-112",
        default_asset_tier=AssetTier.HIGH,
        max_probe_injections=1,
    )
    ctx = SimpleNamespace(state={"asset_id": "WS-FIN-112", "asset_tier": "HIGH"})
    req = SimpleNamespace(
        config=SimpleNamespace(system_instruction="You are a SOC analyst."),
        contents=[
            SimpleNamespace(
                parts=[
                    SimpleNamespace(
                        text=None,
                        function_call=None,
                        function_response=SimpleNamespace(
                            name="udm_search",
                            response={"total_events": 0, "window_hours": 72},
                        ),
                    )
                ]
            )
        ],
    )

    incomplete_resp = _make_d1_response(
        p_compromise=0.40,
        checks={"widened_72h_to_168h_on_empty_hunt": 0.10},
    )
    with patch(
        "governed_agents.shared_decision_guards.bayes_containment_gate.aevaluate_decisions",
        new=AsyncMock(return_value=incomplete_resp),
    ):
        result = asyncio.run(callback(ctx, req))
        assert result is None
        assert "[EPISTEMIC_INVESTIGATION_ADVISORY]" in req.config.system_instruction
        assert "168 hours" in req.config.system_instruction
        assert ctx.state["bayes_probe_injections"] == 1

        # Second call respects max_probe_injections=1
        prev_inst = req.config.system_instruction
        asyncio.run(callback(ctx, req))
        assert req.config.system_instruction == prev_inst


def test_epistemic_before_model_callback_skips_without_tool_response() -> None:
    callback = make_bayes_epistemic_before_model_callback()
    ctx = SimpleNamespace(state={})
    req = SimpleNamespace(
        config=SimpleNamespace(system_instruction="Base"),
        contents=[
            SimpleNamespace(
                parts=[
                    SimpleNamespace(
                        text="Triage alert", function_call=None, function_response=None
                    )
                ]
            )
        ],
    )
    with patch(
        "governed_agents.shared_decision_guards.bayes_containment_gate.aevaluate_decisions",
        new=AsyncMock(),
    ) as mock_aeval:
        result = asyncio.run(callback(ctx, req))
        assert result is None
        mock_aeval.assert_not_called()


def test_run_epistemic_probe_loop_executes_missing_probe() -> None:
    incomplete = _make_d1_response(
        p_compromise=0.40,
        checks={"widened_72h_to_168h_on_empty_hunt": 0.10},
    )
    complete = _make_d1_response(p_compromise=0.92)

    async def _probe_exec(missing: list[str], _decision: Any) -> str:
        assert "widened_72h_to_168h_on_empty_hunt" in missing
        return "TOOL_RESPONSE udm_search [COMPUTED_WINDOW_HOURS: 168]: hits=12"

    with patch(
        "governed_agents.shared_decision_guards.bayes_containment_gate.aevaluate_decisions",
        new=AsyncMock(side_effect=[incomplete, complete]),
    ):
        final = asyncio.run(
            run_epistemic_probe_loop(
                "TOOL_RESPONSE udm_search [COMPUTED_WINDOW_HOURS: 72]: hits=0",
                asset_id="WS-ENG-089",
                asset_tier=AssetTier.STANDARD,
                probe_executor=_probe_exec,
            )
        )
    assert final.action == ContainmentAction.AUTO_ISOLATE_CONTAIN


def test_after_model_callback_synthesizes_function_call_when_mapped() -> None:
    callback = make_bayes_after_model_callback(
        default_asset_id="WS-FIN-112",
        default_asset_tier=AssetTier.HIGH,
        probe_tool_map={
            "widened_72h_to_168h_on_empty_hunt": ("udm_search", {"hours": 168})
        },
    )
    ctx = SimpleNamespace(state={})
    part = SimpleNamespace(text="72h hunt empty.", function_call=None)
    llm_resp = SimpleNamespace(content=SimpleNamespace(parts=[part]))
    incomplete = _make_d1_response(
        p_compromise=0.40,
        checks={"widened_72h_to_168h_on_empty_hunt": 0.10},
    )
    with patch(
        "governed_agents.shared_decision_guards.bayes_containment_gate.aevaluate_decisions",
        new=AsyncMock(return_value=incomplete),
    ):
        result = asyncio.run(callback(ctx, llm_resp))
        assert result is llm_resp
        assert len(llm_resp.content.parts) == 1
        assert llm_resp.content.parts[0].function_call.name == "udm_search"


def test_workflow3_runner_dry_run_eight_scenarios(tmp_path: pathlib.Path) -> None:
    out_file = tmp_path / "workflow3_dry_run.json"
    exit_code = run_workflow3_bayes_gate.main(
        ["--dry-run", "--json-out", str(out_file)]
    )
    assert exit_code == 0
    payload = json.loads(out_file.read_text())
    assert len(payload) == 8
    assert all(row["matched"] is True for row in payload)
    actions = {row["scenario_id"]: row["action"] for row in payload}
    assert actions == {
        "qualys_widened_168h_clean_scanner": "AUTO_CLOSE_BENIGN",
        "incomplete_72h_empty_hunt": "FORCE_PROBE_MORE",
        "borderline_single_source_ambiguous": "FORCE_PROBE_MORE",
        "unverified_cmdb_tier_lolbin": "FORCE_PROBE_MORE",
        "unsigned_lolbin_workstation_c2": "AUTO_ISOLATE_CONTAIN",
        "compromised_high_tier_db_server": "AUTO_ISOLATE_CONTAIN",
        "signed_benign_backup_admin": "AUTO_CLOSE_BENIGN",
        "dc_prod_ntdsutil": "RECOMMEND_TIER0_CHG_ESCALATION",
    }
