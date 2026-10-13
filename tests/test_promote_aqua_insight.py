"""Unit tests for Phase 5: Outer-to-inner loop bridge (scripts/promote_aqua_insight.py) and HYP-007 registration."""

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_validate_snapshot_citations():
    """Verify validate_snapshot_citations accepts valid <path>:<start>-<end> citations and rejects hallucinated ones."""
    from scripts.promote_aqua_insight import validate_snapshot_citations

    valid_res = validate_snapshot_citations(
        ["agent_soc_manager/agent.py:1-25", "docs/aqua_goal.md:1-20"],
        root_dir=REPO_ROOT,
    )
    assert valid_res["valid"] is True
    assert valid_res["invalid_citations"] == []

    invalid_res = validate_snapshot_citations(
        [
            "agent_soc_manager/nonexistent_file.py:1-10",
            "docs/aqua_goal.md:9999-10050",
        ],
        root_dir=REPO_ROOT,
    )
    assert invalid_res["valid"] is False
    assert len(invalid_res["invalid_citations"]) == 2


def test_promote_insight_omits_confidence_and_generates_hermetic_stubs(tmp_path: Path):
    """Verify promote_insight_to_evalset drops uncalibrated confidence and builds hermetic mock_tool_responses."""
    from scripts.promote_aqua_insight import promote_insight_to_evalset

    sample_insight = {
        "insight_id": "AQUA-INS-2026-0042",
        "title": "Dropped 7-Day Lookback Window During Specialist Delegation",
        "severity": "HIGH",
        "impact": "HIGH",
        "confidence": 0.97,  # Must be stripped per Melnyk et al. (2026)
        "affected_sessions_count": 14,
        "code_citations": ["agent_soc_manager/agent.py:1-30"],
        "failing_trajectory": {
            "session_id": "sess-prod-9981",
            "user_prompt": "Hunt for suspicious PowerShell executions on wks-finance-04 over the last 7 days.",
            "tool_calls": [
                {
                    "name": "udm_search",
                    "args": {
                        "query": 'principal.hostname = "wks-finance-04"',
                        "hours_back": 24,
                    },
                    "response": {"events": [], "total_events": 0},
                }
            ],
            "final_response": "No suspicious events found in the last 24 hours.",
        },
        "expected_behavior": "Preserve hours_back=168 across udm_search and specialist delegation.",
        "expected_tools": ["udm_search"],
    }

    target_evalset = tmp_path / "aqua_regressions.evalset.json"
    promoted_case = promote_insight_to_evalset(
        insight=sample_insight,
        evalset_path=target_evalset,
        root_dir=REPO_ROOT,
    )

    # Confidence must be omitted from the promoted record
    serialized = json.dumps(promoted_case)
    assert '"confidence"' not in serialized
    assert promoted_case["metadata"]["severity"] == "HIGH"
    assert promoted_case["metadata"]["impact"] == "HIGH"
    assert promoted_case["metadata"]["affected_sessions_count"] == 14

    # Hermetic mock tool stubs must be populated
    stubs = promoted_case["reference"].get("mock_tool_responses", {})
    assert "udm_search" in stubs

    # File on disk must be updated and idempotent on re-promotion
    data = json.loads(target_evalset.read_text(encoding="utf-8"))
    assert data["evalset_id"] == "aqua_regressions"
    assert len(data["eval_cases"]) == 1


def test_aqua_regressions_evalset_and_hyp_007_registered():
    """Verify evalsets/aqua_regressions.evalset.json and HYP-007 in evalsets/HYPOTHESES.md exist and are valid."""
    reg_path = REPO_ROOT / "evalsets" / "aqua_regressions.evalset.json"
    assert reg_path.exists(), "evalsets/aqua_regressions.evalset.json must exist"
    reg_data = json.loads(reg_path.read_text(encoding="utf-8"))
    assert reg_data["evalset_id"] == "aqua_regressions"
    assert len(reg_data.get("eval_cases", [])) >= 1

    hyp_path = REPO_ROOT / "evalsets" / "HYPOTHESES.md"
    hyp_text = hyp_path.read_text(encoding="utf-8")
    assert hyp_text.startswith("---\n")
    assert "HYP-007" in hyp_text
    assert (
        "Two-Loop Agent Quality Flywheel" in hyp_text
        or "Ambient Quality Agent" in hyp_text
    )
    assert "Falsification Criteria" in hyp_text

    readme_path = REPO_ROOT / "evalsets" / "README.md"
    readme_text = readme_path.read_text(encoding="utf-8")
    assert readme_text.startswith("---\n")
    assert "multi_turn_pivots.evalset.json" in readme_text
    assert "aqua_regressions.evalset.json" in readme_text
