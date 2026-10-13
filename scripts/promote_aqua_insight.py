#!/usr/bin/env python3
"""
Outer-to-Inner Loop Bridge: Promote AQuA Insights to Regression EvalSet (`HYP-007`).

Validates `<path>:<start>-<end>` file-and-line citations against the versioned
source snapshot (or repository root), strips uncalibrated LLM `confidence`
scores (per Melnyk et al., 2026), and compiles failing production trajectories
into `evalsets/aqua_regressions.evalset.json` with hermetic mock tool stubs.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVALSET_PATH = REPO_ROOT / "evalsets" / "aqua_regressions.evalset.json"
DEFAULT_INSIGHTS_PATH = REPO_ROOT / "aqua" / "insights.json"

_CITATION_PATTERN = re.compile(
    r"^(?P<path>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$"
)


def validate_snapshot_citations(
    citations: list[str],
    root_dir: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """Validate `<path>:<start>-<end>` citations against a source snapshot or repository root."""
    base = Path(root_dir)
    valid_citations: list[str] = []
    invalid_citations: list[dict[str, str]] = []

    for raw in citations:
        citation = raw.strip()
        match = _CITATION_PATTERN.match(citation)
        if not match:
            invalid_citations.append(
                {
                    "citation": citation,
                    "reason": "Citation does not match '<path>:<start>-<end>' format.",
                }
            )
            continue

        rel_path = match.group("path").lstrip("./")
        start_line = int(match.group("start"))
        end_line = int(match.group("end") or start_line)

        if start_line < 1 or end_line < start_line:
            invalid_citations.append(
                {
                    "citation": citation,
                    "reason": f"Invalid line range {start_line}-{end_line}.",
                }
            )
            continue

        target_file = base / rel_path
        if not target_file.exists() or not target_file.is_file():
            invalid_citations.append(
                {
                    "citation": citation,
                    "reason": f"File '{rel_path}' does not exist in snapshot.",
                }
            )
            continue

        try:
            total_lines = len(
                target_file.read_text(encoding="utf-8", errors="replace").splitlines()
            )
        except Exception as exc:
            invalid_citations.append(
                {
                    "citation": citation,
                    "reason": f"Unable to read '{rel_path}': {exc}",
                }
            )
            continue

        if end_line > total_lines:
            invalid_citations.append(
                {
                    "citation": citation,
                    "reason": f"Line range {start_line}-{end_line} exceeds file length ({total_lines} lines).",
                }
            )
            continue

        valid_citations.append(citation)

    return {
        "valid": len(invalid_citations) == 0,
        "valid_citations": valid_citations,
        "invalid_citations": invalid_citations,
    }


def _build_hermetic_tool_stubs(tool_calls: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract deterministic mock responses from recorded production tool calls."""
    stubs: dict[str, Any] = {}
    for call in tool_calls:
        name = str(call.get("name") or "").strip()
        if not name:
            continue
        stubs[name] = {
            "recorded_args": call.get("args", {}),
            "mock_response": call.get("response", {"status": "stubbed"}),
        }
    return stubs


def promote_insight_to_evalset(
    insight: dict[str, Any],
    evalset_path: Path | str = DEFAULT_EVALSET_PATH,
    root_dir: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """Validate an AQuA insight and promote its failing trajectory into aqua_regressions.evalset.json."""
    insight_id = str(insight.get("insight_id") or "AQUA-INS-UNKNOWN")
    citations = list(insight.get("code_citations") or [])
    citation_check = validate_snapshot_citations(citations, root_dir=root_dir)
    if not citation_check["valid"]:
        raise ValueError(
            f"Insight {insight_id} contains invalid code citations: {citation_check['invalid_citations']}"
        )

    trajectory = insight.get("failing_trajectory") or {}
    user_prompt = str(trajectory.get("user_prompt") or "")
    tool_calls = list(trajectory.get("tool_calls") or [])
    expected_tools = list(
        insight.get("expected_tools")
        or [c.get("name") for c in tool_calls if c.get("name")]
    )

    # Note: Uncalibrated 'confidence' is intentionally excluded per Melnyk et al. (2026)
    promoted_case = {
        "eval_id": f"aqua_reg_{insight_id.lower().replace('-', '_')}",
        "name": f"[{insight.get('severity', 'HIGH')}] {insight.get('title', insight_id)}",
        "split": insight.get("split", "train"),
        "metadata": {
            "insight_id": insight_id,
            "severity": str(insight.get("severity") or "HIGH").upper(),
            "impact": str(insight.get("impact") or "HIGH").upper(),
            "affected_sessions_count": int(
                insight.get("affected_sessions_count") or 1
            ),
            "verified_code_citations": citation_check["valid_citations"],
            "source_session_id": str(trajectory.get("session_id") or "unknown"),
            "promoted_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "conversation": [
            {
                "role": "user",
                "content": user_prompt,
            }
        ],
        "reference": {
            "expected_specialist": insight.get(
                "expected_specialist", "orchestrator_direct"
            ),
            "tool_trajectory": expected_tools,
            "grading_rubric": str(
                insight.get("expected_behavior")
                or "Resolve the failure mode identified by AQuA."
            ),
            "mock_tool_responses": _build_hermetic_tool_stubs(tool_calls),
            "categorical_rubrics": [
                "temporal_grounding",
                "mid_investigation_pivot_honored",
                "hitl_containment_safety",
                "attribution_footer_compliance",
            ],
        },
    }

    target_path = Path(evalset_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if target_path.exists():
        evalset_data = json.loads(target_path.read_text(encoding="utf-8"))
    else:
        evalset_data = {
            "evalset_id": "aqua_regressions",
            "name": "AQuA Outer-Loop Promoted Production Regressions",
            "description": "Regression cases promoted from Ambient Quality Agent (AQuA) production insights with hermetic mock tool stubs (HYP-007).",
            "eval_cases": [],
        }

    cases: list[dict[str, Any]] = list(evalset_data.get("eval_cases") or [])
    replaced = False
    for idx, existing in enumerate(cases):
        if existing.get("eval_id") == promoted_case["eval_id"]:
            cases[idx] = promoted_case
            replaced = True
            break
    if not replaced:
        cases.append(promoted_case)

    evalset_data["eval_cases"] = cases
    target_path.write_text(
        json.dumps(evalset_data, indent=2) + "\n", encoding="utf-8"
    )
    return promoted_case


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Promote a failing AQuA production insight into evalsets/aqua_regressions.evalset.json"
    )
    parser.add_argument(
        "--insight-id",
        required=True,
        help="ID of the AQuA insight to promote (e.g. AQUA-INS-2026-0001)",
    )
    parser.add_argument(
        "--insights-file",
        type=Path,
        default=DEFAULT_INSIGHTS_PATH,
        help="Path to JSON file containing exported AQuA insights",
    )
    parser.add_argument(
        "--evalset-file",
        type=Path,
        default=DEFAULT_EVALSET_PATH,
        help="Target regression evalset JSON file",
    )
    args = parser.parse_args()

    if not args.insights_file.exists():
        raise SystemExit(
            f"[FAIL] Insights file not found: {args.insights_file}"
        )

    raw_data = json.loads(args.insights_file.read_text(encoding="utf-8"))
    insights_list = (
        raw_data.get("insights", []) if isinstance(raw_data, dict) else raw_data
    )
    matched = next(
        (
            item
            for item in insights_list
            if item.get("insight_id") == args.insight_id
        ),
        None,
    )
    if matched is None:
        raise SystemExit(
            f"[FAIL] Insight ID '{args.insight_id}' not found in {args.insights_file}"
        )

    promoted = promote_insight_to_evalset(
        insight=matched,
        evalset_path=args.evalset_file,
        root_dir=REPO_ROOT,
    )
    print(
        f"[PASS] Promoted insight {args.insight_id} -> {promoted['eval_id']} in {args.evalset_file}"
    )


if __name__ == "__main__":
    main()
