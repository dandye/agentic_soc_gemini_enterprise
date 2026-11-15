"""Hermetic tests for the unified Decision 1 client, shims, and container packaging."""

from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from governed_agents.shared_decision_guards import decision_client as canonical_client


REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "terraform" / "dist"
AGENTS_DIR = REPO_ROOT / "governed_agents"


def _make_httpx_response(
    status_code: int, json_body: dict[str, Any] | None = None, text: str = ""
) -> MagicMock:
    import httpx

    resp = MagicMock()
    resp.status_code = status_code
    if json_body is not None:
        resp.json.return_value = json_body
        resp.text = text or str(json_body)
    else:
        resp.json.side_effect = ValueError("not json")
        resp.text = text
    if status_code >= 400:
        req = httpx.Request("POST", "https://example.invalid/v1beta/decisions")
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status_code}", request=req, response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


def test_question_builders_and_noul_criteria() -> None:
    """noul_question supports optional criteria alongside choice_question and score_question."""
    q_plain = canonical_client.noul_question("Is this malicious?")
    assert q_plain == {"type": "noul", "instructions": "Is this malicious?"}

    q_crit = canonical_client.noul_question(
        "Is this a prompt injection?",
        criteria={"yes": "Attempts instruction override", "no": "Normal SOC query"},
    )
    assert q_crit["criteria"] == {
        "yes": "Attempts instruction override",
        "no": "Normal SOC query",
    }

    q_choice = canonical_client.choice_question("Pick one", {"a": "A", "b": "B"})
    assert q_choice == {
        "type": "choice",
        "instructions": "Pick one",
        "criteria": {"a": "A", "b": "B"},
    }

    q_score = canonical_client.score_question("Rate", ["L0", "L1", "L2"])
    assert q_score == {
        "type": "score",
        "instructions": "Rate",
        "criteria": ["L0", "L1", "L2"],
    }


def test_multimodal_list_input_and_custom_params_sync_and_async() -> None:
    """Supports multimodal list inputs without .strip() crashes and custom model/endpoint/user_id."""
    assert (
        canonical_client.evaluate_decisions([], {"q": {"type": "noul"}})["enabled"]
        is False
    )
    assert (
        asyncio.run(canonical_client.aevaluate_decisions([], {"q": {"type": "noul"}}))[
            "enabled"
        ]
        is False
    )

    parts = [
        {"type": "text", "text": "Triage this screenshot"},
        {"type": "image", "data": "iVBORw0KGgo=", "mime_type": "image/png"},
    ]
    questions = {
        "is_threat": canonical_client.noul_question("Threat?"),
        "cat": canonical_client.choice_question("Category?", {"c2": "C2"}),
        "sev": canonical_client.score_question(
            "Severity?", ["L0", "L1", "L2", "L3", "L4"]
        ),
    }
    ok_payload = {
        "answers": {
            "is_threat": {"type": "noul", "noul": 0.88, "confidence": 0.91},
            "cat": {
                "type": "choice",
                "choice": "c2",
                "confidence": 0.86,
                "probabilities": {"c2": 0.86},
            },
            "sev": {
                "type": "score",
                "score": 3.0,
                "confidence": 0.82,
                "probabilities": {"3": 0.82},
                "legend": {"3": "High"},
            },
        },
        "usage": {"inputTokens": 321},
    }

    sync_client = MagicMock()
    sync_client.post.return_value = _make_httpx_response(200, ok_payload)

    async def fake_async_post(*_: Any, **__: Any) -> MagicMock:
        return _make_httpx_response(200, ok_payload)

    async_client = MagicMock()
    async_client.post.side_effect = fake_async_post

    with (
        patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}, clear=False),
        patch.object(canonical_client, "_get_http_client", return_value=sync_client),
        patch.object(
            canonical_client, "_get_async_http_client", return_value=async_client
        ),
    ):
        os.environ.pop("GEMINI_AUTH_PROVIDER", None)
        res = canonical_client.evaluate_decisions(
            parts,
            questions,
            model="gemini-decision-1",
            endpoint="https://example.invalid/v1beta/decisions",
            timeout=9.5,
            user_id="custom_user",
        )
        assert res["enabled"] is True
        assert res["model"] == "gemini-decision-1"
        assert res["answers"]["sev"]["raw_score"] == 3.0
        assert res["answers"]["sev"]["score"] == 4.0
        assert res["answers"]["sev"]["legend"] == {"3": "High"}
        call_args = sync_client.post.call_args
        assert call_args.args[0] == "https://example.invalid/v1beta/decisions"
        assert call_args.kwargs["timeout"] == 9.5
        assert isinstance(call_args.kwargs["json"]["input"], list)

        ares = asyncio.run(
            canonical_client.aevaluate_decisions(
                parts,
                questions,
                model="gemini-decision-1",
                endpoint="https://example.invalid/v1beta/decisions",
                timeout=9.5,
                user_id="custom_user",
            )
        )
        assert ares["enabled"] is True
        assert ares["answers"]["sev"]["score"] == 4.0


def test_http_400_safety_block_detection() -> None:
    """Detects HTTP 400 safety blocks and sets safety_blocked=True alongside error."""
    safety_bodies = [
        {"error": {"code": "SAFETY", "message": "Blocked by safety filter"}},
        {"error": {"status": "prohibited_content", "message": "Disallowed"}},
        {"error": {"details": [{"reason": "IMAGE_SAFETY"}]}},
        {"error": {"code": 400, "message": "Request blocked due to safety policy"}},
    ]
    sync_client = MagicMock()
    with (
        patch.dict(os.environ, {"GEMINI_API_KEY": "fake-key"}, clear=False),
        patch.object(canonical_client, "_get_http_client", return_value=sync_client),
    ):
        os.environ.pop("GEMINI_AUTH_PROVIDER", None)
        for body in safety_bodies:
            sync_client.post.return_value = _make_httpx_response(400, body)
            res = canonical_client.evaluate_decisions(
                "test input", {"q": {"type": "noul"}}
            )
            assert res["enabled"] is True
            assert res.get("safety_blocked") is True
            assert "HTTP 400" in res["error"]

        sync_client.post.return_value = _make_httpx_response(
            400,
            {"error": {"code": "INVALID_ARGUMENT", "message": "Malformed question"}},
        )
        non_safety = canonical_client.evaluate_decisions(
            "test input", {"q": {"type": "noul"}}
        )
        assert non_safety["enabled"] is True
        assert "safety_blocked" not in non_safety
        assert "HTTP 400" in non_safety["error"]


def test_agent_shims_resolve_to_canonical_client() -> None:
    """Agent decision_client.py shims re-export the canonical shared_decision_guards client."""
    for agent_name in ("soc_orchestrator", "threat_hunter", "cti_researcher"):
        shim_path = AGENTS_DIR / agent_name / "decision_client.py"
        assert shim_path.is_file()
        mod_name = f"governed_agents.{agent_name}.decision_client"
        sys.modules.pop(mod_name, None)
        shim_mod = __import__(mod_name, fromlist=["*"])
        assert shim_mod.evaluate_decisions is canonical_client.evaluate_decisions
        assert shim_mod.aevaluate_decisions is canonical_client.aevaluate_decisions


def test_packaged_archive_bundles_shared_guards_and_imports_isolated(
    tmp_path: Path,
) -> None:
    """Extracting threat_hunter.tar.gz into /tmp allows isolated import of shared_decision_guards."""
    archive_path = DIST_DIR / "threat_hunter.tar.gz"
    assert archive_path.is_file(), "Run scripts/governance/package_agent.sh all first"

    extract_dir = tmp_path / "container_root"
    extract_dir.mkdir()
    with tarfile.open(archive_path, "r:gz") as tf:
        names = tf.getnames()
        assert "agent.py" in names
        assert "requirements.txt" in names
        assert "shared_decision_guards/decision_client.py" in names
        tf.extractall(extract_dir, filter="data")

    code = (
        "import sys; "
        f"sys.path.insert(0, {str(extract_dir)!r}); "
        "import shared_decision_guards.decision_client as sdc; "
        "import decision_client as dc; "
        "assert dc.evaluate_decisions is sdc.evaluate_decisions; "
        "assert dc.aevaluate_decisions is sdc.aevaluate_decisions"
    )
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"Isolated import failed:\n{proc.stderr}"


def test_packaged_sha256_matches_python_hash_for_all_agents() -> None:
    """Every dist/<agent>.sha256 matches the agent_files + shared_decision_guards formula."""
    shared_dir = AGENTS_DIR / "shared_decision_guards"
    shared_entries: dict[str, Path] = {}
    for p in shared_dir.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(shared_dir).as_posix()
        if "__pycache__/" in f"/{rel}" or rel.endswith((".pyc", ".pyo")):
            continue
        shared_entries[f"shared_decision_guards/{rel}"] = p

    for agent_name in (
        "cti_researcher",
        "threat_hunter",
        "detection_engineer",
        "tier2_responder",
        "soc_orchestrator",
    ):
        agent_dir = AGENTS_DIR / agent_name
        entries = dict(shared_entries)
        for p in agent_dir.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(agent_dir).as_posix()
            if "__pycache__/" in f"/{rel}" or rel.endswith((".pyc", ".pyo")):
                continue
            entries[rel] = p

        hasher = hashlib.sha256()
        for rel in sorted(entries):
            file_digest = hashlib.sha256(entries[rel].read_bytes()).hexdigest()
            hasher.update(f"{rel}\n{file_digest}\n".encode())
        expected = hasher.hexdigest()

        sha_file = DIST_DIR / f"{agent_name}.sha256"
        assert sha_file.is_file()
        assert sha_file.read_text(encoding="utf-8").strip() == expected
