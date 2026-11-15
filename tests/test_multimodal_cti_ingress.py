"""Hermetic unit tests for pre-agent multimodal CTI ingress and Slice 3 fixes."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from governed_agents.shared_decision_guards import multimodal_cti_ingress  # noqa: E402


def _placeholder_adc_path() -> str:
    configured = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if configured:
        return configured
    path = Path(tempfile.gettempdir()) / "governed_agents_placeholder_adc.json"
    if not path.exists():
        path.write_text(
            json.dumps(
                {
                    "type": "authorized_user",
                    "client_id": "placeholder.apps.googleusercontent.com",
                    "client_secret": "placeholder",
                    "refresh_token": "placeholder",
                    "quota_project_id": "example-secops-project",
                }
            )
        )
    return str(path)


_HERMETIC_ENV = {
    "GOOGLE_CLOUD_PROJECT": "example-secops-project",
    "GOOGLE_CLOUD_LOCATION": "us-central1",
    "GOOGLE_GENAI_USE_VERTEXAI": "TRUE",
    "GOOGLE_APPLICATION_CREDENTIALS": _placeholder_adc_path(),
    "GTI_AUTH_PROVIDER": (
        "projects/example-secops-project/locations/us-central1/"
        "authProviders/agw-secops-gti-api-key"
    ),
    "CHRONICLE_PROJECT_ID": "example-secops-project",
    "CHRONICLE_CUSTOMER_ID": "00000000-0000-0000-0000-000000000000",
    "CHRONICLE_REGION": "us",
    "CTI_RESEARCHER_URL": "https://example.invalid/cti/a2a",
    "THREAT_HUNTER_URL": "https://example.invalid/hunter/a2a",
    "DETECTION_ENGINEER_URL": "https://example.invalid/detection/a2a",
    "TIER2_RESPONDER_URL": "https://example.invalid/responder/a2a",
}


def test_ingress_uses_native_confidence_without_verbal_rubric() -> None:
    """Verifies verbal confidence_score rubric was deleted in favor of native confidence."""
    assert "confidence_score" not in multimodal_cti_ingress._INGRESS_QUESTIONS

    mock_decision = {
        "enabled": True,
        "answers": {
            "is_actionable_threat": {
                "type": "noul",
                "noul": 0.94,
                "confidence": 0.94,
            },
            "threat_category": {
                "type": "choice",
                "choice": "phishing_credential_theft",
                "confidence": 0.98,
            },
            "severity": {
                "type": "score",
                "raw_score": 2.84,
                "score": 3.84,
                "confidence": 0.81,
            },
            "requires_immediate_hunt": {
                "type": "noul",
                "noul": 0.91,
                "confidence": 0.91,
            },
        },
        "usage": {"total_input_tokens": 1400, "total_output_tokens": 0},
    }

    with patch.object(
        multimodal_cti_ingress,
        "evaluate_decisions",
        return_value=mock_decision,
    ):
        res = multimodal_cti_ingress.triage_multimodal_security_artifact(
            b"\x89PNG\r\n\x1a\nfake-png",
            mime_type="image/png",
            context={"spf_dkim": "fail"},
        )

    assert res["enabled"] is True
    assert res["is_actionable_threat"] is True
    assert res["threat_category"] == "phishing_credential_theft"
    assert res["severity"] == 3.84
    assert res["confidence"] == 0.96
    assert res["recommended_route"] == "escalate_threat_hunter"
    assert res["usage"]["total_output_tokens"] == 0


def test_ingress_supports_png_pdf_text_and_uri(tmp_path: Path) -> None:
    """Verifies PNG path, PDF path, text OSINT, and HTTPS URI payload construction."""
    png_file = tmp_path / "lure.png"
    png_file.write_bytes(b"\x89PNG\r\n\x1a\npng-bytes")
    pdf_file = tmp_path / "advisory.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n%fake\n")

    captured_inputs: list[Any] = []

    def _fake_eval(
        input_text: Any, questions: dict[str, Any], **_: Any
    ) -> dict[str, Any]:
        del questions
        captured_inputs.append(input_text)
        return {
            "enabled": True,
            "answers": {
                "is_actionable_threat": {"noul": 0.10, "confidence": 0.90},
                "threat_category": {
                    "choice": "benign_infrastructure",
                    "confidence": 0.92,
                },
                "severity": {"raw_score": 0.2, "score": 1.2, "confidence": 0.85},
                "requires_immediate_hunt": {"noul": 0.05, "confidence": 0.95},
            },
            "usage": {"total_input_tokens": 500, "total_output_tokens": 0},
        }

    with patch.object(
        multimodal_cti_ingress, "evaluate_decisions", side_effect=_fake_eval
    ):
        res_png = multimodal_cti_ingress.triage_multimodal_security_artifact(
            png_file, context={"source": "email_gateway"}
        )
        res_pdf = multimodal_cti_ingress.triage_multimodal_security_artifact(pdf_file)
        res_txt = multimodal_cti_ingress.triage_multimodal_security_artifact(
            "Routine SDK changelog update", mime_type="text/plain"
        )

        mock_http_resp = MagicMock()
        mock_http_resp.content = b"%PDF-1.4\nremote"
        mock_http_resp.headers = {"content-type": "application/pdf"}
        mock_http_resp.raise_for_status = MagicMock()
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = (
                mock_http_resp
            )
            res_uri = multimodal_cti_ingress.triage_multimodal_security_artifact(
                "https://intel.example/advisory.pdf"
            )

    assert res_png["recommended_route"] == "archive_no_llm"
    assert res_pdf["mime_type"] == "application/pdf"
    assert res_txt["mime_type"] == "text/plain"
    assert res_uri["mime_type"] == "application/pdf"

    assert isinstance(captured_inputs[0], list)
    assert captured_inputs[0][1] == {
        "type": "image",
        "data": base64.b64encode(b"\x89PNG\r\n\x1a\npng-bytes").decode("ascii"),
        "mime_type": "image/png",
    }
    assert isinstance(captured_inputs[1], list)
    assert captured_inputs[1][1]["type"] == "document"
    assert captured_inputs[1][1]["mime_type"] == "application/pdf"
    assert isinstance(captured_inputs[2], str)
    assert isinstance(captured_inputs[3], list)
    assert captured_inputs[3][1]["type"] == "document"


def test_ingress_unconfigured_and_gti_tools_wrapper() -> None:
    """Verifies unconfigured graceful no-op and gti_tools backwards-compat wrapper."""
    with patch.dict(
        os.environ,
        {"GEMINI_AUTH_PROVIDER": "", "GEMINI_API_KEY": ""},
        clear=False,
    ):
        res = multimodal_cti_ingress.triage_multimodal_security_artifact(
            "Suspicious C2 domain example.bad"
        )
    assert res["enabled"] is False

    cti_dir = str(REPO_ROOT / "governed_agents" / "cti_researcher")
    sys.path.insert(0, cti_dir)
    for mod in ("agent", "gti_tools", "decision_client"):
        sys.modules.pop(mod, None)
    try:
        spec = importlib.util.spec_from_file_location(
            "gti_tools", Path(cti_dir) / "gti_tools.py"
        )
        assert spec is not None and spec.loader is not None
        gti_tools = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gti_tools)
    finally:
        sys.path.remove(cti_dir)

    with patch.object(
        gti_tools,
        "triage_multimodal_security_artifact",
        return_value={"enabled": True, "is_actionable_threat": True},
    ) as mock_fn:
        out = gti_tools.triage_unstructured_cti_artifact(
            "iVBORw0KGgo=", mime_type="image/png"
        )
    assert out["is_actionable_threat"] is True
    mock_fn.assert_called_once()
    assert mock_fn.call_args.args == ("iVBORw0KGgo=",)
    assert mock_fn.call_args.kwargs["mime_type"] == "image/png"
    assert mock_fn.call_args.kwargs["is_base64"] is True
    assert callable(mock_fn.call_args.kwargs["evaluator"])


def test_cti_researcher_agent_card_removes_unstructured_tool() -> None:
    """Verifies cti_researcher agent.py and agentcard JSON no longer expose the wrapper."""
    card_path = REPO_ROOT / "terraform" / "agentcards" / "cti_researcher.json"
    card = json.loads(card_path.read_text())
    skill_ids = [s["id"] for s in card["skills"]]
    assert "triage_unstructured_cti_artifact" not in skill_ids

    cti_dir = str(REPO_ROOT / "governed_agents" / "cti_researcher")
    sys.path.insert(0, cti_dir)
    for mod in ("agent", "gti_tools", "decision_client"):
        sys.modules.pop(mod, None)
    try:
        with patch.dict(os.environ, _HERMETIC_ENV, clear=False):
            spec = importlib.util.spec_from_file_location(
                "agent", Path(cti_dir) / "agent.py"
            )
            assert spec is not None and spec.loader is not None
            cti_agent = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cti_agent)
    finally:
        sys.path.remove(cti_dir)

    tool_names = [getattr(t, "__name__", "") for t in cti_agent.cti_llm.tools]
    assert "triage_unstructured_cti_artifact" not in tool_names
    card_skill_ids = [s.id for s in cti_agent.agent_card.skills]
    assert "triage_unstructured_cti_artifact" not in card_skill_ids


def test_orchestrator_preflight_skips_turn2_plus_without_rpc() -> None:
    """Verifies _preflight_before_model_callback skips aevaluate_decisions when len(contents) != 1."""
    orch_dir = str(REPO_ROOT / "governed_agents" / "soc_orchestrator")
    sys.path.insert(0, orch_dir)
    for mod in ("agent", "decision_client"):
        sys.modules.pop(mod, None)
    try:
        with patch.dict(os.environ, _HERMETIC_ENV, clear=False):
            spec = importlib.util.spec_from_file_location(
                "agent", Path(orch_dir) / "agent.py"
            )
            assert spec is not None and spec.loader is not None
            orch_agent = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(orch_agent)
    finally:
        sys.path.remove(orch_dir)

    turn2_req = SimpleNamespace(
        contents=[
            SimpleNamespace(role="user", parts=[SimpleNamespace(text="First turn")]),
            SimpleNamespace(role="model", parts=[SimpleNamespace(text="Ack")]),
            SimpleNamespace(role="user", parts=[SimpleNamespace(text="Follow-up")]),
        ],
        append_instructions=MagicMock(),
    )

    with patch.object(
        orch_agent, "aevaluate_decisions", new_callable=AsyncMock
    ) as mock_eval:
        res = asyncio.run(
            orch_agent._preflight_before_model_callback(MagicMock(), turn2_req)
        )

    assert res is None
    mock_eval.assert_not_called()
    turn2_req.append_instructions.assert_not_called()
