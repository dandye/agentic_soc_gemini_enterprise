"""Pre-agent multimodal CTI ingress gate backed by Gemini Decision 1.

Evaluates raw bytes, local file paths, HTTPS/Files-API URIs, or base64/text
artifacts (text OSINT, phishing screenshots, PDF advisories, audio) alongside
optional header/CMDB JSON context in a single zero-output-token Decisions API
call BEFORE waking any generative LLM.

Confidence is computed directly from Decision 1's native calibrated
``answer["confidence"]`` values on ``is_actionable_threat`` and
``threat_category`` rather than a synthetic verbal confidence rubric.
"""

from __future__ import annotations

import base64
import json
import mimetypes
from pathlib import Path
from typing import Any

import httpx


try:
    from shared_decision_guards.decision_client import (
        choice_question,
        evaluate_decisions,
        noul_question,
        score_question,
    )
except ImportError:
    try:
        from governed_agents.shared_decision_guards.decision_client import (
            choice_question,
            evaluate_decisions,
            noul_question,
            score_question,
        )
    except ImportError:
        from decision_client import (  # type: ignore[no-redef]
            choice_question,
            evaluate_decisions,
            noul_question,
            score_question,
        )


_INGRESS_QUESTIONS: dict[str, dict[str, Any]] = {
    "is_actionable_threat": noul_question(
        "True if the artifact describes or depicts a concrete, actionable "
        "cyber threat, phishing lure, credential harvest, active campaign, or "
        "malicious infrastructure relevant to SOC defense; false if benign, "
        "routine maintenance, or unactionable."
    ),
    "threat_category": choice_question(
        instructions=(
            "Select the primary threat category represented in the artifact."
        ),
        criteria={
            "malware_delivery": (
                "Payload hosting, dropper, downloader, or malicious "
                "executable distribution."
            ),
            "command_and_control": (
                "Command-and-control server, beaconing domain/IP, or covert "
                "exfiltration channel."
            ),
            "phishing_credential_theft": (
                "Phishing lure, credential harvesting page, fake login "
                "prompt, or brand impersonation."
            ),
            "scanning_exploitation": (
                "Vulnerability scanner, brute-force source, or active "
                "exploit delivery."
            ),
            "benign_infrastructure": (
                "Legitimate dashboard, maintenance notice, CDN, cloud "
                "provider, DNS resolver, or trusted enterprise service."
            ),
            "other_or_unknown": (
                "Threat category does not match the above options or "
                "insufficient data is present."
            ),
        },
    ),
    "severity": score_question(
        instructions=(
            "Rate operational threat severity from lowest (level 0) to "
            "critical (level 4) based on impact and urgency."
        ),
        criteria=[
            "Informational or benign: no active threat or operational impact.",
            "Low severity: minor reconnaissance or low-impact opportunistic activity.",
            "Moderate severity: suspicious campaign or commodity malware requiring standard triage.",
            "High severity: confirmed active malware, C2, phishing lure, or targeted intrusion activity.",
            "Critical severity: active ransomware, zero-day exploitation, or crown-jewel compromise.",
        ],
    ),
    "requires_immediate_hunt": noul_question(
        "True if the artifact warrants immediate internal SIEM/UDM threat "
        "hunting across endpoints, network logs, or DNS telemetry; false "
        "otherwise."
    ),
}


def _mime_to_part_type(mime_type: str) -> str:
    lower = mime_type.lower()
    if lower.startswith("image/"):
        return "image"
    if lower.startswith("audio/"):
        return "audio"
    if lower.startswith("video/"):
        return "video"
    return "document"


def _guess_mime_type(source_hint: str, fallback: str = "text/plain") -> str:
    guessed, _ = mimetypes.guess_type(source_hint)
    return (guessed or fallback).lower()


def _fetch_uri_bytes(uri: str, timeout: float = 15.0) -> tuple[bytes, str]:
    """Fetches bytes and content-type from an HTTPS or Files-API URI."""
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(uri)
        resp.raise_for_status()
        ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        return resp.content, ctype


def _build_artifact_input(
    source: str | bytes | Path,
    mime_type: str | None,
    context: dict[str, Any] | str | None,
    is_base64: bool,
) -> tuple[str | list[dict[str, Any]], str]:
    """Builds the Decision 1 input payload and resolved MIME type."""
    context_str = ""
    if context is not None:
        if isinstance(context, str):
            context_str = context.strip()
        else:
            context_str = json.dumps(context, sort_keys=True)

    resolved_mime = (mime_type or "").strip().lower()
    raw_bytes: bytes | None = None
    text_body: str | None = None
    b64_body: str | None = None

    if isinstance(source, bytes):
        raw_bytes = source
        if not resolved_mime:
            resolved_mime = "application/octet-stream"
    elif isinstance(source, Path):
        if not source.is_file():
            raise FileNotFoundError(f"Artifact file not found: {source}")
        raw_bytes = source.read_bytes()
        if not resolved_mime:
            resolved_mime = _guess_mime_type(str(source), "application/octet-stream")
    elif isinstance(source, str):
        stripped = source.strip()
        if not stripped:
            raise ValueError("source must not be empty.")
        if stripped.startswith(("https://", "http://")):
            fetched_bytes, fetched_ctype = _fetch_uri_bytes(stripped)
            raw_bytes = fetched_bytes
            if not resolved_mime:
                resolved_mime = fetched_ctype or _guess_mime_type(
                    stripped, "application/octet-stream"
                )
        elif (
            not is_base64
            and "\n" not in stripped
            and len(stripped) < 1024
            and Path(stripped).is_file()
        ):
            path_obj = Path(stripped)
            raw_bytes = path_obj.read_bytes()
            if not resolved_mime:
                resolved_mime = _guess_mime_type(stripped, "application/octet-stream")
        else:
            if not resolved_mime:
                resolved_mime = "text/plain"
            if resolved_mime.startswith("text/") and not is_base64:
                text_body = stripped
            elif is_base64 and resolved_mime.startswith("text/"):
                text_body = base64.b64decode(stripped).decode("utf-8", errors="replace")
            else:
                b64_body = stripped
    else:
        raise TypeError(f"Unsupported source type: {type(source).__name__}")

    if raw_bytes is not None:
        if resolved_mime.startswith("text/"):
            text_body = raw_bytes.decode("utf-8", errors="replace")
        else:
            b64_body = base64.b64encode(raw_bytes).decode("ascii")

    if text_body is not None:
        if context_str:
            combined = (
                f"Context (header/CMDB):\n{context_str}\n\n"
                f"Unstructured CTI artifact ({resolved_mime}):\n{text_body}"
            )
        else:
            combined = f"Unstructured CTI artifact ({resolved_mime}):\n{text_body}"
        return combined, resolved_mime

    if b64_body is None:
        raise ValueError("Artifact payload could not be encoded.")
    prompt_parts = [
        f"Triage this unstructured CTI artifact ({resolved_mime}) for "
        "threat intelligence and SOC actionability."
    ]
    if context_str:
        prompt_parts.append(f"Context (header/CMDB):\n{context_str}")
    return [
        {"type": "text", "text": "\n\n".join(prompt_parts)},
        {
            "type": _mime_to_part_type(resolved_mime),
            "data": b64_body,
            "mime_type": resolved_mime,
        },
    ], resolved_mime


def _compute_native_confidence(
    actionable_ans: dict[str, Any],
    category_ans: dict[str, Any],
) -> float | None:
    """Computes calibrated confidence from Decision 1 native answer confidence."""
    values = [
        float(ans["confidence"])
        for ans in (actionable_ans, category_ans)
        if ans.get("confidence") is not None
    ]
    if not values:
        return None
    return round(sum(values) / len(values), 4)


def triage_multimodal_security_artifact(
    source: str | bytes | Path,
    mime_type: str | None = None,
    *,
    context: dict[str, Any] | str | None = None,
    is_base64: bool = False,
    evaluator: Any = None,
) -> dict[str, Any]:
    """Pre-agent Decision 1 ingress gate for multimodal CTI artifacts."""
    try:
        decision_input, resolved_mime = _build_artifact_input(
            source, mime_type, context, is_base64
        )
    except Exception as exc:
        return {
            "enabled": False,
            "error": str(exc),
        }

    eval_fn = evaluator or evaluate_decisions
    decision = eval_fn(
        input_text=decision_input,
        questions=_INGRESS_QUESTIONS,
    )
    if not decision.get("enabled"):
        return {
            "enabled": False,
            "mime_type": resolved_mime,
            "reason": decision.get("reason", "Decision 1 is not configured."),
        }
    if "error" in decision:
        return {
            "enabled": True,
            "mime_type": resolved_mime,
            "error": decision["error"],
            "safety_blocked": bool(decision.get("safety_blocked", False)),
        }

    answers = decision.get("answers", {})
    actionable_ans = answers.get("is_actionable_threat") or {}
    category_ans = answers.get("threat_category") or {}
    severity_ans = answers.get("severity") or {}
    hunt_ans = answers.get("requires_immediate_hunt") or {}

    if severity_ans.get("raw_score") is not None:
        severity = round(float(severity_ans["raw_score"]) + 1.0, 2)
    elif severity_ans.get("score") is not None:
        severity = round(float(severity_ans["score"]) + 1.0, 2)
    else:
        severity = None

    actionable_prob = actionable_ans.get("noul")
    hunt_prob = hunt_ans.get("noul")
    is_actionable = (
        bool(float(actionable_prob) >= 0.5) if actionable_prob is not None else False
    )
    requires_hunt = bool(float(hunt_prob) >= 0.5) if hunt_prob is not None else False

    native_confidence = _compute_native_confidence(actionable_ans, category_ans)

    if not is_actionable and (severity is None or severity < 2.5):
        recommended_route = "archive_no_llm"
    elif requires_hunt:
        recommended_route = "escalate_threat_hunter"
    else:
        recommended_route = "route_cti_researcher"

    return {
        "enabled": True,
        "mime_type": resolved_mime,
        "is_actionable_threat": is_actionable,
        "is_actionable_threat_probability": actionable_prob,
        "is_actionable_threat_confidence": actionable_ans.get("confidence"),
        "threat_category": category_ans.get("choice", "other_or_unknown"),
        "threat_category_confidence": category_ans.get("confidence"),
        "severity": severity,
        "severity_confidence": severity_ans.get("confidence"),
        "requires_immediate_hunt": requires_hunt,
        "requires_immediate_hunt_probability": hunt_prob,
        "requires_immediate_hunt_confidence": hunt_ans.get("confidence"),
        "confidence": native_confidence,
        "recommended_route": recommended_route,
        "usage": decision.get("usage", {}),
    }
