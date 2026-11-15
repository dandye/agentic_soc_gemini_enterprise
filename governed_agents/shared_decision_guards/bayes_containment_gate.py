"""Workflow 3: Epistemic Investigation-Completeness & Expected-Loss Advisor.

Combines calibrated probabilities from Gemini Decision 1 (``v1beta/decisions``)
with asymmetric CMDB asset-criticality loss matrices in pure Python to
deterministically advise one of four governed SOC actions:

1. ``AUTO_CLOSE_BENIGN`` — directional benign confidence ``(1 - P) >=
   positive_action_confidence``, ``P <= close_max_p``, ``E[Loss|close] <=
   E[Loss|isolate]``, and all epistemic sufficiency checks satisfied.
2. ``FORCE_PROBE_MORE`` — missing epistemic checks OR intermediate posterior
   ``P(compromise)`` where evidence is too uncertain to close or isolate.
3. ``AUTO_ISOLATE_CONTAIN`` — ``E[Loss|close] > E[Loss|isolate]`` AND
   directional compromise probability ``P >= isolate_min_p`` on a ``LOW``,
   ``STANDARD``, or ``HIGH`` asset with all epistemic checks satisfied.
4. ``RECOMMEND_TIER0_CHG_ESCALATION`` (alias ``ESCALATE_CHG_GATE``) — Tier-0
   ``CRITICAL`` asset (e.g., ``DC-PROD-01``) where containment requires a
   ``CHG-*`` emergency change ticket and human/Agent Gateway approval.

This module is an epistemic investigation-completeness and expected-loss
advisor. It complements—and never replaces or self-refuses in front of—Agent
Gateway Semantic Governance (``65-semantic-governance.tf``).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


try:
    from shared_decision_guards.decision_client import (
        aevaluate_decisions,
        evaluate_decisions,
        noul_question,
    )
except ImportError:
    try:
        from governed_agents.shared_decision_guards.decision_client import (
            aevaluate_decisions,
            evaluate_decisions,
            noul_question,
        )
    except ImportError:
        from governed_agents.soc_orchestrator.decision_client import (
            aevaluate_decisions,
            evaluate_decisions,
            noul_question,
        )

logger = logging.getLogger("google_adk." + __name__)

DEFAULT_CLOSE_MAX_P = 0.15
DEFAULT_ISOLATE_MIN_P = 0.70
DEFAULT_POSITIVE_ACTION_CONFIDENCE = 0.70
DEFAULT_EPISTEMIC_THRESHOLD = 0.50

EPISTEMIC_CHECK_KEYS: tuple[str, ...] = (
    "corroborated_two_sources",
    "widened_72h_to_168h_on_empty_hunt",
    "checked_lolbin_signer",
    "verified_asset_tier",
)


class AssetTier(str, Enum):
    """CMDB asset criticality tiers with asymmetric FP/FN loss profiles."""

    LOW = "LOW"
    STANDARD = "STANDARD"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ContainmentAction(str, Enum):
    """Deterministic SOC containment outcomes from the Bayes advisor."""

    AUTO_CLOSE_BENIGN = "AUTO_CLOSE_BENIGN"
    FORCE_PROBE_MORE = "FORCE_PROBE_MORE"
    AUTO_ISOLATE_CONTAIN = "AUTO_ISOLATE_CONTAIN"
    RECOMMEND_TIER0_CHG_ESCALATION = "RECOMMEND_TIER0_CHG_ESCALATION"
    ESCALATE_CHG_GATE = "RECOMMEND_TIER0_CHG_ESCALATION"


@dataclass(frozen=True)
class LossMatrix:
    """Asymmetric financial loss (USD) for false positives vs false negatives."""

    l_fp: float
    l_fn: float

    @property
    def bayes_threshold(self) -> float:
        """Posterior probability threshold P* = L_FP / (L_FP + L_FN)."""
        denom = self.l_fp + self.l_fn
        if denom <= 0:
            return 0.5
        return self.l_fp / denom


ASSET_TIER_LOSSES: dict[AssetTier, LossMatrix] = {
    AssetTier.LOW: LossMatrix(l_fp=500.0, l_fn=10_000.0),
    AssetTier.STANDARD: LossMatrix(l_fp=5_000.0, l_fn=50_000.0),
    AssetTier.HIGH: LossMatrix(l_fp=25_000.0, l_fn=150_000.0),
    AssetTier.CRITICAL: LossMatrix(l_fp=50_000.0, l_fn=250_000.0),
}

_BAYES_GATE_QUESTIONS: dict[str, dict[str, Any]] = {
    "compromise_detected": noul_question(
        "Based on the raw investigation tool traces, is the target host or "
        "account genuinely compromised by malicious activity (as opposed to "
        "authorized scanning, scheduled maintenance, or unconfirmed noise)?"
    ),
    "corroborated_two_sources": noul_question(
        "Do the tool outputs show evidence from at least two independent "
        "telemetry or intelligence sources (e.g., EDR plus Chronicle SIEM/DNS/"
        "firewall logs, or CMDB schedule plus scanner logs)?"
    ),
    "widened_72h_to_168h_on_empty_hunt": noul_question(
        "Do the tool traces show either positive threat hits OR a completed "
        "search window of at least 168 hours (e.g., [COMPUTED_WINDOW_HOURS: 168]) "
        "rather than stopping after an empty 72-hour hunt?"
    ),
    "checked_lolbin_signer": noul_question(
        "If any living-off-the-land binary (LOLBin) or executable appears in "
        "the telemetry, do the tool outputs include its digital signature, "
        "file path, and parent-child process lineage (or are no LOLBins present)?"
    ),
    "verified_asset_tier": noul_question(
        "Do the tool outputs include a CMDB lookup or asset record verifying "
        "the target hostname and criticality tier (LOW, STANDARD, HIGH, or "
        "CRITICAL / Tier-0)?"
    ),
}

_PROBE_HINTS: dict[str, str] = {
    "corroborated_two_sources": (
        "Corroborate the finding across at least two independent telemetry "
        "sources (e.g., EDR process tree + Chronicle UDM network/DNS logs)."
    ),
    "widened_72h_to_168h_on_empty_hunt": (
        "Widen the Chronicle SIEM UDM hunt window from 72 hours to 168 hours "
        "before concluding there are no related events."
    ),
    "checked_lolbin_signer": (
        "Verify the binary digital signature, execution path, and parent-child "
        "process lineage for any involved LOLBin or executable."
    ),
    "verified_asset_tier": (
        "Query CMDB to confirm the asset hostname and criticality tier before "
        "recommending containment or closure."
    ),
}


@dataclass(frozen=True)
class EpistemicCheckResult:
    """Single atomic epistemic sufficiency check returned by Decision 1."""

    name: str
    probability: float
    confidence: float
    passed: bool


@dataclass(frozen=True)
class BayesGateDecision:
    """Complete audit record for a Workflow 3 Bayes containment decision."""

    action: ContainmentAction
    asset_id: str
    asset_tier: AssetTier
    p_compromise: float
    confidence: float
    expected_loss_close_usd: float
    expected_loss_isolate_usd: float
    bayes_threshold_p: float
    epistemic_checks: dict[str, EpistemicCheckResult]
    missing_epistemic_checks: list[str]
    requires_chg_ticket: bool
    reflection_prompt: str | None
    rationale: str
    latency_ms: float
    decision1_enabled: bool
    fallback: bool = False
    usage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serializes the decision to a JSON-compatible dictionary."""
        data = asdict(self)
        data["action"] = self.action.value
        data["asset_tier"] = self.asset_tier.value
        return data


def normalize_asset_tier(tier: AssetTier | str) -> AssetTier:
    """Normalizes a string or AssetTier into a canonical AssetTier."""
    if isinstance(tier, AssetTier):
        return tier
    cleaned = str(tier).strip().upper()
    aliases = {
        "TIER-0": AssetTier.CRITICAL,
        "TIER0": AssetTier.CRITICAL,
        "T0": AssetTier.CRITICAL,
    }
    if cleaned in aliases:
        return aliases[cleaned]
    return AssetTier(cleaned)


def compute_udm_window_bucket(start_time: str, end_time: str) -> str:
    """Computes a duration bucket string from ISO-8601 timestamps in Python."""
    start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
    hours = max(0, round((end_dt - start_dt).total_seconds() / 3600.0))
    return f"[COMPUTED_WINDOW_HOURS: {hours}]"


def compute_expected_losses(
    p_compromise: float,
    asset_tier: AssetTier | str,
) -> tuple[float, float, float]:
    """Computes asymmetric expected financial losses in pure Python.

    Returns ``(expected_loss_close, expected_loss_isolate, bayes_threshold)``
    where:
    - ``expected_loss_close = P(compromise) * L_FN``
    - ``expected_loss_isolate = (1 - P(compromise)) * L_FP``
    - ``bayes_threshold = L_FP / (L_FP + L_FN)``
    """
    p = max(0.0, min(1.0, float(p_compromise)))
    tier = normalize_asset_tier(asset_tier)
    losses = ASSET_TIER_LOSSES[tier]
    expected_loss_close = round(p * losses.l_fn, 2)
    expected_loss_isolate = round((1.0 - p) * losses.l_fp, 2)
    return expected_loss_close, expected_loss_isolate, losses.bayes_threshold


def _build_reflection_prompt(
    asset_id: str,
    asset_tier: AssetTier,
    p_compromise: float,
    confidence: float,
    missing_checks: list[str],
) -> str:
    """Builds a structured investigation advisory when FORCE_PROBE_MORE triggers."""
    probes = [_PROBE_HINTS[k] for k in missing_checks if k in _PROBE_HINTS]
    if not probes:
        probes.append(
            "Gather additional corroborating telemetry to move posterior "
            "P(compromise) out of the ambiguous band before closing or isolating."
        )
    bullet_list = "\n".join(f"- {item}" for item in probes)
    return (
        f"[EPISTEMIC_INVESTIGATION_ADVISORY] Investigation for {asset_id} "
        f"(tier={asset_tier.value}, P={p_compromise:.3f}, "
        f"d1_confidence={confidence:.3f}) is not yet epistemically sufficient "
        f"to close or contain. Execute the following probes before finalizing:\n"
        f"{bullet_list}"
    )


def decide_containment_action(
    *,
    asset_id: str,
    asset_tier: AssetTier | str,
    decision1_response: dict[str, Any],
    latency_ms: float = 0.0,
    close_max_p: float = DEFAULT_CLOSE_MAX_P,
    isolate_min_p: float = DEFAULT_ISOLATE_MIN_P,
    positive_action_confidence: float = DEFAULT_POSITIVE_ACTION_CONFIDENCE,
    epistemic_threshold: float = DEFAULT_EPISTEMIC_THRESHOLD,
) -> BayesGateDecision:
    """Deterministically maps a Decision 1 response + CMDB tier to 1 of 4 actions."""
    tier = normalize_asset_tier(asset_tier)
    enabled = bool(decision1_response.get("enabled", False))
    answers = decision1_response.get("answers") or {}
    has_error = bool(decision1_response.get("error"))

    if not enabled or has_error or "compromise_detected" not in answers:
        reason = (
            decision1_response.get("error")
            or decision1_response.get("reason")
            or "Decision 1 unavailable or incomplete response"
        )
        e_close, e_isolate, threshold_p = compute_expected_losses(0.5, tier)
        fallback_action = (
            ContainmentAction.RECOMMEND_TIER0_CHG_ESCALATION
            if tier == AssetTier.CRITICAL
            else ContainmentAction.FORCE_PROBE_MORE
        )
        missing = list(EPISTEMIC_CHECK_KEYS)
        reflection = (
            _build_reflection_prompt(asset_id, tier, 0.5, 0.0, missing)
            if fallback_action == ContainmentAction.FORCE_PROBE_MORE
            else None
        )
        return BayesGateDecision(
            action=fallback_action,
            asset_id=asset_id,
            asset_tier=tier,
            p_compromise=0.5,
            confidence=0.0,
            expected_loss_close_usd=e_close,
            expected_loss_isolate_usd=e_isolate,
            bayes_threshold_p=threshold_p,
            epistemic_checks={
                k: EpistemicCheckResult(
                    name=k, probability=0.0, confidence=0.0, passed=False
                )
                for k in EPISTEMIC_CHECK_KEYS
            },
            missing_epistemic_checks=missing,
            requires_chg_ticket=(
                fallback_action == ContainmentAction.RECOMMEND_TIER0_CHG_ESCALATION
            ),
            reflection_prompt=reflection,
            rationale=f"Fallback ({fallback_action.value}): {reason}",
            latency_ms=round(latency_ms, 2),
            decision1_enabled=enabled,
            fallback=True,
            usage=dict(decision1_response.get("usage") or {}),
        )

    comp_ans = answers["compromise_detected"]
    p_compromise = max(0.0, min(1.0, float(comp_ans.get("noul", 0.5))))
    confidence = float(
        comp_ans.get("confidence", max(p_compromise, 1.0 - p_compromise))
    )
    e_close, e_isolate, threshold_p = compute_expected_losses(p_compromise, tier)

    epistemic_checks: dict[str, EpistemicCheckResult] = {}
    missing_checks: list[str] = []
    for key in EPISTEMIC_CHECK_KEYS:
        raw = answers.get(key) or {}
        prob = float(raw.get("noul", 0.0))
        conf = float(raw.get("confidence", 0.0))
        passed = prob >= epistemic_threshold
        epistemic_checks[key] = EpistemicCheckResult(
            name=key,
            probability=prob,
            confidence=conf,
            passed=passed,
        )
        if not passed:
            missing_checks.append(key)

    # Branch 1: Missing epistemic checks -> FORCE_PROBE_MORE
    if missing_checks:
        reflection = _build_reflection_prompt(
            asset_id, tier, p_compromise, confidence, missing_checks
        )
        return BayesGateDecision(
            action=ContainmentAction.FORCE_PROBE_MORE,
            asset_id=asset_id,
            asset_tier=tier,
            p_compromise=p_compromise,
            confidence=confidence,
            expected_loss_close_usd=e_close,
            expected_loss_isolate_usd=e_isolate,
            bayes_threshold_p=threshold_p,
            epistemic_checks=epistemic_checks,
            missing_epistemic_checks=missing_checks,
            requires_chg_ticket=False,
            reflection_prompt=reflection,
            rationale=(
                f"Epistemic gate triggered FORCE_PROBE_MORE: "
                f"missing_checks={missing_checks}."
            ),
            latency_ms=round(latency_ms, 2),
            decision1_enabled=True,
            fallback=False,
            usage=dict(decision1_response.get("usage") or {}),
        )

    # Branch 2: Directional benign closure (low P, E[close] <= E[isolate], high 1-P)
    p_benign = 1.0 - p_compromise
    if (
        p_compromise <= close_max_p
        and e_close <= e_isolate
        and p_benign >= positive_action_confidence
    ):
        return BayesGateDecision(
            action=ContainmentAction.AUTO_CLOSE_BENIGN,
            asset_id=asset_id,
            asset_tier=tier,
            p_compromise=p_compromise,
            confidence=confidence,
            expected_loss_close_usd=e_close,
            expected_loss_isolate_usd=e_isolate,
            bayes_threshold_p=threshold_p,
            epistemic_checks=epistemic_checks,
            missing_epistemic_checks=[],
            requires_chg_ticket=False,
            reflection_prompt=None,
            rationale=(
                f"Benign closure on {tier.value} asset {asset_id}: "
                f"P={p_compromise:.3f} <= {close_max_p:.2f}, "
                f"(1-P)={p_benign:.3f} >= {positive_action_confidence:.2f}, "
                f"E[Loss|close]=${e_close:,.2f} <= E[Loss|isolate]=${e_isolate:,.2f}."
            ),
            latency_ms=round(latency_ms, 2),
            decision1_enabled=True,
            fallback=False,
            usage=dict(decision1_response.get("usage") or {}),
        )

    # Branch 3: Directional compromise (E[close] > E[isolate] AND P >= isolate_min_p)
    if e_close > e_isolate and p_compromise >= isolate_min_p:
        if tier == AssetTier.CRITICAL:
            return BayesGateDecision(
                action=ContainmentAction.RECOMMEND_TIER0_CHG_ESCALATION,
                asset_id=asset_id,
                asset_tier=tier,
                p_compromise=p_compromise,
                confidence=confidence,
                expected_loss_close_usd=e_close,
                expected_loss_isolate_usd=e_isolate,
                bayes_threshold_p=threshold_p,
                epistemic_checks=epistemic_checks,
                missing_epistemic_checks=[],
                requires_chg_ticket=True,
                reflection_prompt=None,
                rationale=(
                    f"Tier-0 CRITICAL asset {asset_id}: E[Loss|close]=${e_close:,.2f} "
                    f"> E[Loss|isolate]=${e_isolate:,.2f} (P={p_compromise:.3f} >= "
                    f"{isolate_min_p:.2f}, P*={threshold_p:.4f}). Advising CHG-* "
                    f"emergency change approval at the Agent Gateway."
                ),
                latency_ms=round(latency_ms, 2),
                decision1_enabled=True,
                fallback=False,
                usage=dict(decision1_response.get("usage") or {}),
            )

        return BayesGateDecision(
            action=ContainmentAction.AUTO_ISOLATE_CONTAIN,
            asset_id=asset_id,
            asset_tier=tier,
            p_compromise=p_compromise,
            confidence=confidence,
            expected_loss_close_usd=e_close,
            expected_loss_isolate_usd=e_isolate,
            bayes_threshold_p=threshold_p,
            epistemic_checks=epistemic_checks,
            missing_epistemic_checks=[],
            requires_chg_ticket=False,
            reflection_prompt=None,
            rationale=(
                f"Bayes containment advised on {tier.value} asset {asset_id}: "
                f"E[Loss|close]=${e_close:,.2f} > E[Loss|isolate]=${e_isolate:,.2f} "
                f"(P={p_compromise:.3f} >= {isolate_min_p:.2f}, P*={threshold_p:.4f})."
            ),
            latency_ms=round(latency_ms, 2),
            decision1_enabled=True,
            fallback=False,
            usage=dict(decision1_response.get("usage") or {}),
        )

    # Branch 4: Intermediate / uncertain posterior -> FORCE_PROBE_MORE
    reflection = _build_reflection_prompt(asset_id, tier, p_compromise, confidence, [])
    return BayesGateDecision(
        action=ContainmentAction.FORCE_PROBE_MORE,
        asset_id=asset_id,
        asset_tier=tier,
        p_compromise=p_compromise,
        confidence=confidence,
        expected_loss_close_usd=e_close,
        expected_loss_isolate_usd=e_isolate,
        bayes_threshold_p=threshold_p,
        epistemic_checks=epistemic_checks,
        missing_epistemic_checks=[],
        requires_chg_ticket=False,
        reflection_prompt=reflection,
        rationale=(
            f"Uncertain posterior P={p_compromise:.3f} in epistemic probe band "
            f"(close_max_p={close_max_p:.2f}, P*={threshold_p:.4f}, "
            f"isolate_min_p={isolate_min_p:.2f}); forcing additional probe."
        ),
        latency_ms=round(latency_ms, 2),
        decision1_enabled=True,
        fallback=False,
        usage=dict(decision1_response.get("usage") or {}),
    )


def evaluate_bayes_containment_gate(
    evidence_text: str,
    *,
    asset_id: str,
    asset_tier: AssetTier | str,
    timeout: float = 15.0,
    close_max_p: float = DEFAULT_CLOSE_MAX_P,
    isolate_min_p: float = DEFAULT_ISOLATE_MIN_P,
    positive_action_confidence: float = DEFAULT_POSITIVE_ACTION_CONFIDENCE,
    epistemic_threshold: float = DEFAULT_EPISTEMIC_THRESHOLD,
) -> BayesGateDecision:
    """Synchronously evaluates all 5 Decision 1 noul checks in ONE API call."""
    tier = normalize_asset_tier(asset_tier)
    prompt = (
        f"Asset ID: {asset_id}\n"
        f"CMDB Asset Tier: {tier.value}\n"
        f"Raw Investigation Tool Trace:\n{evidence_text}"
    )
    start = time.perf_counter()
    response = evaluate_decisions(prompt, _BAYES_GATE_QUESTIONS, timeout=timeout)
    latency_ms = (time.perf_counter() - start) * 1000.0
    return decide_containment_action(
        asset_id=asset_id,
        asset_tier=tier,
        decision1_response=response,
        latency_ms=latency_ms,
        close_max_p=close_max_p,
        isolate_min_p=isolate_min_p,
        positive_action_confidence=positive_action_confidence,
        epistemic_threshold=epistemic_threshold,
    )


async def aevaluate_bayes_containment_gate(
    evidence_text: str,
    *,
    asset_id: str,
    asset_tier: AssetTier | str,
    timeout: float = 15.0,
    close_max_p: float = DEFAULT_CLOSE_MAX_P,
    isolate_min_p: float = DEFAULT_ISOLATE_MIN_P,
    positive_action_confidence: float = DEFAULT_POSITIVE_ACTION_CONFIDENCE,
    epistemic_threshold: float = DEFAULT_EPISTEMIC_THRESHOLD,
) -> BayesGateDecision:
    """Asynchronously evaluates all 5 Decision 1 noul checks in ONE API call."""
    tier = normalize_asset_tier(asset_tier)
    prompt = (
        f"Asset ID: {asset_id}\n"
        f"CMDB Asset Tier: {tier.value}\n"
        f"Raw Investigation Tool Trace:\n{evidence_text}"
    )
    start = time.perf_counter()
    response = await aevaluate_decisions(prompt, _BAYES_GATE_QUESTIONS, timeout=timeout)
    latency_ms = (time.perf_counter() - start) * 1000.0
    return decide_containment_action(
        asset_id=asset_id,
        asset_tier=tier,
        decision1_response=response,
        latency_ms=latency_ms,
        close_max_p=close_max_p,
        isolate_min_p=isolate_min_p,
        positive_action_confidence=positive_action_confidence,
        epistemic_threshold=epistemic_threshold,
    )


def _extract_tool_trace_from_request(llm_request: Any) -> tuple[bool, str]:
    """Extracts accumulated tool calls/responses from LlmRequest.contents."""
    contents = getattr(llm_request, "contents", None) or []
    has_function_response = False
    snippets: list[str] = []
    for content in contents:
        parts = getattr(content, "parts", None) or []
        for part in parts:
            fc = getattr(part, "function_call", None)
            if fc is not None:
                snippets.append(
                    f"TOOL_CALL {getattr(fc, 'name', 'unknown')}: "
                    f"{getattr(fc, 'args', {})}"
                )
            fr = getattr(part, "function_response", None)
            if fr is not None:
                has_function_response = True
                snippets.append(
                    f"TOOL_RESPONSE {getattr(fr, 'name', 'unknown')}: "
                    f"{getattr(fr, 'response', {})}"
                )
            text = getattr(part, "text", None)
            if text:
                snippets.append(str(text))
    return has_function_response, "\n".join(snippets).strip()


def _append_advisory_to_request(llm_request: Any, advisory_text: str) -> None:
    """Appends an epistemic advisory to LlmRequest.config.system_instruction."""
    config = getattr(llm_request, "config", None)
    if config is not None:
        existing = getattr(config, "system_instruction", None)
        if isinstance(existing, str):
            config.system_instruction = f"{existing}\n\n{advisory_text}".strip()
            return
        if existing is None:
            config.system_instruction = advisory_text
            return

    contents = getattr(llm_request, "contents", None)
    if isinstance(contents, list):
        contents.append({"role": "user", "parts": [{"text": advisory_text}]})


def make_bayes_epistemic_before_model_callback(
    *,
    default_asset_id: str = "UNKNOWN-ASSET",
    default_asset_tier: AssetTier | str = AssetTier.STANDARD,
    max_probe_injections: int = 1,
) -> Callable[..., Any]:
    """Creates an ADK ``before_model_callback`` for post-tool epistemic gating.

    Runs only when ``llm_request.contents`` already contains at least one
    ``function_response`` (i.e. before the LLM synthesizes its post-tool
    verdict). If Decision 1 + asymmetric loss math selects
    ``FORCE_PROBE_MORE``, appends an ``[EPISTEMIC_INVESTIGATION_ADVISORY]``
    instruction to ``llm_request`` so the model invokes the missing tool(s)
    instead of terminating early.
    """

    async def _before_model_callback(
        callback_context: Any,
        llm_request: Any,
    ) -> Any:
        has_tool_response, evidence_text = _extract_tool_trace_from_request(llm_request)
        if not has_tool_response or not evidence_text:
            return None

        state = getattr(callback_context, "state", None)
        asset_id = default_asset_id
        asset_tier: AssetTier | str = default_asset_tier
        probe_count = 0
        if isinstance(state, dict):
            asset_id = str(state.get("asset_id") or default_asset_id)
            asset_tier = state.get("asset_tier") or default_asset_tier
            probe_count = int(state.get("bayes_probe_injections", 0))

        decision = await aevaluate_bayes_containment_gate(
            evidence_text,
            asset_id=asset_id,
            asset_tier=asset_tier,
        )
        if isinstance(state, dict):
            state["bayes_gate_last_decision"] = decision.to_dict()

        if (
            decision.action == ContainmentAction.FORCE_PROBE_MORE
            and decision.reflection_prompt
            and probe_count < max_probe_injections
        ):
            if isinstance(state, dict):
                state["bayes_probe_injections"] = probe_count + 1
            _append_advisory_to_request(llm_request, decision.reflection_prompt)
        elif decision.action == ContainmentAction.RECOMMEND_TIER0_CHG_ESCALATION:
            _append_advisory_to_request(
                llm_request,
                f"[TIER0_CHG_ADVISORY] {asset_id} is a Tier-0 CRITICAL asset "
                f"(P={decision.p_compromise:.3f}). Recommend CHG-* emergency "
                "change approval at the Agent Gateway before any isolation.",
            )
        return None

    return _before_model_callback


async def run_epistemic_probe_loop(
    initial_evidence: str,
    *,
    asset_id: str,
    asset_tier: AssetTier | str,
    probe_executor: Callable[[list[str], BayesGateDecision], Awaitable[str]],
    max_iterations: int = 2,
) -> BayesGateDecision:
    """Explicitly executes missing epistemic probes until ready or exhausted."""
    evidence = initial_evidence
    decision = await aevaluate_bayes_containment_gate(
        evidence, asset_id=asset_id, asset_tier=asset_tier
    )
    for _ in range(max_iterations):
        if decision.action != ContainmentAction.FORCE_PROBE_MORE:
            break
        extra_evidence = await probe_executor(
            decision.missing_epistemic_checks, decision
        )
        if not extra_evidence.strip():
            break
        evidence = f"{evidence}\n{extra_evidence}"
        decision = await aevaluate_bayes_containment_gate(
            evidence, asset_id=asset_id, asset_tier=asset_tier
        )
    return decision


def make_bayes_after_model_callback(
    *,
    default_asset_id: str = "UNKNOWN-ASSET",
    default_asset_tier: AssetTier | str = AssetTier.STANDARD,
    probe_tool_map: dict[str, tuple[str, dict[str, Any]]] | None = None,
    max_probe_injections: int = 1,
) -> Callable[..., Any]:
    """Optional ADK ``after_model_callback`` that synthesizes a probe tool call.

    Unlike text-mutation hacks, this callback only intervenes when
    ``probe_tool_map`` provides a concrete tool name and args for a missing
    epistemic check, replacing the premature text response with a synthesized
    ``function_call`` part so ADK executes the missing probe.
    """

    async def _after_model_callback(
        callback_context: Any,
        llm_response: Any,
    ) -> Any:
        if not probe_tool_map:
            return None
        content = getattr(llm_response, "content", None)
        parts = getattr(content, "parts", None) or []
        if not parts or any(
            getattr(part, "function_call", None) is not None for part in parts
        ):
            return None

        evidence_text = "\n".join(
            str(getattr(part, "text", ""))
            for part in parts
            if getattr(part, "text", None)
        ).strip()
        if not evidence_text:
            return None

        state = getattr(callback_context, "state", None)
        asset_id = default_asset_id
        asset_tier: AssetTier | str = default_asset_tier
        probe_count = 0
        if isinstance(state, dict):
            asset_id = str(state.get("asset_id") or default_asset_id)
            asset_tier = state.get("asset_tier") or default_asset_tier
            probe_count = int(state.get("bayes_probe_injections", 0))

        decision = await aevaluate_bayes_containment_gate(
            evidence_text,
            asset_id=asset_id,
            asset_tier=asset_tier,
        )
        if isinstance(state, dict):
            state["bayes_gate_last_decision"] = decision.to_dict()

        if (
            decision.action == ContainmentAction.FORCE_PROBE_MORE
            and probe_count < max_probe_injections
        ):
            for missing in decision.missing_epistemic_checks:
                if missing in probe_tool_map:
                    tool_name, tool_args = probe_tool_map[missing]
                    if isinstance(state, dict):
                        state["bayes_probe_injections"] = probe_count + 1
                    from google.genai import types

                    content.parts = [
                        types.Part(
                            function_call=types.FunctionCall(
                                name=tool_name, args=dict(tool_args)
                            )
                        )
                    ]
                    return llm_response
        return None

    return _after_model_callback
