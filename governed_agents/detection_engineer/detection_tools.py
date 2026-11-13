"""Detection Engineering tools for Chronicle SIEM YARA-L 2.0 UDM rules.

Explicitly distinguishes Chronicle SIEM YARA-L 2.0 (UDM event correlation rules
with `meta`, `events`, `match`, `outcome`, and `condition` sections) from
standard YARA (file or payload binary/string signature matching).
"""

from __future__ import annotations

from typing import Any

from decision_client import evaluate_decisions


_YARAL2_LANGUAGE_LABEL = "YARA-L 2.0 (Chronicle SIEM UDM)"

_MITRE_TACTIC_CRITERIA = {
    "reconnaissance": "Gathering information to plan future adversary operations.",
    "resource_development": "Establishing resources to support adversary operations.",
    "initial_access": "Gaining an initial foothold within a network.",
    "execution": "Running adversary-controlled code on a local or remote system.",
    "persistence": "Maintaining a foothold across restarts or credential changes.",
    "privilege_escalation": "Gaining higher-level permissions on a system or network.",
    "defense_evasion": "Avoiding detection throughout a compromise.",
    "credential_access": "Stealing account names, passwords, or authentication tokens.",
    "discovery": "Exploring the environment to identify systems, accounts, or data.",
    "lateral_movement": "Moving through the environment to reach target systems.",
    "collection": "Gathering data of interest to the adversary objective.",
    "command_and_control": "Communicating with compromised systems to control them.",
    "exfiltration": "Stealing data from the target network.",
    "impact": "Manipulating, interrupting, or destroying systems and data.",
    "other_or_unknown": (
        "Does not map clearly to a single MITRE ATT&CK tactic or lacks context."
    ),
}

_RULE_QUALITY_CRITERIA = [
    (
        "Broken or non-YARA-L 2.0 rule: uses standard file/payload YARA syntax, "
        "lacks Chronicle UDM event logic, or has severe structural defects."
    ),
    (
        "Minimal YARA-L 2.0 draft with major structural gaps, overly broad UDM "
        "predicates, or weak detection logic."
    ),
    (
        "Functional YARA-L 2.0 UDM rule with basic sections, but missing tuning, "
        "outcome enrichment, or specificity."
    ),
    (
        "Well-structured YARA-L 2.0 UDM rule with clear metadata, specific UDM "
        "event filters, and sound outcome or condition logic."
    ),
    (
        "Production-grade YARA-L 2.0 UDM rule with complete sections, precise UDM "
        "field predicates, false-positive mitigations, and strong coverage alignment."
    ),
]


def grade_yaral2_rule(
    rule_text: str,
    coverage_context: str = "",
) -> dict[str, Any]:
    """Grades a Chronicle SIEM YARA-L 2.0 UDM detection rule in one Decision 1 pass.

    Evaluates Chronicle SIEM **YARA-L 2.0** (UDM event correlation rules), which
    is distinct from standard file/payload YARA.

    Args:
        rule_text: The YARA-L 2.0 rule text to grade.
        coverage_context: Optional description of target log sources, threat
            scenario, or expected UDM telemetry for coverage alignment.

    Returns:
        A structured grading dictionary with `rule_quality_score` (1.0-5.0),
        `false_positive_risk`, `mitre_tactic`, `has_required_yaral2_sections`,
        and `ready_for_validation`. Returns `{"enabled": False, ...}` when the
        Decision 1 client is unconfigured.
    """
    cleaned_rule = rule_text.strip()
    if not cleaned_rule:
        return {
            "enabled": False,
            "rule_language": _YARAL2_LANGUAGE_LABEL,
            "error": "rule_text must be a non-empty YARA-L 2.0 rule.",
        }

    context_block = coverage_context.strip() or "None provided."
    input_payload = (
        "Evaluate the following Chronicle SIEM YARA-L 2.0 UDM detection rule.\n"
        "Note: YARA-L 2.0 (Chronicle SIEM UDM event correlation rules with meta, "
        "events, match, outcome, and condition sections) is distinct from standard "
        "file/payload YARA (binary/string signature matching).\n\n"
        f"Coverage context: {context_block}\n\n"
        f"Rule text:\n{cleaned_rule}"
    )

    questions: dict[str, dict[str, Any]] = {
        "rule_quality_score": {
            "type": "score",
            "instructions": (
                "Rate the overall engineering quality of this Chronicle SIEM "
                "YARA-L 2.0 UDM detection rule from level 0 (broken or non-YARA-L 2.0) "
                "to level 4 (production-grade YARA-L 2.0 UDM rule)."
            ),
            "criteria": _RULE_QUALITY_CRITERIA,
        },
        "false_positive_risk": {
            "type": "choice",
            "instructions": (
                "Classify the expected false-positive risk of this YARA-L 2.0 UDM "
                "rule in an enterprise SOC environment."
            ),
            "criteria": {
                "low": "Specific UDM predicates and exclusions minimize benign noise.",
                "medium": (
                    "Moderate specificity; may match some benign administrative or "
                    "automated activity without tuning."
                ),
                "high": (
                    "Overly broad UDM matching or missing exclusions likely to "
                    "produce high false-positive volume."
                ),
                "unknown": "Insufficient rule logic or context to assess risk.",
            },
        },
        "mitre_tactic": {
            "type": "choice",
            "instructions": (
                "Select the primary MITRE ATT&CK Enterprise tactic targeted by this "
                "YARA-L 2.0 detection rule, or other_or_unknown if unclear."
            ),
            "criteria": _MITRE_TACTIC_CRITERIA,
        },
        "has_required_yaral2_sections": {
            "type": "noul",
            "instructions": (
                "Does the rule use Chronicle SIEM YARA-L 2.0 structure (a `rule` "
                "block with `meta`, `events`, and `condition` sections and UDM event "
                "predicates) rather than standard file/payload YARA (`strings`, "
                "`pe`, or binary/hex patterns)?"
            ),
        },
        "ready_for_validation": {
            "type": "noul",
            "instructions": (
                "Is this YARA-L 2.0 UDM rule complete and coherent enough to "
                "submit to Chronicle `validate_rule` and `evaluate_rule_coverage`?"
            ),
        },
    }

    result = evaluate_decisions(input_payload, questions)
    if not result.get("enabled"):
        return {
            "enabled": False,
            "rule_language": _YARAL2_LANGUAGE_LABEL,
            "reason": result.get("reason", "Decision client is not configured."),
            "answers": {},
        }
    if "error" in result:
        return {
            "enabled": True,
            "rule_language": _YARAL2_LANGUAGE_LABEL,
            "error": result["error"],
            "answers": {},
        }

    answers = result.get("answers") or {}
    quality_ans = answers.get("rule_quality_score") or {}
    fp_ans = answers.get("false_positive_risk") or {}
    tactic_ans = answers.get("mitre_tactic") or {}
    sections_ans = answers.get("has_required_yaral2_sections") or {}
    ready_ans = answers.get("ready_for_validation") or {}

    raw_score = quality_ans.get("score")
    shifted_score = round(float(raw_score) + 1.0, 4) if raw_score is not None else None
    sections_noul = sections_ans.get("noul")
    ready_noul = ready_ans.get("noul")

    return {
        "enabled": True,
        "model": result.get("model", "gemini-decision-1"),
        "rule_language": _YARAL2_LANGUAGE_LABEL,
        "rule_quality_score": shifted_score,
        "rule_quality_confidence": quality_ans.get("confidence"),
        "false_positive_risk": fp_ans.get("choice"),
        "false_positive_confidence": fp_ans.get("confidence"),
        "mitre_tactic": tactic_ans.get("choice"),
        "mitre_tactic_confidence": tactic_ans.get("confidence"),
        "has_required_yaral2_sections": (
            bool(float(sections_noul) >= 0.5) if sections_noul is not None else None
        ),
        "has_required_yaral2_sections_noul": sections_noul,
        "ready_for_validation": (
            bool(float(ready_noul) >= 0.5) if ready_noul is not None else None
        ),
        "ready_for_validation_noul": ready_noul,
        "answers": answers,
        "usage": result.get("usage", {}),
    }
