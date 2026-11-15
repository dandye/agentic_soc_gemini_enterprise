"""Compatibility shim re-exporting the canonical Decision 1 client."""

from __future__ import annotations


try:
    from shared_decision_guards.decision_client import (
        DECISION_MODEL,
        DECISIONS_API_URL,
        aevaluate_decisions,
        choice_question,
        evaluate_decisions,
        noul_question,
        score_question,
    )
except ImportError:
    from governed_agents.shared_decision_guards.decision_client import (
        DECISION_MODEL,
        DECISIONS_API_URL,
        aevaluate_decisions,
        choice_question,
        evaluate_decisions,
        noul_question,
        score_question,
    )

__all__ = [
    "DECISIONS_API_URL",
    "DECISION_MODEL",
    "aevaluate_decisions",
    "choice_question",
    "evaluate_decisions",
    "noul_question",
    "score_question",
]
