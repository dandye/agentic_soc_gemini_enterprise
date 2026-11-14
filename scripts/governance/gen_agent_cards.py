#!/usr/bin/env python3
"""Regenerate terraform/agentcards/<name>.json from governed_agents/*/agent.py.

- Terraform requires explicit spec.class_methods for A2A discovery. Generating
  each agent's card directly from Python keeps 41-agents.tf synchronized.
- supportedInterfaces is stripped because the container populates its own
  runtime URL from GOOGLE_CLOUD_AGENT_ENGINE_ID during A2aAgent.set_up().
- Output is pretty-printed and key-sorted for deterministic diffs.

Usage (from repository root):
    .venv/bin/python scripts/governance/gen_agent_cards.py
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "terraform" / "agentcards"

AGENTS = (
    "cti_researcher",
    "threat_hunter",
    "detection_engineer",
    "tier2_responder",
    "soc_orchestrator",
)

PLACEHOLDER_ENV = {
    "GOOGLE_CLOUD_PROJECT": "example-secops-project",
    "GOOGLE_CLOUD_LOCATION": "us-central1",
    "GTI_AUTH_PROVIDER": (
        "projects/example-secops-project/locations/us-central1/"
        "authProviders/agw-secops-gti-api-key"
    ),
    "CHRONICLE_PROJECT_ID": "example-secops-project",
    "CHRONICLE_CUSTOMER_ID": "00000000-0000-0000-0000-000000000000",
    "CHRONICLE_REGION": "us",
    "CTI_RESEARCHER_URL": "https://example.invalid/cti_researcher/a2a",
    "THREAT_HUNTER_URL": "https://example.invalid/threat_hunter/a2a",
    "DETECTION_ENGINEER_URL": "https://example.invalid/detection_engineer/a2a",
    "TIER2_RESPONDER_URL": "https://example.invalid/tier2_responder/a2a",
}

_SIBLING_MODULES = (
    "agent",
    "decision_client",
    "gti_tools",
    "response_tools",
    "secops_mcp",
    "triage_tools",
)


def card_for(name: str) -> dict[str, Any]:
    """Import governed_agents/<name>/agent.py and serialize its AgentCard."""
    from vertexai._genai import _agent_engines_utils as utils

    agent_dir = str(ROOT / "governed_agents" / name)
    sys.path.insert(0, agent_dir)
    for stale in _SIBLING_MODULES:
        sys.modules.pop(stale, None)
    try:
        module = __import__("agent")
    finally:
        sys.path.remove(agent_dir)

    card = utils._serialize_agent_card_to_dict(module.root_agent.agent_card)
    card.pop("supportedInterfaces", None)
    return card


def main() -> int:
    os.environ.update(PLACEHOLDER_ENV)

    from google.cloud import aiplatform

    aiplatform.init(
        project=PLACEHOLDER_ENV["GOOGLE_CLOUD_PROJECT"],
        location=PLACEHOLDER_ENV["GOOGLE_CLOUD_LOCATION"],
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for name in AGENTS:
        card = card_for(name)
        path = OUT_DIR / f"{name}.json"
        path.write_text(json.dumps(card, indent=2, sort_keys=True) + "\n")
        skills = len(card.get("skills", []))
        print(f"wrote {path.relative_to(ROOT)} ({skills} skills)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
