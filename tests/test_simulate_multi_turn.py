"""Unit tests for the Open-Ended Multi-Turn Conversation Simulator (`installation_scripts/simulate_multi_turn.py`)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from installation_scripts.simulate_multi_turn import (
    SIMULATOR_PERSONAS,
    format_simulator_contents,
    generate_simulated_user_turn,
    run_simulation,
)


class _DummyModels:
    def __init__(self, replies: list[str]) -> None:
        self._replies = list(replies)
        self.calls: list[dict[str, Any]] = []

    def generate_content(self, *, model: str, contents: list[Any], config: Any) -> Any:
        self.calls.append({"model": model, "contents": contents, "config": config})
        reply = self._replies.pop(0) if self._replies else "[SIMULATION_COMPLETE]"

        class _Resp:
            text = reply

        return _Resp()


class _DummyGenAIClient:
    def __init__(self, replies: list[str]) -> None:
        self.models = _DummyModels(replies)


class _DummyStreamingRemoteAgent:
    """Simulates a deployed Vertex AI Reasoning Engine (`AdkApp`) with `async_create_session` and `async_stream_query`."""

    def __init__(self, session_id: str = "9876543210") -> None:
        self.session_id = session_id
        self.queries: list[dict[str, str]] = []

    async def async_create_session(self, user_id: str) -> dict[str, str]:
        return {"id": self.session_id, "user_id": user_id}

    async def async_stream_query(
        self, *, user_id: str, session_id: str, message: str
    ):
        self.queries.append(
            {"user_id": user_id, "session_id": session_id, "message": message}
        )
        turn_idx = len(self.queries)
        yield {
            "content": {
                "role": "model",
                "parts": [
                    {
                        "functionCall": {
                            "name": "udm_search",
                            "args": {
                                "query": f"turn_{turn_idx}",
                                "hours_back": 168,
                            },
                        },
                        "text": None,
                    }
                ],
            }
        }
        yield {
            "content": {
                "role": "model",
                "parts": [
                    {
                        "text": (
                            f"Completed turn {turn_idx} investigation on FINANCE-WRK-01.\n\n"
                            "*Agent: agent_soc_manager | Model: gemini-3.1-pro-preview | Tools: udm_search*"
                        )
                    }
                ],
            }
        }


class _DummyDirectQueryAgent:
    """Simulates an `agentplatform` runtime exposing synchronous `.query(user_id, session_id, message)`."""

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def query(self, *, user_id: str, session_id: str, message: str) -> dict[str, Any]:
        self.calls.append(
            {"user_id": user_id, "session_id": session_id, "message": message}
        )
        return {
            "output": (
                f"Audited request: {message}\n\n"
                "*Agent: agent_soc_manager | Model: gemini-3.1-pro-preview | Tools: None*"
            )
        }


def test_format_simulator_contents_flips_perspective() -> None:
    """Verify assistant messages become user inputs to the simulator LLM and simulator messages become model outputs."""
    history = [
        {"author": "user", "text": "Hello, please check FINANCE-WRK-01."},
        {"author": "assistant", "text": "No events in 24h on FINANCE-WRK-01."},
        {"author": "user", "text": "Expand to 7 days (hours_back=168)."},
    ]
    contents = format_simulator_contents(history)
    assert len(contents) == 3
    assert contents[0].role == "model"
    assert contents[0].parts[0].text == "Hello, please check FINANCE-WRK-01."
    assert contents[1].role == "user"
    assert contents[1].parts[0].text == "No events in 24h on FINANCE-WRK-01."
    assert contents[2].role == "model"
    assert contents[2].parts[0].text == "Expand to 7 days (hours_back=168)."


def test_generate_simulated_user_turn_invokes_genai_client() -> None:
    """Verify generate_simulated_user_turn passes flipped history and returns trimmed prompt."""
    dummy_client = _DummyGenAIClient(
        ["  Pivot to srv-dc-prod-01 over the last 7 days (hours_back=168).  "]
    )
    history = [
        {"author": "user", "text": "Initial triage prompt"},
        {"author": "assistant", "text": "Initial triage findings"},
    ]
    next_turn = generate_simulated_user_turn(
        history,
        genai_client=dummy_client,  # type: ignore[arg-type]
        simulator_model="gemini-2.5-flash",
    )
    assert (
        next_turn
        == "Pivot to srv-dc-prod-01 over the last 7 days (hours_back=168)."
    )
    assert len(dummy_client.models.calls) == 1
    assert dummy_client.models.calls[0]["model"] == "gemini-2.5-flash"


def test_run_simulation_multi_turn_and_early_completion(tmp_path: Path) -> None:
    """Verify open-ended simulation runs multiple dynamic turns, stops on [SIMULATION_COMPLETE], and writes ledger + report."""
    sim_client = _DummyGenAIClient(
        [
            "Expand the lookback window to the last 7 days (hours_back=168) on FINANCE-WRK-01.",
            "Now check if any other finance workstations communicated with FINANCE-WRK-01 over the last 7 days (hours_back=168).",
            "[SIMULATION_COMPLETE] All investigation requirements satisfied.",
        ]
    )
    remote_agent = _DummyStreamingRemoteAgent(session_id="555666777")

    result = run_simulation(
        duration_minutes=5.0,
        max_turns=10,
        persona="soc_incident_commander",
        opening_prompt="Triage FINANCE-WRK-01 over the last 7 days (hours_back=168).",
        turn_delay_seconds=0.0,
        remote_agent=remote_agent,
        genai_client=sim_client,  # type: ignore[arg-type]
        output_dir=tmp_path,
    )

    # 3 user turns executed before the 3rd simulator call emitted [SIMULATION_COMPLETE]
    assert result["turn_count"] == 3
    assert result["session_id"] == "555666777"
    assert len(result["tool_calls"]) == 3
    assert result["aqua_evaluation"]["passed"] is True
    assert result["aqua_evaluation"]["score"] == 1.0

    run_file = Path(result["run_file"])
    report_file = Path(result["report_file"])
    assert run_file.exists()
    assert report_file.exists()

    saved_json = json.loads(run_file.read_text(encoding="utf-8"))
    assert saved_json["summary"]["total_turns"] == 3
    assert saved_json["summary"]["total_tool_calls"] == 3


def test_run_simulation_supports_direct_query_runtime(tmp_path: Path) -> None:
    """Verify run_simulation also supports runtimes exposing synchronous .query(user_id, session_id, message)."""
    sim_client = _DummyGenAIClient(
        [
            "What about HIPAA compliance and multi-region failover?",
            "[SIMULATION_COMPLETE]",
        ]
    )
    direct_agent = _DummyDirectQueryAgent()

    result = run_simulation(
        duration_minutes=5.0,
        max_turns=5,
        persona="enterprise_cloud_security",
        turn_delay_seconds=0.0,
        remote_agent=direct_agent,
        genai_client=sim_client,  # type: ignore[arg-type]
        output_dir=tmp_path,
    )
    assert result["turn_count"] == 2
    assert len(direct_agent.calls) == 2
    assert "enterprise_cloud_security" in SIMULATOR_PERSONAS
