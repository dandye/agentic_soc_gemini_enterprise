#!/usr/bin/env python3
"""
Test runner demonstrating the Google ADK Native Evaluation Framework as described in:
https://adk.dev/evaluate/ and https://adk.dev/evaluate/criteria/

Supports:
1. Native `adk eval` CLI integration
2. Programmatic Python `AgentEvaluator.evaluate_eval_set()`
3. Evaluation criteria:
   - tool_trajectory_avg_score
   - response_match_score
   - rubric_based_final_response_quality_v1 (LLM-as-a-judge against custom rubrics)
   - rubric_based_tool_use_quality_v1 (LLM-as-a-judge for tool usage quality)
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path


# Ensure required environment variables for Vertex AI and mTLS settings
os.environ["GOOGLE_API_USE_MTLS_ENDPOINT"] = "never"
os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "false"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE"
if "GOOGLE_CLOUD_PROJECT" not in os.environ:
    os.environ["GOOGLE_CLOUD_PROJECT"] = os.environ.get(
        "GCP_PROJECT_ID", "dandye-0324-chronicle"
    )
if "GOOGLE_CLOUD_LOCATION" not in os.environ:
    os.environ["GOOGLE_CLOUD_LOCATION"] = "us-central1"

# Add current worktree directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from google.adk.evaluation.agent_evaluator import AgentEvaluator  # noqa: E402
from google.adk.evaluation.eval_config import EvalConfig  # noqa: E402
from google.adk.evaluation.eval_set import EvalSet  # noqa: E402


async def run_programmatic_eval_async(
    agent_module: str,
    eval_set_path: Path,
    config_path: Path,
):
    print("=" * 80)
    print("RUNNING PROGRAMMATIC ADK EVALUATION (AgentEvaluator.evaluate_eval_set)")
    print(f"Agent Module: {agent_module}")
    print(f"EvalSet File: {eval_set_path}")
    print(f"Config File:  {config_path}")
    print("=" * 80)

    with open(eval_set_path) as f:
        eval_set_data = json.load(f)
    eval_set = EvalSet.model_validate(eval_set_data)

    with open(config_path) as f:
        config_data = json.load(f)
    eval_config = EvalConfig.model_validate(config_data)

    try:
        eval_results = await AgentEvaluator.evaluate_eval_set(
            agent_module=agent_module,
            eval_set=eval_set,
            eval_config=eval_config,
            num_runs=1,
            print_detailed_results=True,
        )
        print("\nAll evaluation criteria thresholds satisfied.")
        return {"status": "SUCCESS", "results": eval_results}
    except AssertionError as e:
        print("\nEvaluation completed with threshold failures:")
        print(str(e))
        return {"status": "FAILED_THRESHOLDS", "error": str(e)}


AGENT_PRESETS = {
    "triage": {
        "agent_module": "test_agents.soc_triage_agent",
        "evalset": Path("test_agents/soc_triage_agent/soc_triage_evalset.json"),
        "config": Path("test_agents/soc_triage_agent/eval_config.json"),
    },
    "knowledge": {
        "agent_module": "test_agents.soc_knowledge_agent",
        "evalset": Path("evalsets/soc_knowledge_evalset.json"),
        "config": Path("test_agents/soc_knowledge_agent/eval_config.json"),
    },
}


def main():
    parser = argparse.ArgumentParser(
        description="Test Google ADK Native Evaluation Framework"
    )
    parser.add_argument(
        "--agent",
        type=str,
        choices=["triage", "knowledge"],
        default=None,
        help="Convenience preset to select preconfigured agent suite (triage, knowledge)",
    )
    parser.add_argument(
        "--agent-module",
        type=str,
        default=None,
        help="Import path of agent module (e.g. test_agents.soc_triage_agent, test_agents.soc_knowledge_agent)",
    )
    parser.add_argument(
        "--evalset",
        type=Path,
        default=None,
        help="Path to EvalSet JSON file",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to EvalConfig JSON file",
    )
    args = parser.parse_args()

    # Determine preset or defaults
    if args.agent:
        preset = AGENT_PRESETS[args.agent]
        agent_module = args.agent_module or preset["agent_module"]
        evalset = args.evalset or preset["evalset"]
        config = args.config or preset["config"]
    elif args.agent_module == "test_agents.soc_knowledge_agent":
        agent_module = args.agent_module
        evalset = args.evalset or AGENT_PRESETS["knowledge"]["evalset"]
        config = args.config or AGENT_PRESETS["knowledge"]["config"]
    else:
        agent_module = args.agent_module or AGENT_PRESETS["triage"]["agent_module"]
        evalset = args.evalset or AGENT_PRESETS["triage"]["evalset"]
        config = args.config or AGENT_PRESETS["triage"]["config"]

    results = asyncio.run(
        run_programmatic_eval_async(
            agent_module=agent_module,
            eval_set_path=evalset.resolve(),
            config_path=config.resolve(),
        )
    )

    print("\n" + "=" * 80)
    print(f"Evaluation Run Summary Status: {results['status']}")
    print("=" * 80)


if __name__ == "__main__":
    main()
