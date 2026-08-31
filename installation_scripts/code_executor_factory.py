"""
Code Executor Factory for Vertex AI Agent Engine, Code Interpreter, and local execution.
Provides unified instantiation and security math utilities for SOC analytics.
"""

from __future__ import annotations

import collections
import datetime
import math
import os
from typing import Any, List, Dict

# Set default mTLS and Vertex environment flags to prevent client cert provider errors
os.environ.setdefault("GOOGLE_API_USE_MTLS_ENDPOINT", "never")
os.environ.setdefault("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")

from google.adk.code_executors import (
    BaseCodeExecutor,
    BuiltInCodeExecutor,
    UnsafeLocalCodeExecutor,
    VertexAiCodeExecutor,
    AgentEngineSandboxCodeExecutor,
)
from google.adk.code_executors.code_execution_utils import (
    CodeExecutionInput,
    CodeExecutionResult,
)


class LazyVertexAiCodeExecutor(BaseCodeExecutor):
    """Lazy-loaded VertexAiCodeExecutor to defer Extension RPCs and prevent startup network exceptions."""

    _executor: VertexAiCodeExecutor | None = None
    _kwargs: dict = {}

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        self._kwargs = kwargs
        self._executor = None

    def execute_code(
        self,
        invocation_context: Any,
        code_execution_input: CodeExecutionInput,
    ) -> CodeExecutionResult:
        if self._executor is None:
            self._executor = VertexAiCodeExecutor(**self._kwargs)
        return self._executor.execute_code(invocation_context, code_execution_input)


def get_code_executor(
    executor_type: str = "auto",
    sandbox_resource_name: str | None = None,
    agent_engine_resource_name: str | None = None,
    **kwargs: Any,
) -> BaseCodeExecutor:
    """Instantiates the appropriate ADK CodeExecutor based on configuration and runtime environment.

    Args:
        executor_type: One of 'auto', 'agent_engine', 'vertex_ai', 'builtin', 'local'.
        sandbox_resource_name: Specific Vertex AI Agent Engine sandbox environment resource name.
        agent_engine_resource_name: Specific Reasoning Engine / Agent Engine parent resource name.
        **kwargs: Additional configuration passed to CodeExecutor.

    Returns:
        Configured BaseCodeExecutor instance.
    """
    executor_type = executor_type.lower()

    if executor_type == "local":
        return UnsafeLocalCodeExecutor(**kwargs)

    if executor_type == "builtin":
        return BuiltInCodeExecutor(**kwargs)

    if executor_type == "vertex_ai":
        return LazyVertexAiCodeExecutor(**kwargs)

    if executor_type == "agent_engine":
        target_sandbox = sandbox_resource_name or os.environ.get(
            "SANDBOX_RESOURCE_NAME"
        )
        target_engine = agent_engine_resource_name or os.environ.get(
            "AGENT_ENGINE_RESOURCE_NAME"
        )
        return AgentEngineSandboxCodeExecutor(
            sandbox_resource_name=target_sandbox,
            agent_engine_resource_name=target_engine,
            **kwargs,
        )

    # 'auto' mode: check environment variables or default to AgentEngine/BuiltIn
    target_sandbox = sandbox_resource_name or os.environ.get("SANDBOX_RESOURCE_NAME")
    target_engine = agent_engine_resource_name or os.environ.get(
        "AGENT_ENGINE_RESOURCE_NAME"
    )

    if target_sandbox or target_engine:
        return AgentEngineSandboxCodeExecutor(
            sandbox_resource_name=target_sandbox,
            agent_engine_resource_name=target_engine,
            **kwargs,
        )

    # Fallback to BuiltInCodeExecutor if running without explicit Agent Engine resource
    return BuiltInCodeExecutor(**kwargs)


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy of a string (e.g. domain name, file name, payload).

    Formula: H(X) = -sum(P(x) * log2(P(x)))

    Args:
        data: String to calculate entropy for.

    Returns:
        Float value of Shannon entropy in bits (higher indicates randomness / DGA).
    """
    if not data:
        return 0.0

    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def calculate_beaconing_jitter(timestamps: List[str]) -> Dict[str, Any]:
    """Calculates interval statistics, delta intervals, and jitter to detect periodic C2 beaconing.

    Args:
        timestamps: List of ISO 8601 timestamp strings in chronological order.

    Returns:
        Dictionary with count, mean interval, std dev, coefficient of variation, and periodicity verdict.
    """
    if len(timestamps) < 3:
        return {
            "error": "Insufficient timestamps (minimum 3 required for beaconing analysis)",
            "is_periodic": False,
        }

    parsed_dt = []
    for ts in timestamps:
        clean_ts = ts.replace("Z", "+00:00")
        parsed_dt.append(datetime.datetime.fromisoformat(clean_ts))

    parsed_dt.sort()

    intervals = []
    for i in range(1, len(parsed_dt)):
        delta = (parsed_dt[i] - parsed_dt[i - 1]).total_seconds()
        intervals.append(delta)

    n = len(intervals)
    mean_interval = sum(intervals) / n
    variance = sum((x - mean_interval) ** 2 for x in intervals) / n
    std_dev = math.sqrt(variance)
    coefficient_of_variation = std_dev / mean_interval if mean_interval > 0 else 0.0

    # Low CV (< 0.15) indicates high regularity / automated periodic beaconing
    is_periodic = coefficient_of_variation < 0.15

    return {
        "event_count": len(timestamps),
        "interval_count": n,
        "intervals_seconds": intervals,
        "mean_interval_seconds": mean_interval,
        "std_dev_seconds": std_dev,
        "coefficient_of_variation": coefficient_of_variation,
        "is_periodic": is_periodic,
        "verdict": (
            f"HIGH CONFIDENCE AUTOMATED BEACONING (Interval ~{mean_interval:.1f}s, CV={coefficient_of_variation:.3f})"
            if is_periodic
            else f"VARIABLE HUMAN / BURSTY TRAFFIC (Mean ~{mean_interval:.1f}s, CV={coefficient_of_variation:.3f})"
        ),
    }
