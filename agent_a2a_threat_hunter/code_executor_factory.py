"""
Code Executor Factory for Vertex AI Agent Engine, Code Interpreter, and local execution.
Provides unified instantiation and security math utilities for SOC analytics.
"""

from __future__ import annotations

import collections
import datetime
import math
import os
import threading
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
import copy
# Patch AgentEngineSandboxCodeExecutor.__deepcopy__ and __reduce__ to handle unpicklable threading.Lock
def _agent_engine_sandbox_deepcopy(self: Any, memo: dict) -> Any:
    m = self.__class__.__new__(self.__class__)
    memo[id(self)] = m
    for k, v in self.__dict__.items():
        object.__setattr__(m, k, copy.deepcopy(v, memo))
    if hasattr(self, "__pydantic_fields_set__"):
        object.__setattr__(
            m,
            "__pydantic_fields_set__",
            copy.deepcopy(self.__pydantic_fields_set__, memo),
        )
    object.__setattr__(
        m,
        "__pydantic_extra__",
        copy.deepcopy(getattr(self, "__pydantic_extra__", None), memo),
    )
    priv = {}
    for k, v in getattr(self, "__pydantic_private__", {}).items():
        if k == "_agent_engine_creation_lock":
            priv[k] = threading.Lock()
        else:
            priv[k] = copy.deepcopy(v, memo)
    object.__setattr__(m, "__pydantic_private__", priv)
    return m


def _reconstruct_agent_engine_sandbox(cls: Any, state: dict) -> Any:
    obj = cls.__new__(cls)
    obj.__dict__.update(state)
    obj._agent_engine_creation_lock = threading.Lock()
    return obj


def _agent_engine_sandbox_reduce(self: Any) -> Any:
    state = dict(self.__dict__)
    state.pop("_agent_engine_creation_lock", None)
    return (_reconstruct_agent_engine_sandbox, (self.__class__, state))


AgentEngineSandboxCodeExecutor.__deepcopy__ = _agent_engine_sandbox_deepcopy
AgentEngineSandboxCodeExecutor.__reduce__ = _agent_engine_sandbox_reduce



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

    # 'auto' mode: default to AgentEngineSandboxCodeExecutor
    target_sandbox = sandbox_resource_name or os.environ.get("SANDBOX_RESOURCE_NAME")
    target_engine = agent_engine_resource_name or os.environ.get(
        "AGENT_ENGINE_RESOURCE_NAME"
    )
    return AgentEngineSandboxCodeExecutor(
        sandbox_resource_name=target_sandbox,
        agent_engine_resource_name=target_engine,
        **kwargs,
    )


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
    variance = (
        sum((x - mean_interval) ** 2 for x in intervals) / (n - 1)
        if n > 1
        else 0.0
    )
    std_dev = math.sqrt(variance)
    coefficient_of_variation = (
        std_dev / mean_interval if mean_interval > 0 else 0.0
    )

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


def extract_payload_strings(data: bytes | str, min_length: int = 4) -> List[str]:
    """Extracts printable ASCII and UTF-16LE strings from raw binary payload data.

    Args:
        data: Raw bytes or string buffer to extract strings from.
        min_length: Minimum length of continuous printable characters.

    Returns:
        List of extracted string tokens.
    """
    import re

    if isinstance(data, str):
        data = data.encode("utf-8")

    extracted: List[str] = []

    # 1. ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
    for m in ascii_pattern.finditer(data):
        extracted.append(m.group(0).decode("ascii", errors="ignore"))

    # 2. UTF-16LE strings (common in Windows PE binaries, PowerShell scripts, registry blobs)
    utf16_pattern = re.compile(
        rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}"
    )
    for m in utf16_pattern.finditer(data):
        try:
            decoded = m.group(0).decode("utf-16le", errors="ignore")
            if decoded and decoded not in extracted:
                extracted.append(decoded)
        except Exception:
            pass

    return extracted


def deobfuscate_xor_strings(
    payload: bytes | str,
    key_range: range | list | None = None,
    max_preview_bytes: int = 65536,
) -> List[Dict[str, Any]]:
    """Brute-forces single-byte XOR obfuscation to recover hidden URLs, IPs, commands, and strings (FLOSS pattern).

    Args:
        payload: Obfuscated binary payload or hex string.
        key_range: Optional key candidates to evaluate (defaults to 1..255).
        max_preview_bytes: Max initial buffer bytes to scan for scoring to prevent sandbox CPU timeouts on large blobs.

    Returns:
        Sorted list of candidate decrypted outputs ranked by confidence score.
    """
    import binascii
    import re

    if isinstance(payload, str):
        try:
            payload_bytes = binascii.unhexlify(
                payload.replace(" ", "").replace("0x", "")
            )
        except Exception:
            payload_bytes = payload.encode("latin1")
    else:
        payload_bytes = payload

    if key_range is None:
        key_range = range(1, 256)

    eval_payload = (
        payload_bytes[:max_preview_bytes]
        if len(payload_bytes) > max_preview_bytes
        else payload_bytes
    )

    candidates = []
    high_value_keywords = [
        "http://",
        "https://",
        ".exe",
        ".dll",
        "powershell",
        "cmd.exe",
        "rundll32",
        "reg.exe",
        "whoami",
        "beacon",
        "user-agent",
        ".com",
        ".net",
        ".org",
        ".io",
    ]

    for key in key_range:
        decoded_bytes = bytes([b ^ key for b in eval_payload])
        strings = extract_payload_strings(decoded_bytes, min_length=4)

        if not strings:
            continue

        score = 0
        matched_indicators = []
        for s in strings:
            s_lower = s.lower()
            for kw in high_value_keywords:
                if kw in s_lower:
                    score += 25
                    matched_indicators.append(s)
            if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s):
                score += 30
                matched_indicators.append(s)
            if re.search(r"https?://[a-zA-Z0-9.-]+", s):
                score += 40
                matched_indicators.append(s)

        printable_ratio = (
            sum(32 <= b <= 126 for b in decoded_bytes) / len(decoded_bytes)
            if decoded_bytes
            else 0
        )
        if printable_ratio > 0.6:
            score += int(printable_ratio * 20)

        if score > 0 or strings:
            candidates.append({
                "key": key,
                "key_hex": f"0x{key:02X}",
                "confidence_score": score,
                "printable_ratio": round(printable_ratio, 3),
                "matched_indicators": list(set(matched_indicators)),
                "decoded_strings": strings,
            })

    candidates.sort(
        key=lambda x: (x["confidence_score"], x["printable_ratio"]), reverse=True
    )
    return candidates


def validate_and_test_yara_rule(
    rule_text: str, target_data: bytes | str
) -> Dict[str, Any]:
    """Compiles and tests a YARA rule against payload data inside the sandbox (YARA pattern).

    Note:
        Uses native `yara-python` compiler when available. If native `yara` is not installed,
        uses a built-in fallback parser supporting standard string matches ($s = "...")
        and presence conditions. Advanced regex ($re = /.../) and boolean expressions
        require the native `yara-python` compiler.

    Args:
        rule_text: Text of the YARA rule definition.
        target_data: Target binary bytes or string to test matching against.

    Returns:
        Dictionary with compilation status ('valid': True/False), syntax errors, and match results.
    """
    import re

    if isinstance(target_data, str):
        target_bytes = target_data.encode("utf-8", errors="ignore")
    else:
        target_bytes = target_data

    # 1. Try native yara compilation if yara-python is installed
    try:
        import yara

        try:
            compiled_rules = yara.compile(source=rule_text)
            matches = compiled_rules.match(data=target_bytes)
            matched_names = [m.rule for m in matches]
            return {
                "valid": True,
                "compiler": "native_yara",
                "matches": len(matches) > 0,
                "matched_rules": matched_names,
                "match_count": len(matches),
            }
        except yara.SyntaxError as syn_err:
            return {
                "valid": False,
                "compiler": "native_yara",
                "matches": False,
                "error": str(syn_err),
            }
    except ImportError:
        pass

    # 2. Resilient built-in YARA rule validator & evaluator fallback
    rule_match = re.search(r"rule\s+([A-Za-z0-9_]+)", rule_text)
    if not rule_match:
        return {
            "valid": False,
            "compiler": "builtin_yara_parser",
            "matches": False,
            "error": "Syntax error: Missing or invalid 'rule <RuleName>' identifier",
        }

    rule_name = rule_match.group(1)

    if "condition:" not in rule_text:
        return {
            "valid": False,
            "compiler": "builtin_yara_parser",
            "matches": False,
            "error": "Syntax error: Missing 'condition:' section in YARA rule",
        }

    string_definitions = {}
    strings_section_match = re.search(
        r"strings:(.*?)(?:condition:|$)", rule_text, re.DOTALL
    )
    if strings_section_match:
        raw_strings = strings_section_match.group(1)
        for line in raw_strings.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            str_def_match = re.match(r"(\$[A-Za-z0-9_]+)\s*=\s*\"([^\"]+)\"", line)
            if str_def_match:
                var_name, str_val = str_def_match.groups()
                string_definitions[var_name] = str_val.encode("utf-8")
            elif "=" in line and not line.endswith("}"):
                return {
                    "valid": False,
                    "compiler": "builtin_yara_parser",
                    "matches": False,
                    "error": f"Syntax error in string definition line: '{line}'",
                }

    matched_strings = []
    for var_name, str_bytes in string_definitions.items():
        if str_bytes in target_bytes:
            matched_strings.append(var_name)

    matches = len(matched_strings) > 0 if string_definitions else True

    return {
        "valid": True,
        "compiler": "builtin_yara_parser",
        "matches": matches,
        "matched_rules": [rule_name] if matches else [],
        "matched_strings": matched_strings,
        "match_count": 1 if matches else 0,
    }

