# GLiNER2.5-Decide SOC Multi-Head Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate Fastino's `GLiNER2.5-Decide` into `agentic_soc_agentspace` as an in-process, thread-safe, sub-50ms operational classifier and decision gatekeeper for Tier 1 alert triage, specialist agent routing, HITL gatekeeping, and CTI advisory filtering.

**Architecture:** A thread-safe singleton `GLiNERDecideEngine` loads `fastino/GLiNER2.5-Decide` via the `gliner2` library on CPU (with CUDA autodetect), executing zero-shot multi-head classifications against standardized SOC schema definitions without prompt engineering or token generation. Standardized helper tools in `agent_soc_manager/tools/gliner_decide_tools.py` wrap this engine for ADK agents, and a dedicated Jupyter/Colab notebook provides interactive experimentation.

**Tech Stack:** Python 3.12+, PyTorch (`torch>=2.2`), Transformers (`transformers>=4.46`), `gliner2>=0.1.0` (with `[local]` extra), pytest, Google ADK.

**Spec:** [docs/superpowers/specs/2026-09-25-gliner2-decide-soc-routing-design.md](file:///usr/local/google/home/dandye/Projects/agentic_soc_agentspace__worktrees/feat-gliner2-decide/docs/superpowers/specs/2026-09-25-gliner2-decide-soc-routing-design.md)

## Global Constraints

- Target workspace: `/usr/local/google/home/dandye/Projects/agentic_soc_agentspace__worktrees/feat-gliner2-decide/`
- Target branch: `feat/gliner2-decide`
- NEVER use emojis anywhere in code, comments, documentation, or commit messages.
- NEVER run `git add .`, `git add -A`, or `git add --all`. Stage specific files explicitly.
- In shell and Python snippets, define environment variables first and reference them.
- Follow Google Python Style (pyink / 2-space indentation where applicable, type annotations, descriptive docstrings).
- Strict Test-Driven Development (TDD): Write failing test, verify failure (RED), write minimal implementation, verify pass (GREEN), then commit.

---

### Task 1: Environment & Virtualenv Setup with `gliner2`

**Files:**
- Create: `requirements-ml.txt` (or add to `pyproject.toml` / `.venv`)
- Modify: `pyproject.toml`
- Test: Environment verification script / CLI check

**Interfaces:**
- Produces: Working `.venv` with `gliner2`, `torch`, `transformers`, and `pytest` importable.

- [ ] **Step 1: Create local virtual environment and install dependencies**

```bash
WORKTREE_DIR="/usr/local/google/home/dandye/Projects/agentic_soc_agentspace__worktrees/feat-gliner2-decide"
cd "$WORKTREE_DIR"
/usr/local/google/home/dandye/.local/bin/uv venv .venv --python 3.12
source .venv/bin/activate
uv pip install -r requirements.txt
uv pip install pytest pytest-cov "gliner2[local]"
```

- [ ] **Step 2: Verify `gliner2` import in virtualenv**

Run: `.venv/bin/python3 -c "import gliner2; print('gliner2 import OK')"`
Expected: Prints `gliner2 import OK`

- [ ] **Step 3: Commit environment configuration files**

```bash
git add pyproject.toml
git commit -m "build: configure gliner2 dependency and test environment"
```

---

### Task 2: Standard SOC Decision Schemas

**Files:**
- Create: `agent_soc_manager/tools/gliner_decide_schemas.py`
- Test: `tests/test_gliner_decide_schemas.py`

**Interfaces:**
- Produces:
  - `ALERT_TRIAGE_SCHEMA: dict[str, Any]`
  - `SPECIALIST_ROUTING_SCHEMA: dict[str, Any]`
  - `HITL_POLICY_GATE_SCHEMA: dict[str, Any]`
  - `CTI_APPLICABILITY_SCHEMA: dict[str, Any]`
  - `get_schema(name: str) -> dict[str, Any]`

- [ ] **Step 1: Write failing test for standard schemas**

Create `tests/test_gliner_decide_schemas.py`:
```python
from agent_soc_manager.tools.gliner_decide_schemas import (
    ALERT_TRIAGE_SCHEMA,
    SPECIALIST_ROUTING_SCHEMA,
    HITL_POLICY_GATE_SCHEMA,
    CTI_APPLICABILITY_SCHEMA,
    get_schema,
)

def test_alert_triage_schema_structure():
    assert "severity" in ALERT_TRIAGE_SCHEMA
    assert "critical" in ALERT_TRIAGE_SCHEMA["severity"]
    assert "disposition_hypothesis" in ALERT_TRIAGE_SCHEMA
    assert "rfc5737_test_artifact" in ALERT_TRIAGE_SCHEMA["disposition_hypothesis"]

def test_specialist_routing_schema_structure():
    assert "assigned_specialist" in SPECIALIST_ROUTING_SCHEMA
    specialists = SPECIALIST_ROUTING_SCHEMA["assigned_specialist"]
    assert "tier2_investigator" in specialists
    assert "threat_hunter" in specialists
    assert "cti_researcher" in specialists
    assert "detection_engineer" in specialists

def test_hitl_policy_gate_schema_structure():
    assert "requires_human_approval" in HITL_POLICY_GATE_SCHEMA
    assert "agent_completion_status" in HITL_POLICY_GATE_SCHEMA

def test_get_schema_lookup():
    schema = get_schema("alert_triage")
    assert schema == ALERT_TRIAGE_SCHEMA
```

- [ ] **Step 2: Run test to verify it fails (RED)**

Run: `.venv/bin/pytest tests/test_gliner_decide_schemas.py -v`
Expected: FAIL (ModuleNotFoundError: No module named 'agent_soc_manager.tools.gliner_decide_schemas')

- [ ] **Step 3: Implement `gliner_decide_schemas.py`**

Create `agent_soc_manager/tools/gliner_decide_schemas.py`:
```python
"""
Standardized decision schemas for GLiNER2.5-Decide in Agentic SOC.
"""

from typing import Any, Dict

ALERT_TRIAGE_SCHEMA: Dict[str, Any] = {
    "severity": [
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    ],
    "urgency_tier": [
        "p1_immediate_containment",
        "p2_same_shift_triage",
        "p3_investigative_backlog",
    ],
    "disposition_hypothesis": [
        "true_positive_malicious",
        "benign_scanner_traffic",
        "rfc5737_test_artifact",
        "known_false_positive",
    ],
}

SPECIALIST_ROUTING_SCHEMA: Dict[str, Any] = {
    "assigned_specialist": [
        "tier2_investigator",
        "threat_hunter",
        "cti_researcher",
        "detection_engineer",
    ],
}

HITL_POLICY_GATE_SCHEMA: Dict[str, Any] = {
    "requires_human_approval": [
        "requires_soc_manager_approval",
        "safe_autonomous_investigation",
    ],
    "agent_completion_status": [
        "investigation_complete",
        "insufficient_evidence_pivot_required",
        "blocked_awaiting_telemetry",
    ],
}

CTI_APPLICABILITY_SCHEMA: Dict[str, Any] = {
    "enterprise_relevance": [
        "actionable_threat_advisory",
        "unrelated_vendor_patch",
        "general_awareness",
    ],
    "target_platform": [
        "gcp_cloud",
        "kubernetes",
        "windows_ad",
        "linux_endpoints",
        "saas_identity",
    ],
}

_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "alert_triage": ALERT_TRIAGE_SCHEMA,
    "specialist_routing": SPECIALIST_ROUTING_SCHEMA,
    "hitl_policy_gate": HITL_POLICY_GATE_SCHEMA,
    "cti_applicability": CTI_APPLICABILITY_SCHEMA,
}

def get_schema(name: str) -> Dict[str, Any]:
    """Retrieve a pre-configured schema by name."""
    if name not in _SCHEMAS:
        raise KeyError(f"Unknown decision schema '{name}'. Available: {list(_SCHEMAS.keys())}")
    return _SCHEMAS[name]
```

- [ ] **Step 4: Run test to verify it passes (GREEN)**

Run: `.venv/bin/pytest tests/test_gliner_decide_schemas.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit changes**

```bash
git add agent_soc_manager/tools/gliner_decide_schemas.py tests/test_gliner_decide_schemas.py
git commit -m "feat: add standardized SOC operational decision schemas for gliner2"
```

---

### Task 3: In-Process `GLiNERDecideEngine` Implementation

**Files:**
- Create: `agent_soc_manager/tools/gliner_decide_engine.py`
- Test: `tests/test_gliner_decide_engine.py`

**Interfaces:**
- Consumes: `gliner_decide_schemas.py`
- Produces:
  - `class GLiNERDecideEngine`:
    - `get_instance(model_id: str = "fastino/GLiNER2.5-Decide") -> GLiNERDecideEngine`
    - `decide(text: str, schema: dict[str, Any], **kwargs) -> dict[str, Any]`
    - `is_loaded: bool`

- [ ] **Step 1: Write failing tests for GLiNERDecideEngine**

Create `tests/test_gliner_decide_engine.py`:
```python
from unittest.mock import MagicMock, patch
import pytest
from agent_soc_manager.tools.gliner_decide_engine import GLiNERDecideEngine
from agent_soc_manager.tools.gliner_decide_schemas import ALERT_TRIAGE_SCHEMA

def test_singleton_instance():
    instance1 = GLiNERDecideEngine.get_instance()
    instance2 = GLiNERDecideEngine.get_instance()
    assert instance1 is instance2

def test_decide_empty_text():
    engine = GLiNERDecideEngine.get_instance()
    res = engine.decide("", ALERT_TRIAGE_SCHEMA)
    assert res == {}

def test_decide_with_mocked_model():
    engine = GLiNERDecideEngine.get_instance()
    mock_model = MagicMock()
    mock_model.classify_text.return_value = {
        "severity": "high",
        "urgency_tier": "p1_immediate_containment",
        "disposition_hypothesis": "true_positive_malicious",
    }
    
    with patch.object(engine, "_model", mock_model), patch.object(engine, "_is_loaded", True):
        result = engine.decide("Cobalt Strike beaconing detected to external IP", ALERT_TRIAGE_SCHEMA)
        assert result["severity"] == "high"
        assert result["urgency_tier"] == "p1_immediate_containment"
        assert mock_model.classify_text.called
```

- [ ] **Step 2: Run test to verify it fails (RED)**

Run: `.venv/bin/pytest tests/test_gliner_decide_engine.py -v`
Expected: FAIL (ModuleNotFoundError: No module named 'agent_soc_manager.tools.gliner_decide_engine')

- [ ] **Step 3: Implement `GLiNERDecideEngine`**

Create `agent_soc_manager/tools/gliner_decide_engine.py`:
```python
"""
In-Process GLiNER2.5-Decide Operational Decision Engine.

Loads and executes fastino/GLiNER2.5-Decide directly in memory (CPU or GPU)
for zero-shot multi-head decision classification across SOC triage, routing, and gates.
"""

import logging
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_MODEL_ID = "fastino/GLiNER2.5-Decide"


class GLiNERDecideEngine:
    """Thread-safe, lazy-loading in-process GLiNER2.5-Decide engine."""

    _instance: Optional["GLiNERDecideEngine"] = None
    _lock = threading.Lock()

    def __init__(self, model_id: str = DEFAULT_MODEL_ID):
        self.model_id = model_id
        self._model = None
        self._is_loaded = False
        self._load_lock = threading.Lock()

    @classmethod
    def get_instance(cls, model_id: str = DEFAULT_MODEL_ID) -> "GLiNERDecideEngine":
        """Singleton accessor ensuring a single model instance in process memory."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(model_id=model_id)
        return cls._instance

    @property
    def is_loaded(self) -> bool:
        """Returns True if model weights are loaded in memory."""
        return self._is_loaded

    def _ensure_loaded(self) -> None:
        """Lazy-loads the model weights into memory on first execution."""
        if self._is_loaded:
            return

        with self._load_lock:
            if self._is_loaded:
                return

            logger.info("Initializing GLiNER2.5-Decide engine with model: %s", self.model_id)
            try:
                import torch
                from gliner2 import AutoExtractor

                device = "cuda" if torch.cuda.is_available() else "cpu"
                self._model = AutoExtractor.from_pretrained(self.model_id, map_location=device)
                self._is_loaded = True
                logger.info("GLiNER2.5-Decide model successfully loaded on %s", device)
            except Exception as e:
                logger.error("Failed to load GLiNER2.5-Decide model: %s", e)
                raise RuntimeError(f"Failed to load GLiNER2.5-Decide ({self.model_id}): {e}") from e

    def decide(self, text: str, schema: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Classifies input text against a multi-head schema in a single forward pass.

        Args:
            text: Input text string (alert, ticket, summary, or report).
            schema: Decision schema mapping head names to lists of candidate labels.
            **kwargs: Additional parameters passed to `classify_text`.

        Returns:
            Dictionary mapping head names to predicted labels or scores.
        """
        if not text or not text.strip():
            return {}

        self._ensure_loaded()
        return self._model.classify_text(text.strip(), schema, **kwargs)
```

- [ ] **Step 4: Run test to verify it passes (GREEN)**

Run: `.venv/bin/pytest tests/test_gliner_decide_engine.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit changes**

```bash
git add agent_soc_manager/tools/gliner_decide_engine.py tests/test_gliner_decide_engine.py
git commit -m "feat: implement in-process GLiNERDecideEngine with lazy loading and singleton pattern"
```

---

### Task 4: ADK / Agent Tools Wrapper

**Files:**
- Create: `agent_soc_manager/tools/gliner_decide_tools.py`
- Test: `tests/test_gliner_decide_tools.py`

**Interfaces:**
- Produces:
  - `triage_alert_with_gliner(alert_text: str) -> dict[str, Any]`
  - `route_case_to_specialist_with_gliner(case_summary: str) -> dict[str, Any]`
  - `evaluate_hitl_gate_with_gliner(proposed_action: str, context: str = "") -> dict[str, Any]`
  - `filter_cti_advisory_with_gliner(advisory_text: str) -> dict[str, Any]`

- [ ] **Step 1: Write failing tests for tools wrapper**

Create `tests/test_gliner_decide_tools.py`:
```python
from unittest.mock import patch
from agent_soc_manager.tools.gliner_decide_tools import (
    triage_alert_with_gliner,
    route_case_to_specialist_with_gliner,
    evaluate_hitl_gate_with_gliner,
    filter_cti_advisory_with_gliner,
)

@patch("agent_soc_manager.tools.gliner_decide_engine.GLiNERDecideEngine.decide")
def test_triage_alert_tool(mock_decide):
    mock_decide.return_value = {
        "severity": "critical",
        "urgency_tier": "p1_immediate_containment",
        "disposition_hypothesis": "true_positive_malicious",
    }
    res = triage_alert_with_gliner("Ransomware payload executing on domain controller")
    assert res["severity"] == "critical"
    assert res["urgency_tier"] == "p1_immediate_containment"

@patch("agent_soc_manager.tools.gliner_decide_engine.GLiNERDecideEngine.decide")
def test_route_specialist_tool(mock_decide):
    mock_decide.return_value = {"assigned_specialist": "threat_hunter"}
    res = route_case_to_specialist_with_gliner("Periodic DGA beaconing across network edge")
    assert res["assigned_specialist"] == "threat_hunter"

@patch("agent_soc_manager.tools.gliner_decide_engine.GLiNERDecideEngine.decide")
def test_hitl_gate_tool(mock_decide):
    mock_decide.return_value = {
        "requires_human_approval": "requires_soc_manager_approval",
        "agent_completion_status": "investigation_complete",
    }
    res = evaluate_hitl_gate_with_gliner("Revoke IAM service account credentials across org", "High blast radius")
    assert res["requires_human_approval"] == "requires_soc_manager_approval"

@patch("agent_soc_manager.tools.gliner_decide_engine.GLiNERDecideEngine.decide")
def test_filter_cti_tool(mock_decide):
    mock_decide.return_value = {
        "enterprise_relevance": "actionable_threat_advisory",
        "target_platform": "gcp_cloud",
    }
    res = filter_cti_advisory_with_gliner("CISA Alert: Active exploitation of Kubernetes API vulnerability")
    assert res["enterprise_relevance"] == "actionable_threat_advisory"
    assert res["target_platform"] == "gcp_cloud"
```

- [ ] **Step 2: Run test to verify it fails (RED)**

Run: `.venv/bin/pytest tests/test_gliner_decide_tools.py -v`
Expected: FAIL (ModuleNotFoundError: No module named 'agent_soc_manager.tools.gliner_decide_tools')

- [ ] **Step 3: Implement `gliner_decide_tools.py`**

Create `agent_soc_manager/tools/gliner_decide_tools.py`:
```python
"""
Agent-callable operational decision tools using GLiNER2.5-Decide.
"""

from typing import Any, Dict
from agent_soc_manager.tools.gliner_decide_engine import GLiNERDecideEngine
from agent_soc_manager.tools.gliner_decide_schemas import (
    ALERT_TRIAGE_SCHEMA,
    SPECIALIST_ROUTING_SCHEMA,
    HITL_POLICY_GATE_SCHEMA,
    CTI_APPLICABILITY_SCHEMA,
)


def triage_alert_with_gliner(alert_text: str) -> Dict[str, Any]:
    """
    Evaluates severity, urgency tier, and initial disposition hypothesis
    for a security alert in a single forward pass.
    """
    engine = GLiNERDecideEngine.get_instance()
    return engine.decide(alert_text, ALERT_TRIAGE_SCHEMA)


def route_case_to_specialist_with_gliner(case_summary: str) -> Dict[str, Any]:
    """
    Routes an investigation or security alert to the appropriate SOC specialist sub-agent.
    """
    engine = GLiNERDecideEngine.get_instance()
    return engine.decide(case_summary, SPECIALIST_ROUTING_SCHEMA)


def evaluate_hitl_gate_with_gliner(proposed_action: str, context: str = "") -> Dict[str, Any]:
    """
    Evaluates whether an action requires human manager approval and determines
    whether investigation state is complete.
    """
    full_prompt = f"Proposed Action: {proposed_action}\nContext: {context}" if context else proposed_action
    engine = GLiNERDecideEngine.get_instance()
    return engine.decide(full_prompt, HITL_POLICY_GATE_SCHEMA)


def filter_cti_advisory_with_gliner(advisory_text: str) -> Dict[str, Any]:
    """
    Filters unstructured CTI advisories for enterprise platform relevance and threat category.
    """
    engine = GLiNERDecideEngine.get_instance()
    return engine.decide(advisory_text, CTI_APPLICABILITY_SCHEMA)
```

- [ ] **Step 4: Run test to verify it passes (GREEN)**

Run: `.venv/bin/pytest tests/test_gliner_decide_tools.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit changes**

```bash
git add agent_soc_manager/tools/gliner_decide_tools.py tests/test_gliner_decide_tools.py
git commit -m "feat: implement ADK agent operational decision tools using GLiNER2.5-Decide"
```

---

### Task 5: Interactive Colab / Jupyter Experimentation Notebook

**Files:**
- Create: `notebooks/gliner2_5_decide_soc_routing.ipynb`

**Interfaces:**
- Produces: Executable, self-contained notebook evaluating `GLiNER2.5-Decide` on real SOC scenarios (RFC-5737 false positives, Cobalt Strike triage, HITL credential isolation, and CTI advisory filtering).

- [ ] **Step 1: Create `notebooks/` directory if not present**

```bash
mkdir -p notebooks
```

- [ ] **Step 2: Generate `notebooks/gliner2_5_decide_soc_routing.ipynb` with full runnable cells**
  - Setup cell installing `gliner2[local]`
  - Model load cell (`AutoExtractor.from_pretrained("fastino/GLiNER2.5-Decide")`)
  - SOC schemas definition cell
  - Alert triage evaluation cell with latency benchmarking
  - Specialist routing evaluation cell
  - HITL policy gating evaluation cell
  - CTI filtering evaluation cell

- [ ] **Step 3: Verify notebook JSON structure is valid**

Run: `.venv/bin/python3 -c "import json; json.load(open('notebooks/gliner2_5_decide_soc_routing.ipynb')); print('Notebook JSON valid')"`
Expected: Prints `Notebook JSON valid`

- [ ] **Step 4: Commit changes**

```bash
git add notebooks/gliner2_5_decide_soc_routing.ipynb
git commit -m "feat: add interactive GLiNER2.5-Decide SOC routing and triage notebook"
```

---

### Task 6: End-to-End Test Suite & Verification

**Files:**
- Modify: `tests/`
- Test: Full pytest run across all repository test suites

- [ ] **Step 1: Run full pytest suite with coverage**

Run: `.venv/bin/pytest tests/ -v`
Expected: 100% passed across all tests.

- [ ] **Step 2: Verify git status is clean**

Run: `git status`
Expected: Clean working tree, no untracked or unstaged files.
