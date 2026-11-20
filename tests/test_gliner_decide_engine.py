"""Unit tests for in-process GLiNERDecideEngine."""

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
  res_whitespace = engine.decide("   \n\t  ", ALERT_TRIAGE_SCHEMA)
  assert res_whitespace == {}


def test_decide_with_mocked_model():
  engine = GLiNERDecideEngine.get_instance()
  mock_model = MagicMock()
  mock_model.classify_text.return_value = {
      "severity": "high",
      "urgency_tier": "p1_immediate_containment",
      "disposition_hypothesis": "true_positive_malicious",
  }

  with patch.object(engine, "_model", mock_model), patch.object(
      engine, "_is_loaded", True
  ):
    result = engine.decide(
        "Cobalt Strike beaconing detected to external IP", ALERT_TRIAGE_SCHEMA
    )
    assert result["severity"] == "high"
    assert result["urgency_tier"] == "p1_immediate_containment"
    assert result["disposition_hypothesis"] == "true_positive_malicious"
    assert mock_model.classify_text.called
