"""
Unit tests for In-Process SecureBERT Named Entity Recognition Engine and Tools.
"""

from unittest.mock import MagicMock

import pytest

from agent_soc_manager.tools.cti_nlp_tools import (
    extract_entities_with_securebert,
    get_cti_nlp_function_tools,
)
from agent_soc_manager.tools.securebert_engine import (
    SECUREBERT_CTI_MODEL_ID,
    SecureBertNerEngine,
)


def test_securebert_singleton():
    """Verifies that SecureBertNerEngine behaves as a thread-safe singleton."""
    engine1 = SecureBertNerEngine.get_instance()
    engine2 = SecureBertNerEngine.get_instance()
    assert engine1 is engine2
    assert engine1.model_id == SECUREBERT_CTI_MODEL_ID


def test_securebert_extract_empty_text():
    """Verifies handling of empty or whitespace-only inputs."""
    engine = SecureBertNerEngine.get_instance()
    res = engine.extract_entities("")
    assert res["status"] == "success"
    assert res["total_entities_detected"] == 0
    assert res["unique_entities_extracted"] == 0


def test_securebert_extract_entities_mocked():
    """Verifies entity extraction, thresholding, and categorization with mock pipeline."""
    mock_pipeline = MagicMock()
    mock_pipeline.return_value = [
        {"entity_group": "threat actor group", "score": 0.95, "word": " Volt Typhoon", "start": 0, "end": 12},
        {"entity_group": "malware family", "score": 0.88, "word": " KV-botnet", "start": 58, "end": 67},
        {"entity_group": "hacking tool", "score": 0.92, "word": " Mimikatz", "start": 72, "end": 80},
        {"entity_group": "cve identifier", "score": 0.96, "word": " CVE-2023-46805", "start": 91, "end": 105},
        {"entity_group": "attack technique id", "score": 0.94, "word": " T1190", "start": 110, "end": 115},
        {"entity_group": "threat actor group", "score": 0.20, "word": " LowConfidenceActor", "start": 120, "end": 138},
    ]

    engine = SecureBertNerEngine(model_id="test-securebert")
    engine._pipeline = mock_pipeline
    engine._is_loaded = True

    sample_text = (
        "Volt Typhoon actors compromised SOHO routers and deployed KV-botnet and Mimikatz "
        "targeting CVE-2023-46805 exploiting T1190."
    )

    res = engine.extract_entities(sample_text, confidence_threshold=0.5)

    assert res["status"] == "success"
    assert res["model"] == "test-securebert"
    assert res["inference_mode"] == "in_process_cpu"
    # Low confidence (0.20) should be dropped
    assert res["total_entities_detected"] == 5

    categorized = res["categorized_entities"]
    threat_actors = [item["value"] for item in categorized["threat_actors"]]
    malware = [item["value"] for item in categorized["malware_families"]]
    tools = [item["value"] for item in categorized["hacking_tools"]]
    cves = [item["value"] for item in categorized["cve_identifiers"]]
    techniques = [item["value"] for item in categorized["mitre_techniques"]]

    assert "Volt Typhoon" in threat_actors
    assert "KV-botnet" in malware
    assert "Mimikatz" in tools
    assert "CVE-2023-46805" in cves
    assert "T1190" in techniques


def test_securebert_tool_registration():
    """Verifies that extract_entities_with_securebert is registered in function tools."""
    tools = get_cti_nlp_function_tools()
    tool_names = [getattr(t, "__name__", str(t)) for t in tools]
    assert "extract_entities_with_securebert" in tool_names


@pytest.mark.slow
def test_securebert_live_inference_cpu():
    """Verifies live in-process CPU inference with real SecureBERT weights."""
    sample_text = (
        "Volt Typhoon actors deployed KV-botnet and Mimikatz against critical infrastructure "
        "exploiting CVE-2023-46805 and technique T1190."
    )
    result = extract_entities_with_securebert(sample_text, confidence_threshold=0.5)

    assert result["status"] == "success"
    assert result["inference_mode"] == "in_process_cpu"
    assert result["total_entities_detected"] > 0

    categorized = result["categorized_entities"]
    threat_actors = [item["value"] for item in categorized.get("threat_actors", [])]
    tools = [item["value"] for item in categorized.get("hacking_tools", [])]

    assert any("Volt" in actor for actor in threat_actors)
    assert any("Mimikatz" in t for t in tools)
