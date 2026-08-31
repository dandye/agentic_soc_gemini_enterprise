"""
Unit tests for CTI NLP Document Processor and FastMCP tools.
"""

from pathlib import Path

import pytest
import respx
from google.adk.agents import Agent

from agent_soc_manager.tools.cti_nlp_tools import (
    CTI_ENTITY_LABELS,
    create_cti_nlp_agent,
    extract_and_validate_iocs,
    fetch_and_parse_cisa_advisory,
    get_cti_nlp_function_tools,
    mcp_server,
    normalize_cti_document,
    parse_security_document,
)


def test_normalize_cti_document_boilerplate_and_hashes():
    """Verifies that boilerplate lines and pagination are cleaned and split hashes rejoined."""
    raw_input = (
        "CISA Cybersecurity Advisory\n"
        "TLP:CLEAR\n"
        "Page 1 of 5 | Product ID\n"
        "Observed malicious artifact with hash:\n"
        "e3b0c44298fc1c149afbf4c8996f12 27ae41e4649b934ca495991b7852b855b9\n"
        "Contact: cert@cisa.dhs.gov\n"
    )

    result = normalize_cti_document(raw_input)
    assert result["status"] == "success"
    clean_text = result["normalized_text"]

    # Verify split hash was rejoined (30 chars + 34 chars = 64 char SHA256)
    assert "e3b0c44298fc1c149afbf4c8996f1227ae41e4649b934ca495991b7852b855b9" in clean_text
    assert result["normalized_length"] > 0


def test_extract_and_validate_iocs_strict():
    """Verifies extraction and strict grammatical filtering of valid vs malformed IOCs."""
    sample_text = (
        "Malicious infrastructure observed:\n"
        "- Valid IPv4: 198.51.100.45, 203.0.113.19:8080\n"
        "- Defanged IPv4: 192.0.2[.]1\n"
        "- Invalid IPv4 (should be rejected): 999.888.777.666, 10.0.0.999\n"
        "- Valid SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "- Invalid Hash (odd length fragment): 1234abcd5678ef\n"
        "- Valid CVE: CVE-2024-1709, CVE-2023-46805\n"
        "- Invalid CVE: CVE-ABCD-1234\n"
        "- Valid MITRE TTPs: T1190, T1059.001, TA0001\n"
        "- Valid CWE: CWE-22, CWE-89\n"
        "- Valid Email: analyst@soc-unit.example.com\n"
        "- Valid Domain: c2-controller.threat-net.org\n"
        "- TLP: TLP:CLEAR\n"
    )

    res = extract_and_validate_iocs(sample_text)
    assert res["status"] == "success"
    indicators = res["indicators"]

    # Validated IPv4s
    assert "198.51.100.45" in indicators["ipv4_addresses"]
    assert "192.0.2.1" in indicators["ipv4_addresses"]
    assert "999.888.777.666" not in indicators["ipv4_addresses"]
    assert "10.0.0.999" not in indicators["ipv4_addresses"]

    # Validated Hashes
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in indicators["file_hashes"]["sha256"]
    assert "1234abcd5678ef" not in indicators["file_hashes"]["all"]

    # Validated CVEs & MITRE TTPs
    assert "CVE-2024-1709" in indicators["cve_identifiers"]
    assert "CVE-2023-46805" in indicators["cve_identifiers"]
    assert "T1190" in indicators["mitre_attack_techniques"]
    assert "T1059.001" in indicators["mitre_attack_techniques"]
    assert "TA0001" in indicators["mitre_attack_tactics"]

    # CWE & Email
    assert "CWE-22" in indicators["cwe_identifiers"]
    assert "analyst@soc-unit.example.com" in indicators["email_addresses"]


def test_parse_security_document_text_and_markdown(tmp_path: Path):
    """Verifies document parsing for markdown and plaintext files."""
    doc_file = tmp_path / "threat_brief.md"
    doc_file.write_text(
        "# Threat Brief: APT29 Campaign\n"
        "Observed C2 IP: 198.51.100.99 communicating over HTTPS.\n"
        "Associated CVE-2024-21887 and technique T1190.\n",
        encoding="utf-8",
    )

    result = parse_security_document(str(doc_file), is_file_path=True)
    assert result["status"] == "success"
    assert result["file_name"] == "threat_brief.md"
    assert result["file_type"] == "text/markdown"
    assert "198.51.100.99" in result["extracted_iocs"]["ipv4_addresses"]
    assert "CVE-2024-21887" in result["extracted_iocs"]["cve_identifiers"]
    assert "T1190" in result["extracted_iocs"]["mitre_attack_techniques"]


def test_parse_security_document_html(tmp_path: Path):
    """Verifies document parsing for HTML files."""
    html_file = tmp_path / "advisory.html"
    html_file.write_text(
        "<html><body><h1>Advisory Alert</h1><p>Malware hash: 44d88612fea8a8f36de82e1278abb02f</p></body></html>",
        encoding="utf-8",
    )

    result = parse_security_document(str(html_file), is_file_path=True)
    assert result["status"] == "success"
    assert result["file_type"] == "text/html"
    assert "44d88612fea8a8f36de82e1278abb02f" in result["extracted_iocs"]["file_hashes"]["md5"]


@pytest.mark.asyncio
async def test_fetch_and_parse_cisa_advisory_mocked():
    """Verifies fetching and parsing a CISA cybersecurity advisory with mocked HTTP response."""
    slug = "aa24-038a"
    mock_url = f"https://www.cisa.gov/news-events/cybersecurity-advisories/{slug}"
    html_content = (
        "<html><body>"
        "<h1>AA24-038A: PRC State-Sponsored Actors Compromise US Infrastructure</h1>"
        "<article>"
        "<p>Actors utilized living-off-the-land techniques and targeted CVE-2023-46805.</p>"
        "<p>Observed malicious IP: 198.51.100.101 and technique T1190.</p>"
        "</article>"
        "</body></html>"
    )

    async with respx.mock(assert_all_called=True) as respx_mock:
        respx_mock.get(mock_url).respond(status_code=200, text=html_content)

        res = await fetch_and_parse_cisa_advisory(slug)
        assert res["status"] == "success"
        assert res["slug"] == "aa24-038a"
        assert "PRC State-Sponsored Actors" in res["title"]
        assert "198.51.100.101" in res["extracted_iocs"]["ipv4_addresses"]
        assert "CVE-2023-46805" in res["extracted_iocs"]["cve_identifiers"]
        assert "T1190" in res["extracted_iocs"]["mitre_attack_techniques"]


def test_fastmcp_server_and_agent_builder():
    """Verifies FastMCP server tool registration and ADK Agent construction."""
    tools = get_cti_nlp_function_tools()
    assert len(tools) == 5

    agent = create_cti_nlp_agent(name="cti_test_agent")
    assert isinstance(agent, Agent)
    assert agent.name == "cti_test_agent"
    assert len(agent.tools) == 5

    # Verify FastMCP server definition
    assert mcp_server.name == "cti-nlp-processor"
    assert len(CTI_ENTITY_LABELS) == 16
