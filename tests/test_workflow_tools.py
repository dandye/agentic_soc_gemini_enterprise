from agent_soc_manager.tools.workflow_tools import (
    get_all_workflow_tools,
    run_alert_report_workflow,
    run_basic_ioc_enrichment_workflow,
    run_case_report_workflow,
    run_endpoint_triage_workflow,
    run_malware_triage_workflow,
)


def test_get_all_workflow_tools_count():
    tools = get_all_workflow_tools()
    assert len(tools) == 36
    tool_names = [t.__name__ for t in tools]
    assert "run_advanced_threat_hunting_workflow" in tool_names
    assert "run_alert_report_workflow" in tool_names
    assert "run_basic_ioc_enrichment_workflow" in tool_names
    assert "run_malware_triage_workflow" in tool_names
    assert "run_close_duplicate_cases_workflow" in tool_names


def test_run_basic_ioc_enrichment_workflow():
    result = run_basic_ioc_enrichment_workflow(
        ioc_value="198.51.100.1",
        ioc_type="IP Address",
        case_id="CASE-101",
        siem_search_hours=24,
    )
    assert result is not None
    assert "198.51.100.1" in str(result) or "CASE-101" in str(result) or "GTI" in str(result)


def test_run_alert_report_workflow():
    result = run_alert_report_workflow(alert_id="ALERT-999", case_id="CASE-102")
    assert result is not None
    assert "ALERT-999" in str(result) or "CASE-102" in str(result) or "Alert" in str(result)


def test_run_malware_triage_workflow():
    result = run_malware_triage_workflow(
        file_hash="d41d8cd98f00b204e9800998ecf8427e",
        case_id="CASE-103",
    )
    assert result is not None
    assert "d41d8cd98f00b204e9800998ecf8427e" in str(result) or "CASE-103" in str(result) or "Malware" in str(result)


def test_run_case_report_workflow():
    result = run_case_report_workflow(case_id="CASE-555")
    assert result is not None
    assert "CASE-555" in str(result) or "Case" in str(result)


def test_run_endpoint_triage_workflow():
    result = run_endpoint_triage_workflow(endpoint_id="WRK-101", endpoint_type="HOST", case_id="CASE-104")
    assert result is not None
    assert "WRK-101" in str(result) or "Endpoint" in str(result) or "CASE-104" in str(result)
