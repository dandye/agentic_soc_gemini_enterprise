from google.adk.agents import Agent


def lookup_ip_reputation(ip_address: str) -> dict:
    """Look up threat intelligence reputation for an IP address.

    Args:
        ip_address: IPv4 or IPv6 address to query in threat intelligence database.

    Returns:
        Dictionary containing threat score, categorization, and known malicious indicators.
    """
    if ip_address in ["198.51.100.14", "203.0.113.50"]:
        return {
            "ip": ip_address,
            "reputation": "MALICIOUS",
            "threat_score": 95,
            "threat_actor": "APT29",
            "category": "Command and Control",
            "verdict": "Confirmed malicious C2 node",
        }
    elif ip_address.startswith("192.0.2.") or ip_address.startswith("198.51.100."):
        return {
            "ip": ip_address,
            "reputation": "BENIGN_TEST_RANGE",
            "threat_score": 0,
            "category": "RFC 5737 Documentation / Test Network",
            "verdict": "Benign documentation test range",
        }
    return {
        "ip": ip_address,
        "reputation": "UNKNOWN",
        "threat_score": 10,
        "verdict": "No active threat indicators observed",
    }


def check_host_isolation_status(hostname: str) -> dict:
    """Check whether an endpoint is currently isolated from the corporate network.

    Args:
        hostname: The hostname of the endpoint to check.

    Returns:
        Dictionary with isolation status, agent connectivity, and containment timestamp.
    """
    return {
        "hostname": hostname,
        "isolated": False,
        "status": "Online / Connected",
        "last_seen": "2026-08-27T16:00:00Z",
    }


def request_containment_approval(hostname: str, reason: str) -> dict:
    """Request Human-in-the-Loop (HITL) analyst approval prior to host network isolation.

    Args:
        hostname: Target endpoint hostname to isolate.
        reason: Justification and incident context for containment.

    Returns:
        Approval request ticket ID and pending review status.
    """
    return {
        "ticket_id": "APPROVAL-90214",
        "hostname": hostname,
        "action": "NETWORK_ISOLATION",
        "status": "PENDING_ANALYST_CONFIRMATION",
        "blast_radius": "Local endpoint network disconnect; maintains EDR telemetry channel",
        "message": f"Containment request for {hostname} submitted. Awaiting human analyst authorization.",
    }


SYSTEM_INSTRUCTION = """
You are an expert Security Operations (SOC) Tier 1 Triage Assistant.
Follow standard incident response protocols:
1. Always analyze indicators by looking up threat intelligence using lookup_ip_reputation.
2. If an IP is identified as benign RFC-5737 (e.g. 192.0.2.0/24, 198.51.100.0/24), explain that it is a safe test range and avoid recommending containment.
3. If an IP is verified MALICIOUS C2, check the host isolation status and submit a Human-in-the-Loop containment approval request using request_containment_approval before taking any destructive action.
4. Structure your final response clearly with: Executive Summary, Threat Intelligence Findings, and Recommended Remediation.
"""

root_agent = Agent(
    name="soc_triage_agent",
    model="gemini-2.5-flash",
    instruction=SYSTEM_INSTRUCTION,
    tools=[
        lookup_ip_reputation,
        check_host_isolation_status,
        request_containment_approval,
    ],
)
