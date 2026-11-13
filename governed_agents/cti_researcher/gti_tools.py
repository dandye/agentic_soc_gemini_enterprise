"""Google Threat Intelligence (VirusTotal v3) tools backed by Auth Manager.

`GTI_AUTH_PROVIDER` holds the resource name of the Agent Identity AuthProvider
(`projects/<project>/locations/<region>/authProviders/<id>`), never the API key
itself. On each tool invocation, this module authenticates as the agent's own
SPIFFE workload identity via `agentidentitycredentials.googleapis.com` to
retrieve the credential into process memory for a single HTTPS call through
the egress Agent Gateway to `https://www.virustotal.com/api/v3/...`.
"""

import os
import threading
import urllib.parse
from typing import Any

import httpx
from decision_client import (
    choice_question,
    evaluate_decisions,
    noul_question,
    score_question,
)
from google.cloud.agentidentitycredentials_v1 import (
    AuthProviderCredentialsServiceClient,
    RetrieveCredentialsRequest,
)


GTI_API_BASE_URL = os.getenv("GTI_API_BASE_URL", "https://www.virustotal.com/api/v3")
_HTTP_TIMEOUT_SECONDS = 20.0

_creds_lock = threading.Lock()
_creds_client: AuthProviderCredentialsServiceClient | None = None


def _get_gti_api_key() -> str:
    """Retrieves the GTI API key from Agent Platform Auth Manager at call time."""
    global _creds_client
    provider_name = os.environ["GTI_AUTH_PROVIDER"]
    with _creds_lock:
        if _creds_client is None:
            _creds_client = AuthProviderCredentialsServiceClient(transport="rest")
        client = _creds_client

    response = client.retrieve_credentials(
        RetrieveCredentialsRequest(
            auth_provider=provider_name,
            user_id="cti_researcher",
        )
    )
    token = getattr(getattr(response, "success", None), "token", "") or ""
    if not token:
        raise RuntimeError(
            f"Auth Manager provider {provider_name!r} returned an empty credential"
        )
    return token


def _fetch_gti_resource(path: str) -> dict[str, Any]:
    """Executes a GET against GTI v3 without logging or echoing the API key."""
    api_key = _get_gti_api_key()
    url = f"{GTI_API_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = client.get(
            url,
            headers={
                "x-apikey": api_key,
                "Accept": "application/json",
            },
        )
    if response.status_code == 404:
        return {
            "found": False,
            "status_code": 404,
            "detail": "Indicator not found in GTI.",
        }
    if response.status_code >= 400:
        return {
            "error": (
                f"GTI API returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )
        }
    payload = response.json()
    return {"found": True, "data": payload.get("data", {})}


def _summarize_indicator(
    indicator: str, indicator_type: str, result: dict[str, Any]
) -> dict[str, Any]:
    """Extracts concise reputation attributes from a GTI v3 object."""
    if "error" in result or not result.get("found"):
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            **result,
        }

    data = result.get("data") or {}
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    threat_cls = attrs.get("popular_threat_classification") or {}

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "found": True,
        "id": data.get("id", indicator),
        "reputation": attrs.get("reputation"),
        "malicious_detections": stats.get("malicious", 0),
        "suspicious_detections": stats.get("suspicious", 0),
        "harmless_detections": stats.get("harmless", 0),
        "undetected_engines": stats.get("undetected", 0),
        "popular_threat_label": threat_cls.get("suggested_threat_label"),
        "tags": (attrs.get("tags") or [])[:15],
        "categories": attrs.get("categories") or {},
        "meaningful_name": attrs.get("meaningful_name"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


def lookup_file_hash_reputation(file_hash: str) -> dict[str, Any]:
    """Looks up GTI / VirusTotal reputation and detections for a SHA256, SHA1, or MD5 file hash."""
    cleaned = urllib.parse.quote(file_hash.strip(), safe="")
    raw = _fetch_gti_resource(f"files/{cleaned}")
    return _summarize_indicator(file_hash.strip(), "file_hash", raw)


def lookup_domain_reputation(domain: str) -> dict[str, Any]:
    """Looks up GTI / VirusTotal reputation, categories, and detections for a domain name."""
    cleaned = urllib.parse.quote(domain.strip().lower(), safe=".-")
    raw = _fetch_gti_resource(f"domains/{cleaned}")
    return _summarize_indicator(domain.strip().lower(), "domain", raw)


def lookup_ip_reputation(ip_address: str) -> dict[str, Any]:
    """Looks up GTI / VirusTotal reputation, ASN owner, country, and detections for an IPv4/IPv6 address."""
    cleaned = urllib.parse.quote(ip_address.strip(), safe=".:")
    raw = _fetch_gti_resource(f"ip_addresses/{cleaned}")
    return _summarize_indicator(ip_address.strip(), "ip_address", raw)


def get_threat_collection(collection_id: str) -> dict[str, Any]:
    """Retrieves metadata and description for a GTI threat collection, campaign, or malware report ID."""
    cleaned = urllib.parse.quote(collection_id.strip(), safe="-_")
    raw = _fetch_gti_resource(f"collections/{cleaned}")
    if "error" in raw or not raw.get("found"):
        return {
            "collection_id": collection_id.strip(),
            **raw,
        }
    data = raw.get("data") or {}
    attrs = data.get("attributes") or {}
    return {
        "collection_id": data.get("id", collection_id.strip()),
        "found": True,
        "name": attrs.get("name"),
        "collection_type": attrs.get("collection_type"),
        "description": (attrs.get("description") or "")[:1200],
        "tags": (attrs.get("tags") or [])[:20],
        "targeted_industries": attrs.get("targeted_industries") or [],
        "targeted_regions": attrs.get("targeted_regions") or [],
    }


def classify_ioc_intelligence(indicator_summaries_json: str) -> dict[str, Any]:
    """Classifies GTI/IOC enrichment summaries in a single Decision 1 pass."""
    cleaned = (indicator_summaries_json or "").strip()
    if not cleaned:
        return {
            "enabled": False,
            "error": "indicator_summaries_json must not be empty.",
        }

    questions = {
        "verdict": choice_question(
            instructions=(
                "Classify the overall threat verdict for the summarized GTI/IOC "
                "indicator data."
            ),
            criteria={
                "malicious": (
                    "Confirmed malicious indicator with strong multi-engine "
                    "detections, malware family attribution, or active C2/exploit "
                    "infrastructure."
                ),
                "suspicious": (
                    "Partially flagged or anomalous indicator with moderate "
                    "detections, newly observed domain, or ambiguous threat context."
                ),
                "benign": (
                    "Clean or well-known legitimate infrastructure with zero or "
                    "negligible detections and trusted ownership."
                ),
                "unknown": (
                    "Insufficient intelligence, indicator not found in GTI, or "
                    "conflicting data that prevents classification."
                ),
            },
        ),
        "threat_category": choice_question(
            instructions=(
                "Select the primary threat category represented by the indicator "
                "intelligence."
            ),
            criteria={
                "malware_delivery": (
                    "Payload hosting, dropper, downloader, or malicious "
                    "executable distribution."
                ),
                "command_and_control": (
                    "Command-and-control server, beaconing domain/IP, or covert "
                    "exfiltration channel."
                ),
                "phishing_credential_theft": (
                    "Phishing lure, credential harvesting infrastructure, or "
                    "brand impersonation."
                ),
                "scanning_exploitation": (
                    "Vulnerability scanner, brute-force source, or active "
                    "exploit delivery."
                ),
                "benign_infrastructure": (
                    "Legitimate CDN, cloud provider, DNS resolver, or trusted "
                    "enterprise service."
                ),
                "other_or_unknown": (
                    "Threat category does not match the above options or "
                    "insufficient data is present."
                ),
            },
        ),
        "confidence_score": score_question(
            instructions=(
                "Rate classification confidence from lowest (level 0) to highest "
                "(level 4) based on detection consensus and threat context."
            ),
            criteria=[
                "Very low confidence: indicator not found, conflicting signals, or minimal context.",
                "Low confidence: isolated weak detection with no threat family attribution.",
                "Moderate confidence: multiple suspicious signals or moderate detections without clear attribution.",
                "High confidence: strong multi-engine consensus, consistent tags, or known threat label.",
                "Very high confidence: overwhelming malicious consensus, explicit malware or campaign attribution, and corroborating metadata.",
            ],
        ),
        "requires_immediate_hunt": noul_question(
            "True if the indicator intelligence warrants immediate internal "
            "SIEM/UDM threat hunting across endpoints, network logs, or DNS "
            "telemetry; false otherwise."
        ),
        "false_positive_likely": noul_question(
            "True if detections are likely a false positive such as a dual-use "
            "admin tool, shared CDN/cloud IP, or isolated vendor heuristic; "
            "false otherwise."
        ),
    }

    decision = evaluate_decisions(
        input_text=(
            "GTI / VirusTotal v3 indicator enrichment summaries:\n" f"{cleaned}"
        ),
        questions=questions,
    )
    if not decision.get("enabled"):
        return {
            "enabled": False,
            "reason": decision.get("reason", "Decision 1 is not configured."),
        }
    if "error" in decision:
        return {
            "enabled": True,
            "error": decision["error"],
        }

    answers = decision.get("answers", {})
    verdict_ans = answers.get("verdict") or {}
    category_ans = answers.get("threat_category") or {}
    confidence_ans = answers.get("confidence_score") or {}
    hunt_ans = answers.get("requires_immediate_hunt") or {}
    fp_ans = answers.get("false_positive_likely") or {}

    raw_score = confidence_ans.get("score")
    confidence_score = (
        round(float(raw_score) + 1.0, 2) if raw_score is not None else None
    )

    hunt_prob = hunt_ans.get("noul")
    fp_prob = fp_ans.get("noul")

    return {
        "enabled": True,
        "verdict": verdict_ans.get("choice", "unknown"),
        "verdict_confidence": verdict_ans.get("confidence"),
        "threat_category": category_ans.get("choice", "other_or_unknown"),
        "threat_category_confidence": category_ans.get("confidence"),
        "confidence_score": confidence_score,
        "requires_immediate_hunt": (
            bool(float(hunt_prob) >= 0.5) if hunt_prob is not None else False
        ),
        "requires_immediate_hunt_probability": hunt_prob,
        "false_positive_likely": (
            bool(float(fp_prob) >= 0.5) if fp_prob is not None else False
        ),
        "false_positive_likely_probability": fp_prob,
        "usage": decision.get("usage", {}),
    }
