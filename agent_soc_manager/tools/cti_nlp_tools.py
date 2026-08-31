"""
CTI Document Processor and NER FastMCP Server for Google ADK.

This module provides a 1P custom MCP Server and ADK toolset leveraging
the CTI Named Entity Recognition and text normalization pipeline from
dandye/nlp_capstone (external/nlp_capstone).

It handles:
1. Deterministic text normalization (boilerplate/pagination removal, hash rejoining).
2. Grammatical span validation for 16 CTI entity types (IOCs, CVEs, MITRE TTPs).
3. Parsing of local PDFs, HTML, Markdown, and CISA advisories.
4. Direct in-process ADK tool integration or standalone FastMCP server execution.
"""

import logging
import re
import sys
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup
from google.adk.agents import Agent
from mcp.server.fastmcp import FastMCP
from pypdf import PdfReader


logger = logging.getLogger(__name__)

# Ensure external/nlp_capstone is importable
_REPO_ROOT = Path(__file__).resolve().parents[2]
_NLP_CAPSTONE_ROOT = _REPO_ROOT / "external" / "nlp_capstone"
if _NLP_CAPSTONE_ROOT.exists() and str(_NLP_CAPSTONE_ROOT) not in sys.path:
    sys.path.insert(0, str(_NLP_CAPSTONE_ROOT))

# Import normalization and validation modules from nlp_capstone
try:
    from ner.span_validators import (
        _clean,
        _refang,
        _valid_cve,
        _valid_cwe,
        _valid_email,
        _valid_hash,
        _valid_ip,
        _valid_technique_id,
        _valid_tlp,
        validate,
    )
    from ner.text_normalize import (
        code_regions,
        rejoin_split_hashes,
        strip_boilerplate,
    )
    from scraper.fetcher import BROWSER_UA
except ImportError:
    logger.warning(
        "nlp_capstone submodule not found at %s. Using internal fallback algorithms.",
        _NLP_CAPSTONE_ROOT,
    )
    # Inline fallback implementations if submodule is uninitialized
    def _refang(t: str) -> str:
        return t.replace("[.]", ".").replace("[@]", "@").replace("hxxp", "http")

    def _clean(t: str) -> str:
        return _refang(t.strip()).strip(".,;:!?\"'()[]{}<>")

    def _valid_hash(t: str) -> bool:
        c = _clean(t)
        return bool(re.match(r"^[0-9a-fA-F]+$", c)) and len(c) in {32, 40, 64, 128}

    def _valid_ip(t: str) -> bool:
        c = _clean(t)
        m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(:\d+)?(/\S*)?$", c)
        if m:
            return all(int(m.group(i)) <= 255 for i in range(1, 5))
        return c.count(":") >= 2 and bool(re.match(r"^[0-9a-fA-F:]+$", c))

    def _valid_email(t: str) -> bool:
        return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s.]+$", _clean(t)))

    def _valid_cve(t: str) -> bool:
        return bool(re.match(r"^CVE-\d{4}-\d{4,7}$", _clean(t), re.IGNORECASE))

    def _valid_cwe(t: str) -> bool:
        return bool(re.match(r"^CWE-\d{1,4}$", _clean(t), re.IGNORECASE))

    def _valid_technique_id(t: str) -> bool:
        c = _clean(t)
        return bool(re.match(r"^T\d{4}(\.\d{3})?$", c, re.IGNORECASE)) or bool(
            re.match(r"^TA\d{4}$", c, re.IGNORECASE)
        )

    def _valid_tlp(t: str) -> bool:
        return bool(
            re.match(
                r"^(CISA\s+)?TLP\s*:?\s*(CLEAR|WHITE|GREEN|AMBER(\+STRICT)?|RED)$",
                _clean(t),
                re.IGNORECASE,
            )
        )

    def validate(label: str, text: str) -> bool:
        mapping = {
            "file hash": _valid_hash,
            "ip address": _valid_ip,
            "email address": _valid_email,
            "cve identifier": _valid_cve,
            "cwe identifier": _valid_cwe,
            "attack technique id": _valid_technique_id,
            "tlp classification": _valid_tlp,
        }
        fn = mapping.get(label)
        return fn(text) if fn else True

    def strip_boilerplate(text: str) -> str:
        return re.sub(r"^\s*page\s+\d+(\s+of\s+\d+)?\s*(\||tlp:|product\s+id|$).*\n?", "", text, flags=re.IGNORECASE | re.MULTILINE)

    def rejoin_split_hashes(text: str) -> str:
        return re.sub(r"\b([0-9a-fA-F]{8,127})\s+([0-9a-fA-F]{4,63})\b", r"\1\2", text)

    def code_regions(text: str) -> list[tuple]:
        return []

    BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


# Instantiate FastMCP server instance
mcp_server = FastMCP(
    name="cti-nlp-processor",
)

# 16 Gold CTI Entity Types
CTI_ENTITY_LABELS = [
    "affected software product",
    "attack technique id",
    "attack technique name",
    "cve identifier",
    "cwe identifier",
    "email address",
    "file hash",
    "file name",
    "file path",
    "hacking tool",
    "ip address",
    "malware family",
    "tactic",
    "threat actor group",
    "tlp classification",
    "yara rule name",
]


@mcp_server.tool()
def normalize_cti_document(
    text: str,
    remove_boilerplate: bool = True,
    rejoin_hashes: bool = True,
) -> dict[str, Any]:
    """Normalizes CTI document text by removing repetitive page headers, footers,

    pagination artifacts, and rejoining PDF line-wrapped hashes.

    Args:
        text: Raw document text (extracted from PDF, HTML, or Markdown).
        remove_boilerplate: Whether to strip pagination and repeated header banners.
        rejoin_hashes: Whether to merge line-wrapped hexadecimal hash fragments.

    Returns:
        Dict containing the normalized text, detected code regions, and stats.
    """
    cleaned = text
    if rejoin_hashes:
        cleaned = rejoin_split_hashes(cleaned)
    if remove_boilerplate:
        cleaned = strip_boilerplate(cleaned)

    detected_code = code_regions(cleaned)

    return {
        "status": "success",
        "original_length": len(text),
        "normalized_length": len(cleaned),
        "code_region_count": len(detected_code),
        "normalized_text": cleaned,
    }


@mcp_server.tool()
def extract_and_validate_iocs(text: str) -> dict[str, Any]:
    """Extracts and grammatically validates all Indicators of Compromise (IOCs) from text.

    Performs grammatical span validation to filter out spurious tokens (e.g. invalid length hashes,
    invalid IP octets, malformed CVE IDs).

    Args:
        text: Input security text, report, or advisory body.

    Returns:
        Dict containing categorized, validated, and deduplicated IOCs.
    """
    refanged_text = _refang(text)

    # Candidate regex extractions
    raw_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", refanged_text)
    raw_ipv6s = re.findall(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b", refanged_text)
    raw_hashes = re.findall(r"\b[0-9a-fA-F]{32,128}\b", refanged_text)
    raw_cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", refanged_text, re.IGNORECASE)
    raw_cwes = re.findall(r"\bCWE-\d{1,4}\b", refanged_text, re.IGNORECASE)
    raw_techniques = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", refanged_text, re.IGNORECASE)
    raw_tactics = re.findall(r"\bTA\d{4}\b", refanged_text, re.IGNORECASE)
    raw_emails = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", refanged_text)
    raw_domains = re.findall(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|gov|edu|io|mil|info|biz|co|ru|cn|top|xyz|cc)\b",
        refanged_text,
        re.IGNORECASE,
    )
    raw_tlp = re.findall(
        r"\b(?:CISA\s+)?TLP\s*:?\s*(?:CLEAR|WHITE|GREEN|AMBER(?:\+STRICT)?|RED)\b",
        refanged_text,
        re.IGNORECASE,
    )

    def _is_valid_ipv6(val: str) -> bool:
        try:
            import ipaddress
            ipaddress.IPv6Address(_clean(val).strip("[]"))
            return True
        except ValueError:
            return False

    # Apply strict span validators from nlp_capstone
    valid_ipv4 = sorted({ip for ip in raw_ips if _valid_ip(ip)})
    valid_ipv6 = sorted({ip for ip in raw_ipv6s if _is_valid_ipv6(ip)})
    valid_hashes = sorted({h.lower() for h in raw_hashes if _valid_hash(h)})
    valid_cves = sorted({c.upper() for c in raw_cves if _valid_cve(c)})
    valid_cwes = sorted({c.upper() for c in raw_cwes if _valid_cwe(c)})
    valid_tcodes = sorted({t.upper() for t in raw_techniques if _valid_technique_id(t)})
    valid_tacodes = sorted({ta.upper() for ta in raw_tactics if _valid_technique_id(ta)})
    valid_emails = sorted({e.lower() for e in raw_emails if _valid_email(e)})
    valid_domains = sorted({d.lower() for d in raw_domains})
    valid_tlp = sorted({_clean(tlp).upper() for tlp in raw_tlp if _valid_tlp(tlp)})

    # Categorize hashes by algorithm
    md5_hashes = [h for h in valid_hashes if len(h) == 32]
    sha1_hashes = [h for h in valid_hashes if len(h) == 40]
    sha256_hashes = [h for h in valid_hashes if len(h) == 64]
    sha512_hashes = [h for h in valid_hashes if len(h) == 128]

    total_count = (
        len(valid_ipv4)
        + len(valid_ipv6)
        + len(valid_hashes)
        + len(valid_cves)
        + len(valid_cwes)
        + len(valid_tcodes)
        + len(valid_tacodes)
        + len(valid_emails)
        + len(valid_domains)
    )

    return {
        "status": "success",
        "total_validated_iocs": total_count,
        "indicators": {
            "ipv4_addresses": valid_ipv4,
            "ipv6_addresses": valid_ipv6,
            "domains": valid_domains,
            "email_addresses": valid_emails,
            "cve_identifiers": valid_cves,
            "cwe_identifiers": valid_cwes,
            "mitre_attack_techniques": valid_tcodes,
            "mitre_attack_tactics": valid_tacodes,
            "tlp_classifications": valid_tlp,
            "file_hashes": {
                "md5": md5_hashes,
                "sha1": sha1_hashes,
                "sha256": sha256_hashes,
                "sha512": sha512_hashes,
                "all": valid_hashes,
            },
        },
    }


@mcp_server.tool()
def parse_security_document(
    file_path_or_content: str,
    is_file_path: bool = True,
    normalize: bool = True,
) -> dict[str, Any]:
    """Parses a security document (PDF, HTML, Markdown, or plain text) and extracts validated IOCs.

    Args:
        file_path_or_content: Local file path or raw document string.
        is_file_path: Set True if input is a filesystem path, False if raw string.
        normalize: Whether to apply nlp_capstone text normalization.

    Returns:
        Dict containing raw text, normalized text, extracted IOCs, and document metadata.
    """
    raw_text = ""
    file_name = "raw_content"
    file_type = "text/plain"

    if is_file_path:
        path = Path(file_path_or_content).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path_or_content}")

        file_name = path.name
        suffix = path.suffix.lower()

        if suffix == ".pdf":
            file_type = "application/pdf"
            reader = PdfReader(str(path))
            pages_text = [page.extract_text() or "" for page in reader.pages]
            raw_text = "\n".join(pages_text)
        elif suffix in (".html", ".htm"):
            file_type = "text/html"
            soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="replace"), "html.parser")
            raw_text = soup.get_text("\n")
        else:
            file_type = "text/markdown" if suffix in (".md", ".markdown") else "text/plain"
            raw_text = path.read_text(encoding="utf-8", errors="replace")
    else:
        raw_text = file_path_or_content

    # Normalize text
    norm_result = normalize_cti_document(raw_text) if normalize else {"normalized_text": raw_text}
    clean_text = norm_result["normalized_text"]

    # Extract IOCs
    ioc_result = extract_and_validate_iocs(clean_text)

    return {
        "status": "success",
        "file_name": file_name,
        "file_type": file_type,
        "raw_text_length": len(raw_text),
        "clean_text_length": len(clean_text),
        "clean_text": clean_text,
        "extracted_iocs": ioc_result["indicators"],
        "total_iocs": ioc_result["total_validated_iocs"],
    }


@mcp_server.tool()
async def fetch_and_parse_cisa_advisory(slug_or_url: str) -> dict[str, Any]:
    """Fetches and parses a CISA advisory by URL or advisory code (e.g. 'aa24-038a' or 'AA24-038A').

    Args:
        slug_or_url: CISA advisory slug (e.g. 'aa24-038a') or full URL.

    Returns:
        Dict with advisory metadata, clean body text, and extracted indicators.
    """
    import httpx

    slug = slug_or_url.strip().lower()
    if "/" in slug:
        match = re.search(r"/(aa\d{2}-\d{3}[a-z]|ar\d{2}-\d{3}[a-z]|alert/[^/]+)", slug)
        if match:
            slug = match.group(1).replace("alert/", "")

    target_url = (
        slug_or_url
        if slug_or_url.startswith("http")
        else f"https://www.cisa.gov/news-events/cybersecurity-advisories/{slug}"
    )

    logger.info("Fetching CISA advisory from %s", target_url)
    try:
        from scraper.fetcher import CISAFetcher
        async with CISAFetcher() as fetcher:
            path = target_url.replace("https://www.cisa.gov", "")
            resp = await fetcher.get(path)
            html_text = resp.text
            final_url = f"https://www.cisa.gov{path}" if not path.startswith("http") else path
    except Exception as fetch_err:
        logger.warning("CISAFetcher failed (%s), attempting direct httpx with browser headers", fetch_err)
        headers = {
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=30.0) as client:
            resp = await client.get(target_url)
            resp.raise_for_status()
            html_text = resp.text
            final_url = str(resp.url)

    soup = BeautifulSoup(html_text, "html.parser")

    # Extract title
    title_el = soup.find("h1")
    title = title_el.get_text(strip=True) if title_el else slug

    # Check for PDF attachment link
    pdf_link = None
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.endswith(".pdf") and ("/files/" in href or "csa" in href.lower() or "aa" in href.lower()):
            pdf_link = f"https://www.cisa.gov{href}" if href.startswith("/") else href
            break

    body_text = ""
    source_format = "html"

    if pdf_link:
        try:
            logger.info("Found official PDF advisory attachment: %s", pdf_link)
            from io import BytesIO

            from pypdf import PdfReader
            from scraper.fetcher import CISAFetcher
            async with CISAFetcher() as pdf_fetcher:
                pdf_path = pdf_link.replace(pdf_fetcher.base_url, "")
                pdf_resp = await pdf_fetcher.get(pdf_path)
                reader = PdfReader(BytesIO(pdf_resp.content))
                pages = [p.extract_text() or "" for p in reader.pages]
                body_text = "\n".join(pages)
                source_format = f"pdf ({len(reader.pages)} pages)"
        except Exception as pdf_err:
            logger.warning("Failed to extract PDF attachment (%s), falling back to HTML", pdf_err)

    if not body_text:
        article_el = soup.find("article") or soup.find("main") or soup.find("div", class_="c-field--name-body")
        body_text = article_el.get_text("\n", strip=True) if article_el else soup.get_text("\n", strip=True)

    # Normalize and extract IOCs
    clean_body = strip_boilerplate(rejoin_split_hashes(body_text))
    ioc_result = extract_and_validate_iocs(clean_body)

    return {
        "status": "success",
        "slug": slug,
        "title": title,
        "url": final_url,
        "source_format": source_format,
        "clean_text_length": len(clean_body),
        "clean_text": clean_body,
        "extracted_iocs": ioc_result["indicators"],
        "total_iocs": ioc_result["total_validated_iocs"],
    }


@mcp_server.tool()
def extract_entities_with_securebert(
    text: str,
    confidence_threshold: float = 0.5,
) -> dict[str, Any]:
    """Extracts semantic CTI entities (threat actors, malware families, hacking tools, CVEs)

    using in-process SecureBERT neural token classification (pzryathzsdhc/cti-ner-securebert).

    Runs locally in process memory (CPU) with zero external network overhead.

    Args:
        text: Raw threat report or advisory text.
        confidence_threshold: Minimum prediction probability [0.0 - 1.0]. Default is 0.5.

    Returns:
        Dict containing categorized threat actors, malware, tools, CVEs, and confidence metrics.
    """
    from agent_soc_manager.tools.securebert_engine import SecureBertNerEngine

    engine = SecureBertNerEngine.get_instance()
    return engine.extract_entities(text=text, confidence_threshold=confidence_threshold)


def get_cti_nlp_function_tools() -> list[Any]:
    """Returns the list of standalone Python function tools for direct in-process ADK agents."""
    return [
        normalize_cti_document,
        extract_and_validate_iocs,
        extract_entities_with_securebert,
        parse_security_document,
        fetch_and_parse_cisa_advisory,
    ]


def create_cti_nlp_agent(
    model: str = "gemini-2.5-flash",
    name: str = "cti_nlp_analyst",
) -> Agent:
    """Builds a dedicated ADK CTI Document and NER Ingestion Agent.

    Args:
        model: Gemini model name.
        name: Name of the agent.

    Returns:
        Configured ADK Agent instance equipped with nlp_capstone CTI tools.
    """
    instruction = (
        "You are an expert Cyber Threat Intelligence (CTI) Ingestion and NER Analyst. "
        "Your role is to analyze security advisories, vulnerability bulletins, incident summaries, "
        "and threat reports.\n\n"
        "You have direct access to specialized in-process CTI processing tools:\n"
        "1. `extract_entities_with_securebert`: In-process neural Named Entity Recognition (SecureBERT) "
        "for semantic extraction of threat actor groups, malware families, hacking tools, and affected products.\n"
        "2. `extract_and_validate_iocs`: High-speed deterministic extraction and grammatical validation for "
        "IP addresses, file hashes (MD5, SHA1, SHA256, SHA512), CVE IDs, CWE IDs, and MITRE ATT&CK techniques.\n"
        "3. `parse_security_document`: Ingests and parses PDF, HTML, Markdown, or plaintext documents, "
        "normalizing text and extracting all validated indicators.\n"
        "4. `fetch_and_parse_cisa_advisory`: Directly fetches CISA cybersecurity alerts by slug (e.g. 'aa24-038a') "
        "or URL, downloading PDF attachments and extracting full telemetry.\n"
        "5. `normalize_cti_document`: Cleans boilerplate headers, pagination, and rejoins split hashes.\n\n"
        "Always present threat intelligence findings structured by Threat Actors, Malware Families, "
        "Hacking Tools, CVE Vulnerabilities, MITRE ATT&CK TTPs, and validated IOC tables."
    )

    return Agent(
        model=model,
        name=name,
        instruction=instruction,
        tools=get_cti_nlp_function_tools(),
    )


def main():
    """CLI entrypoint to run the CTI NLP FastMCP server over stdio or sse."""
    import argparse

    parser = argparse.ArgumentParser(description="CTI NLP Document Processor FastMCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument("--port", type=int, default=8000, help="Port for SSE transport")
    args = parser.parse_args()

    logger.info("Starting CTI NLP FastMCP Server over %s transport", args.transport)
    if args.transport == "sse":
        mcp_server.run(transport="sse", port=args.port)
    else:
        mcp_server.run(transport="stdio")


if __name__ == "__main__":
    main()
