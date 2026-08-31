#!/usr/bin/env python3
"""
CTI Document Ingestion and IOC Extraction Runner
Powered by dandye/nlp_capstone and FastMCP for Google ADK.

Usage:
  # Parse a CISA advisory by slug or URL:
  python investigations/run_cti_document_ingest.py --cisa aa24-038a

  # Parse a local security document (PDF, Markdown, HTML, text):
  python investigations/run_cti_document_ingest.py --file path/to/threat_report.pdf

  # Direct test text string:
  python investigations/run_cti_document_ingest.py --text "Observed C2 IP 198.51.100.22 targeting CVE-2024-1709 and technique T1190."

  # FastMCP server launcher:
  python investigations/run_cti_document_ingest.py --serve [--transport stdio|sse]
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path


# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from agent_soc_manager.tools.cti_nlp_tools import (  # noqa: E402
    create_cti_nlp_agent,
    extract_and_validate_iocs,
    fetch_and_parse_cisa_advisory,
    mcp_server,
    normalize_cti_document,
    parse_security_document,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("run_cti_document_ingest")


async def main_async():
    parser = argparse.ArgumentParser(
        description="Ingest and extract threat intelligence using 1P CTI NLP FastMCP tools"
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Local path to a PDF, Markdown, HTML, or plaintext security document",
    )
    parser.add_argument(
        "--cisa",
        type=str,
        help="CISA advisory slug (e.g. aa24-038a) or full advisory URL",
    )
    parser.add_argument(
        "--text",
        type=str,
        help="Raw text snippet to normalize and extract IOCs from",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Launch the CTI NLP FastMCP server",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol when running --serve (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port when running --serve with SSE transport (default: 8000)",
    )

    args = parser.parse_args()

    if args.serve:
        print("=" * 80)
        print(f"STARTING CTI NLP FastMCP SERVER ({args.transport})")
        print("=" * 80)
        if args.transport == "sse":
            mcp_server.run(transport="sse", port=args.port)
        else:
            mcp_server.run(transport="stdio")
        return

    if args.cisa:
        print("=" * 80)
        print(f"FETCHING & PARSING CISA ADVISORY: {args.cisa}")
        print("=" * 80)
        result = await fetch_and_parse_cisa_advisory(args.cisa)
        print(f"Title: {result.get('title')}")
        print(f"URL:   {result.get('url')}")
        print(f"Clean Text Length: {result.get('clean_text_length')} characters")
        print(f"Total Validated IOCs: {result.get('total_iocs')}")
        print("\nExtracted Indicators:")
        print(json.dumps(result.get("extracted_iocs", {}), indent=2))
        return

    if args.file:
        print("=" * 80)
        print(f"PARSING SECURITY DOCUMENT FILE: {args.file}")
        print("=" * 80)
        result = parse_security_document(args.file, is_file_path=True)
        print(f"File Name: {result.get('file_name')}")
        print(f"File Type: {result.get('file_type')}")
        print(f"Total Validated IOCs: {result.get('total_iocs')}")
        print("\nExtracted Indicators:")
        print(json.dumps(result.get("extracted_iocs", {}), indent=2))
        return

    if args.text:
        print("=" * 80)
        print("NORMALIZING & EXTRACTING IOCS FROM TEXT SNIPPET")
        print("=" * 80)
        norm = normalize_cti_document(args.text)
        print(f"Normalized Text:\n{norm['normalized_text']}\n")
        iocs = extract_and_validate_iocs(norm["normalized_text"])
        print("Extracted Indicators:")
        print(json.dumps(iocs.get("indicators", {}), indent=2))
        return

    # Default dry run / showcase
    print("=" * 80)
    print("CTI NLP DOCUMENT PROCESSOR & FastMCP SHOWCASE")
    print("=" * 80)
    sample_text = (
        "CISA Cybersecurity Advisory\n"
        "TLP:CLEAR\n"
        "Page 1 of 3 | Product ID\n"
        "Observed APT29 actors exploiting CVE-2024-1709 and CWE-22.\n"
        "Active C2 IPv4: 198.51.100.45:443 and IPv6: 2001:db8::1\n"
        "Deployed backdoor hash: e3b0c44298fc1c149afbf4c8996f12 27ae41e4649b934ca495991b7852b855b9\n"
        "Techniques utilized: T1190, T1059.001, and tactic TA0001.\n"
        "Contact: cert@cisa.dhs.gov\n"
    )

    print("1. Raw Input Text:")
    print(sample_text)

    print("2. Normalized Output (Boilerplate Stripped, Hashes Rejoined):")
    norm = normalize_cti_document(sample_text)
    print(norm["normalized_text"])

    print("\n3. Grammatically Validated IOCs:")
    iocs = extract_and_validate_iocs(norm["normalized_text"])
    print(json.dumps(iocs["indicators"], indent=2))

    print("\n4. Initializing CTI NLP ADK Agent:")
    agent = create_cti_nlp_agent(name="cti_nlp_showcase_agent")
    print(f"   [OK] Agent Name: {agent.name}")
    print(f"   [OK] Model:      {agent.model}")
    print(f"   [OK] Tools:      {[getattr(t, '__name__', str(t)) for t in agent.tools]}")
    print("\n" + "=" * 80)
    print("DEMO EXECUTION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main_async())
