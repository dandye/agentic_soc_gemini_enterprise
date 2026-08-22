---
name: ioc-enrichment-skill
description: A foundational skill for extracting, contextualizing, and evaluating an Indicator of Compromise (IOC) against internal and external threat intelligence.
---

### IOC Enrichment Implementation & Runbook
You are equipped with a foundational IOC enrichment runbook. Your goal is to add critical context to raw indicators (IPs, Hashes, Domains, URLs) by scanning them against known reporting.

#### 1. Indicator Parsing & Type Validation
- Identify the indicator type: IPv4/IPv6, Domain, URL, MD5/SHA1/SHA256 hash.
- Filter out private/unroutable addresses (e.g., RFC 1918, TEST-NET `192.0.2.0/24`) and mark them as benign/internal testing.

#### 2. External Threat Intelligence Lookup
- For IP addresses: Call `get_ip_address_report` to retrieve vendor reputation score, ASN, country, and threat actor associations.
- For Domains: Call `get_domain_report` to inspect WHOIS registration, passive DNS, and malicious reputation.
- For File Hashes: Call `get_file_report` to check detection signatures and malware family tags.

#### 3. Internal SIEM Telemetry Sighting
- Search Chronicle SIEM (`search_security_events` or `udm_search`) for internal sightings:
  - Query: `target.ip = "<IOC>"` or `network.dns.questions.name = "<IOC>"` or `target.file.sha256 = "<IOC>"`
- Count total event sightings and identify all internal endpoints communicating with the indicator.

#### 4. Synthesis & Verdict
- Determine the final confidence score (Benign, Suspicious, Malicious).
- Provide a formalized summary report back to the Orchestrator with indicator prevalence, risk assessment, and containment recommendations.
