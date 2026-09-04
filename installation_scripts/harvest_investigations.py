import glob
import json
import os
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests
import typer
from dotenv import load_dotenv
from google.auth.transport.requests import Request
from google.oauth2 import service_account
try:
    from secops import SecOpsClient
except ImportError:
    SecOpsClient = None


load_dotenv()

app = typer.Typer(
    add_completion=False,
    help="Harvest and enrich investigations and detections from Chronicle SIEM",
)

# Configuration
sa_path = os.path.expanduser(
    os.getenv("SECOPS_SA_PATH", "/Users/dandye/.ssh/secops-demo-env-391e3b623e0a.json")
)
project_id = os.getenv("CHRONICLE_PROJECT_ID", "secops-demo-env")
location = os.getenv("CHRONICLE_REGION", "us")
instance_id = os.getenv("CHRONICLE_CUSTOMER_ID", "a13f6726-efed-452e-9008-8fe0d3cb0f75")
# Defaults to <repo-root>/investigations; override with HARVEST_OUTPUT_DIR.
output_dir = os.getenv(
    "HARVEST_OUTPUT_DIR",
    str(Path(__file__).resolve().parent.parent / "investigations"),
)

# VirusTotal API configuration
vt_api_key = os.getenv("GTI_API_KEY")


def get_credentials():
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    creds = service_account.Credentials.from_service_account_file(
        sa_path, scopes=scopes
    )
    creds.refresh(Request())
    return creds


def format_timestamp(ts_str):
    if not ts_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts_str


def make_chronicle_request(url, headers, params=None, method="GET", max_retries=5):
    backoff = 2.0
    for attempt in range(max_retries):
        try:
            if method == "GET":
                r = requests.get(url, headers=headers, params=params, timeout=15)
            else:
                r = requests.post(url, headers=headers, json=params, timeout=15)

            if r.status_code == 200:
                return r
            elif r.status_code == 429:
                print(f"Rate limited (429). Retrying in {backoff}s...")
                time.sleep(backoff)
                backoff *= 2.0
            else:
                # If it's a transient server error, retry as well
                if r.status_code in [500, 502, 503, 504]:
                    print(f"Server error {r.status_code}. Retrying in {backoff}s...")
                    time.sleep(backoff)
                    backoff *= 2.0
                else:
                    return r
        except Exception as e:
            print(f"Request exception on {url}: {e}. Retrying in {backoff}s...")
            time.sleep(backoff)
            backoff *= 2.0
    return None


def get_vt_file_report(file_hash):
    if not vt_api_key:
        return None
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": vt_api_key}
    try:
        time.sleep(0.5)
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json().get("data", {}).get("attributes", {})
    except Exception as e:
        print(f"Error fetching VT file report for {file_hash}: {e}")
    return None


def get_vt_ip_report(ip_addr):
    if not vt_api_key:
        return None
    # Skip private IPs
    if (
        ip_addr.startswith("10.")
        or ip_addr.startswith("192.168.")
        or ip_addr.startswith("172.16.")
        or ip_addr.startswith("127.0.0.1")
    ):
        return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_addr}"
    headers = {"x-apikey": vt_api_key}
    try:
        time.sleep(0.5)
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json().get("data", {}).get("attributes", {})
    except Exception as e:
        print(f"Error fetching VT IP report for {ip_addr}: {e}")
    return None


def get_vt_domain_report(domain):
    if not vt_api_key or not domain or "." not in domain or domain.endswith(".local"):
        return None
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": vt_api_key}
    try:
        time.sleep(0.5)
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json().get("data", {}).get("attributes", {})
    except Exception as e:
        print(f"Error fetching VT domain report for {domain}: {e}")
    return None


def get_chronicle_entity_summary(
    creds, entity_type, entity_value, start_time, end_time
):
    url = f"https://us-chronicle.googleapis.com/v1alpha/projects/{project_id}/locations/{location}/instances/{instance_id}:summarizeEntitiesFromQuery"
    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
    }

    query = ""
    if entity_type == "USER":
        query = f'principal.user.userid = "{entity_value}"'
    elif entity_type == "HOST":
        query = f'principal.hostname = "{entity_value}"'
    else:
        return None

    params = {
        "query": query,
        "timeRange.startTime": start_time or "2026-06-11T00:00:00Z",
        "timeRange.endTime": end_time or "2026-06-15T00:00:00Z",
    }

    r = make_chronicle_request(url, headers, params=params)
    if r and r.status_code == 200:
        summaries = r.json().get("entitySummaries", [])
        if summaries:
            return summaries[0].get("entity", [{}])[0].get("entity", {})
    return None


def generate_mermaid_sequence_diagram(steps):
    if not steps:
        return ""

    lines = []
    lines.append("## Investigation Flow")
    lines.append("")
    lines.append("```mermaid")
    lines.append("sequenceDiagram")
    lines.append("    autonumber")
    lines.append("    participant Agent as Triage Agent")
    lines.append("    participant SIEM as Chronicle SIEM")

    has_ti = False
    for step in steps:
        source_metadata = step.get("sourceMetadata", {})
        source_type = source_metadata.get("sourceType", "")
        if "THREAT" in source_type or "INTEL" in source_type:
            has_ti = True
            break
    if has_ti:
        lines.append("    participant TI as Threat Intelligence")

    lines.append("")

    for idx, step in enumerate(steps, 1):
        summary = step.get("analysisSummary", f"Step {idx}")
        summary_clean = (
            summary.replace("*", "")
            .replace("[", "")
            .replace("]", "")
            .replace("(", "")
            .replace(")", "")
            .replace('"', "'")
        )
        if len(summary_clean) > 80:
            summary_clean = summary_clean[:77] + "..."

        source_metadata = step.get("sourceMetadata", {})
        source_type = source_metadata.get("sourceType", "")

        if source_type == "SOURCE_TYPE_ALERT_FILTER":
            lines.append(f"    Agent->>Agent: Analyze alert: {summary_clean}")
        elif source_type == "SOURCE_TYPE_PROCESS_TREE":
            lines.append("    Agent->>SIEM: Fetch process launch tree")
            lines.append("    SIEM-->>Agent: Return process tree hierarchy")
        elif source_type == "SOURCE_TYPE_COMMAND_LINE_ANALYSIS":
            lines.append(f"    Agent->>Agent: Analyze command line: {summary_clean}")
        elif source_type == "SOURCE_TYPE_SEARCH":
            lines.append(f"    Agent->>SIEM: Search: {summary_clean}")
            query_info = source_metadata.get("query", {})
            total_results = query_info.get("totalResultsCount")
            if total_results is not None:
                lines.append(
                    f"    SIEM-->>Agent: Return {total_results} matching events"
                )
            else:
                lines.append("    SIEM-->>Agent: Return query results")
        elif "THREAT" in source_type or "INTEL" in source_type:
            lines.append(f"    Agent->>TI: Query threat intelligence: {summary_clean}")
            lines.append("    TI-->>Agent: Return threat indicator reputation")
        else:
            lines.append(f"    Agent->>SIEM: Execute step: {summary_clean}")
            lines.append("    SIEM-->>Agent: Return results")

    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def generate_markdown(inv, alerts_data, entities_data):
    inv_id = inv.get("name", "").split("/")[-1]
    verdict = inv.get("verdict", "UNKNOWN")
    confidence = inv.get("confidence", "N/A")
    status = inv.get("status", "UNKNOWN")
    created_time = format_timestamp(
        inv.get("publishTime") or inv.get("timeRange", {}).get("startTime")
    )
    updated_time = format_timestamp(inv.get("updateTime"))
    summary = inv.get("summary", "No summary provided.")

    alerts = inv.get("alerts", {}).get("ids", [])
    cases = inv.get("cases", {}).get("ids", [])
    steps = inv.get("investigationSteps", [])

    md = []
    md.append("---")
    md.append('type: "Chronicle Investigation"')
    md.append(f'title: "Investigation Report: {inv_id}"')
    md.append(
        f'description: "Chronicle SecOps SIEM harvested investigation {inv_id} (Verdict: {verdict}, Status: {status})"'
    )
    md.append(
        f"timestamp: \"{updated_time if updated_time != 'N/A' else created_time}\""
    )
    md.append("provenance:")
    md.append('  source_type: "api_response"')
    md.append('  source_tool: "harvest_investigations"')
    md.append(f"  timestamp: \"{datetime.utcnow().isoformat() + 'Z'}\"")
    md.append(f'status: "{status}"')
    md.append(f'verdict: "{verdict}"')
    md.append(f'confidence: "{confidence}"')
    if alerts:
        md.append("alerts:")
        for a in alerts:
            md.append(f'  - "{a}"')
    else:
        md.append("alerts: []")
    if cases:
        md.append("cases:")
        for c in cases:
            md.append(f'  - "{c}"')
    else:
        md.append("cases: []")
    md.append("---")
    md.append("")
    md.append(f"# Investigation Report: {inv_id}")
    md.append("")

    mermaid_diagram = generate_mermaid_sequence_diagram(steps)
    if mermaid_diagram:
        md.append(mermaid_diagram)

    if alerts_data:
        md.append("## Alert Source Details")
        md.append("")
        for alert_id, alert_info in alerts_data.items():
            detection = alert_info.get("detection", [{}])[0]
            rule_name = detection.get("ruleName", "Unknown Rule")
            rule_desc = detection.get("description", "No description.")
            severity = detection.get("severity", "UNKNOWN")

            md.append(f"### Alert: `{alert_id}` ({rule_name})")
            md.append(f"- **Severity**: `{severity}`")
            md.append(f"- **Rule Description**: {rule_desc}")

            labels = detection.get("ruleLabels", [])
            mitre_tags = []
            for lbl in labels:
                if lbl.get("key") in ["tactic", "technique"]:
                    mitre_tags.append(f"`{lbl.get('key')}:{lbl.get('value')}`")
            if mitre_tags:
                md.append(f"- **MITRE ATT&CK**: {', '.join(mitre_tags)}")
            md.append("")

    if entities_data:
        md.append("## Involved Entities & Threat Intel")
        md.append("")
        md.append(
            "| Entity Type | Entity Value | Summary & Threat Intelligence / Identity Context |"
        )
        md.append("| --- | --- | --- |")
        for ent_val, ent_info in entities_data.items():
            ent_type = ent_info.get("type")
            enrich = ent_info.get("enrichment")

            summary_str = "No enrichment data available."
            if enrich:
                if ent_type == "HASH":
                    label = enrich.get(
                        "suggested_threat_label", "Unknown malware family"
                    )
                    severity = enrich.get("threat_severity", {}).get(
                        "threat_severity_level", "UNKNOWN"
                    )
                    stats = enrich.get("last_analysis_stats", {})
                    mal = stats.get("malicious", 0)
                    tot = mal + stats.get("undetected", 0) + stats.get("harmless", 0)
                    summary_str = f"**VT Severity**: `{severity}` | **Label**: `{label}` | **Votes**: `{mal}/{tot} malicious`"
                elif ent_type == "IP":
                    owner = enrich.get("as_owner", "Unknown ASN")
                    country = enrich.get("country", "Unknown")
                    stats = enrich.get("last_analysis_stats", {})
                    mal = stats.get("malicious", 0)
                    summary_str = f"**VT Country**: {country} | **ASN Owner**: {owner} | **Votes**: `{mal} malicious`"
                elif ent_type == "DOMAIN":
                    registrar = enrich.get("registrar", "Unknown")
                    stats = enrich.get("last_analysis_stats", {})
                    mal = stats.get("malicious", 0)
                    summary_str = (
                        f"**VT Registrar**: {registrar} | **Votes**: `{mal} malicious`"
                    )
                elif ent_type == "USER":
                    display_name = enrich.get("user", {}).get(
                        "userDisplayName", ent_val
                    )
                    email = enrich.get("user", {}).get("emailAddresses", [""])[0]
                    sid = enrich.get("user", {}).get("windowsSid", "N/A")
                    summary_str = (
                        f"**Identity**: {display_name} ({email}) | **SID**: `{sid}`"
                    )
                elif ent_type == "HOST":
                    summary_str = "Host active in SIEM logs. (Identity details retrieved from Chronicle)"

            md.append(f"| `{ent_type}` | `{ent_val}` | {summary_str} |")
        md.append("")

    md.append("## Executive Summary")
    md.append("")
    md.append(summary)
    md.append("")

    md.append("## Investigation Steps")
    md.append("")
    if not steps:
        md.append("*No steps were recorded for this investigation.*")
    else:
        for idx, step in enumerate(steps, 1):
            analysis_summary = step.get("analysisSummary", "No summary.")
            description = step.get("description", "")
            interval = step.get("executionInterval", {})
            start_time = format_timestamp(interval.get("startTime"))
            end_time = format_timestamp(interval.get("endTime"))

            md.append(f"### Step {idx}: {analysis_summary}")
            md.append("")
            if start_time != "N/A" or end_time != "N/A":
                md.append(f"*Execution Window: {start_time} to {end_time}*")
                md.append("")

            if description:
                md.append(description)
                md.append("")

            source_metadata = step.get("sourceMetadata", {})
            source_type = source_metadata.get("sourceType", "")

            if source_type == "SOURCE_TYPE_SEARCH":
                query_info = source_metadata.get("query", {})
                query_code = query_info.get("queryCode")
                if query_code:
                    md.append("#### UDM / Search Query")
                    md.append("```yara")
                    md.append(query_code)
                    md.append("```")
                    md.append("")
            elif source_type == "SOURCE_TYPE_PROCESS_TREE":
                pt_info = source_metadata.get("processTree", {})
                pt_text = pt_info.get("processTree")
                if pt_text:
                    md.append("#### Process Tree")
                    md.append("```text")
                    md.append(pt_text.strip())
                    md.append("```")
                    md.append("")
            elif source_type == "SOURCE_TYPE_COMMAND_LINE_ANALYSIS":
                cla_info = source_metadata.get("commandLineAnalysis", {})
                result = cla_info.get("analysisResult")
                if result:
                    md.append("#### Command Line Analysis Details")
                    md.append(result)
                    md.append("")

            md.append("---")
            md.append("")

    return "\n".join(md)


@app.command("investigations")
def harvest(
    target_total: int = typer.Option(
        100, help="Target total number of investigations to harvest."
    ),
):
    os.makedirs(output_dir, exist_ok=True)
    print("Connecting to Chronicle API...")
    creds = get_credentials()

    # List investigations
    list_url = f"https://us-chronicle.googleapis.com/v1alpha/projects/{project_id}/locations/{location}/instances/{instance_id}/investigations"
    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
    }

    # Check already harvested investigations
    existing_ids = set()
    if os.path.exists(output_dir):
        # We only count files that look like investigation UUIDs (length 36, starts with hex, not starting with alert_ or case_)
        for f in os.listdir(output_dir):
            if (
                f.endswith(".json")
                and not f.startswith("alert_")
                and not f.startswith("case_")
                and len(f) == 41
            ):
                existing_ids.add(f[:-5])

    harvested_count = len(existing_ids)
    print(
        f"Already harvested: {harvested_count} investigations. Target total: {target_total}."
    )

    page_token = None
    while harvested_count < target_total:
        print(f"Listing investigations (pageToken: {page_token})...")
        params = {"pageSize": 50}
        if page_token:
            params["pageToken"] = page_token

        response = make_chronicle_request(list_url, headers, params=params)
        if not response or response.status_code != 200:
            print("Error listing investigations. Exiting pagination loop.")
            break

        res_data = response.json()
        investigations = res_data.get("investigations", [])
        print(f"Found {len(investigations)} investigations on this page.")

        if not investigations:
            print("No more investigations available.")
            break

        for inv in investigations:
            if harvested_count >= target_total:
                break

            inv_name = inv.get("name")
            inv_id = inv_name.split("/")[-1]

            # Check if already exists
            json_path = os.path.join(output_dir, f"{inv_id}.json")
            md_path = os.path.join(output_dir, f"{inv_id}.md")
            if os.path.exists(json_path) and os.path.exists(md_path):
                print(f"Investigation {inv_id} already exists. Skipping.")
                continue

            # Fetch full details
            get_url = f"https://us-chronicle.googleapis.com/v1alpha/{inv_name}"
            print(
                f"\n[{harvested_count+1}/{target_total}] Fetching full details for investigation {inv_id}..."
            )
            get_response = make_chronicle_request(get_url, headers)

            if not get_response or get_response.status_code != 200:
                print(f"Failed to fetch {inv_id}.")
                continue

            full_inv = get_response.json()

            # Fetch Alert Info & Extract Entities
            alerts = full_inv.get("alerts", {}).get("ids", [])
            alerts_data = {}
            entities_data = {}

            time_range = full_inv.get("timeRange", {})
            start_time = time_range.get("startTime")
            end_time = time_range.get("endTime")

            for alert_id in alerts:
                alert_url = f"https://us-chronicle.googleapis.com/v1alpha/projects/{project_id}/locations/{location}/instances/{instance_id}/legacy:legacyGetAlert"
                try:
                    alert_resp = make_chronicle_request(
                        alert_url,
                        headers,
                        params={"alertId": alert_id, "includeDetections": "true"},
                    )
                    if alert_resp and alert_resp.status_code == 200:
                        alert_payload = alert_resp.json().get("alert", {})
                        alerts_data[alert_id] = alert_payload

                        # Parse entities from outcomes robustly
                        detections = alert_payload.get("detection", [])
                        for det in detections:
                            outcomes = det.get("outcomes", [])
                            for out in outcomes:
                                key = out.get("key", "")
                                val = out.get("value", "")
                                if not val:
                                    continue

                                key_lower = key.lower()
                                # 1. User
                                if (
                                    key_lower in ["adversary_uid", "target_user_userid"]
                                    or key_lower.endswith("_userid")
                                    or key_lower.endswith("_username")
                                ):
                                    if val and not any(
                                        c in val for c in [" ", "\\", "/"]
                                    ):
                                        entities_data[val] = {"type": "USER"}
                                # 2. Host
                                elif key_lower in [
                                    "victim_name",
                                    "principal_hostname",
                                    "target_hostname",
                                ] or key_lower.endswith("_hostname"):
                                    if val and not any(
                                        c in val for c in [" ", "\\", "/"]
                                    ):
                                        entities_data[val] = {"type": "HOST"}
                                # 3. Hash
                                elif (
                                    key_lower.endswith("_sha256")
                                    or key_lower.endswith("_md5")
                                    or key_lower in ["sha256", "md5"]
                                ):
                                    if (
                                        val
                                        and len(val) in [32, 64]
                                        and not any(c in val for c in [" ", "\\", "/"])
                                    ):
                                        entities_data[val] = {"type": "HASH"}
                                # 4. IP
                                elif (
                                    key_lower.endswith("_ip")
                                    or key_lower == "victim_netid"
                                    or key_lower == "ip"
                                ):
                                    clean_val = val.strip(", ")
                                    if clean_val and not any(
                                        c in clean_val for c in [" ", "\\", "/"]
                                    ):
                                        entities_data[clean_val] = {"type": "IP"}
                                # 5. File Path / File Name
                                elif (
                                    key_lower.endswith("_full_path")
                                    or key_lower.endswith("_path")
                                    or key_lower == "file_path"
                                    or key_lower.endswith("_file_name")
                                ):
                                    fname = val.replace("\\", "/").split("/")[-1]
                                    if (
                                        fname
                                        and "." in fname
                                        and not any(c in fname for c in [" ", '"', "'"])
                                    ):
                                        entities_data[fname] = {"type": "FILE"}

                        # Parse entities from UDM references
                        col_elements = alert_payload.get("collectionElements", [])
                        for elem in col_elements:
                            refs = elem.get("references", [])
                            for ref in refs:
                                evt = ref.get("event", {})

                                # Check principal
                                pr = evt.get("principal", {})
                                if pr.get("hostname"):
                                    entities_data[pr.get("hostname")] = {"type": "HOST"}
                                if pr.get("ip"):
                                    for raw_ip in pr.get("ip"):
                                        clean_ip = raw_ip.strip(", ")
                                        if clean_ip and not any(
                                            c in clean_ip for c in [" ", "\\", "/"]
                                        ):
                                            entities_data[clean_ip] = {"type": "IP"}
                                if pr.get("user", {}).get("userid"):
                                    entities_data[pr.get("user", {}).get("userid")] = {
                                        "type": "USER"
                                    }

                                # Check target
                                tg = evt.get("target", {})
                                if tg.get("hostname"):
                                    entities_data[tg.get("hostname")] = {"type": "HOST"}
                                if tg.get("ip"):
                                    for raw_ip in tg.get("ip"):
                                        clean_ip = raw_ip.strip(", ")
                                        if clean_ip and not any(
                                            c in clean_ip for c in [" ", "\\", "/"]
                                        ):
                                            entities_data[clean_ip] = {"type": "IP"}
                                if tg.get("user", {}).get("userid"):
                                    entities_data[tg.get("user", {}).get("userid")] = {
                                        "type": "USER"
                                    }
                                if tg.get("file", {}).get("sha256"):
                                    entities_data[tg.get("file", {}).get("sha256")] = {
                                        "type": "HASH"
                                    }
                                if tg.get("file", {}).get("md5"):
                                    entities_data[tg.get("file", {}).get("md5")] = {
                                        "type": "HASH"
                                    }
                                if tg.get("process", {}).get("file", {}).get("sha256"):
                                    entities_data[
                                        tg.get("process", {})
                                        .get("file", {})
                                        .get("sha256")
                                    ] = {"type": "HASH"}
                except Exception as e:
                    print(f"Error retrieving alert data for {alert_id}: {e}")

            # Enrich Entities
            print(
                f"Extracted {len(entities_data)} entities for {inv_id}. Enriched information collection..."
            )
            for ent_val, ent_info in list(entities_data.items()):
                ent_type = ent_info["type"]

                enrich = None
                if ent_type == "HASH":
                    enrich = get_vt_file_report(ent_val)
                elif ent_type == "IP":
                    enrich = get_vt_ip_report(ent_val)
                elif ent_type == "DOMAIN":
                    enrich = get_vt_domain_report(ent_val)
                elif ent_type == "USER":
                    enrich = get_chronicle_entity_summary(
                        creds, "USER", ent_val, start_time, end_time
                    )
                elif ent_type == "HOST":
                    enrich = get_chronicle_entity_summary(
                        creds, "HOST", ent_val, start_time, end_time
                    )

                if enrich:
                    entities_data[ent_val]["enrichment"] = enrich

            # Save JSON
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(full_inv, f, indent=2)

            # Save Markdown with full enrichment details
            md_content = generate_markdown(full_inv, alerts_data, entities_data)
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md_content)

            print(f"Successfully harvested and enriched {inv_id}.")
            harvested_count += 1

        page_token = res_data.get("nextPageToken")
        if not page_token:
            print(
                "No next page token. All available investigations have been processed."
            )
            break

    print(
        f"\nHarvest complete! Total investigations: {harvested_count} under {output_dir}"
    )


def generate_alert_markdown(alert, associated_case_id=None):
    alert_id = alert.get("responsePlatformInfo", {}).get("alertId", "Unknown ID")
    feedback = alert.get("feedbackSummary", {})
    severity = feedback.get("severityDisplay", "Unknown")
    status = feedback.get("status", "Unknown")
    det_time = alert.get("detectionTime", "Unknown")
    case_name = alert.get("caseName", "None")

    # Extract details from detection list
    rule_name = "Unknown Rule"
    rule_id = "Unknown ID"
    description = "No description."
    tags = alert.get("tags", [])

    detections = alert.get("detection", [])
    if detections:
        detection = detections[0]
        rule_name = detection.get("ruleName", rule_name)
        rule_id = detection.get("ruleId", rule_id)
        description = detection.get("description", description)

    md = []
    md.append("---")
    md.append('type: "Chronicle Alert"')
    md.append(f'title: "Alert: {rule_name}"')
    md.append(
        f'description: "Chronicle SecOps SIEM harvested alert for rule {rule_name} (Severity: {severity}, Status: {status})"'
    )
    md.append(f'timestamp: "{det_time}"')
    md.append("provenance:")
    md.append('  source_type: "api_response"')
    md.append('  source_tool: "harvest_investigations"')
    md.append(f"  timestamp: \"{datetime.utcnow().isoformat() + 'Z'}\"")
    md.append(f'alert_id: "{alert_id}"')
    md.append(f'rule_name: "{rule_name}"')
    md.append(f'severity: "{severity}"')
    md.append(f'status: "{status}"')
    md.append(f'case_name: "{case_name}"')
    md.append("---")
    md.append("")
    md.append(f"# Alert: {rule_name}")
    md.append("")
    md.append(f"* **Alert ID**: `{alert_id}`")
    md.append(f"* **Rule ID**: `{rule_id}`")
    md.append(f"* **Severity**: `{severity}`")
    md.append(f"* **Status**: `{status}`")
    md.append(f"* **Detection Time**: `{det_time}`")
    md.append(f"* **Associated Case**: `{case_name}`")
    if associated_case_id:
        md.append(
            f"* **Associated SOAR Case**: [Case {associated_case_id}](file://{output_dir}/case_{associated_case_id}.md)"
        )
    md.append("")
    md.append("## Description")
    md.append(description)
    md.append("")
    if tags:
        md.append("## MITRE ATT&CK Tactics & Techniques")
        for t in tags:
            md.append(f"- `{t}`")
        md.append("")

    return "\n".join(md)


def generate_case_markdown(case):
    case_name = case.get("name")
    case_id = case_name.split("/")[-1]
    display_name = case.get("displayName", "Unknown Case")
    priority = case.get("priority", "UNKNOWN")
    status = case.get("status", "UNKNOWN")
    stage = case.get("stage", "UNKNOWN")
    assignee = case.get("assignee", "None")
    env = case.get("environment", "Default")
    alert_count = case.get("alertCount", 0)

    create_time_ms = case.get("createTime")
    create_time_str = "Unknown"
    if create_time_ms:
        try:
            dt = datetime.fromtimestamp(int(create_time_ms) / 1000, tz=UTC)
            create_time_str = dt.isoformat()
        except Exception:
            create_time_str = "Unknown"

    md = []
    md.append("---")
    md.append('type: "SOAR Case"')
    md.append(f'title: "SOAR Case: {display_name}"')
    md.append(
        f'description: "Chronicle SOAR harvested case {case_id} (Priority: {priority}, Status: {status})"'
    )
    md.append(f'timestamp: "{create_time_str}"')
    md.append("provenance:")
    md.append('  source_type: "api_response"')
    md.append('  source_tool: "harvest_investigations"')
    md.append(f"  timestamp: \"{datetime.utcnow().isoformat() + 'Z'}\"")
    md.append(f'case_id: "{case_id}"')
    md.append(f'priority: "{priority}"')
    md.append(f'status: "{status}"')
    md.append(f'assignee: "{assignee}"')
    md.append("---")
    md.append("")
    md.append(f"# SOAR Case: {display_name}")
    md.append("")
    md.append(f"* **Case ID**: `{case_id}`")
    md.append(f"* **Priority**: `{priority}`")
    md.append(f"* **Status**: `{status}`")
    md.append(f"* **Stage**: `{stage}`")
    md.append(f"* **Assignee**: `{assignee}`")
    md.append(f"* **Environment**: `{env}`")
    md.append(f"* **Created Time**: `{create_time_str}`")
    md.append("")
    md.append("## Details")
    md.append(f"This case was created from {alert_count} associated alert(s).")
    md.append("")
    return "\n".join(md)


def extract_uuid(aid):
    if not aid:
        return ""
    match = re.search(
        r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}",
        aid,
    )
    if match:
        return match.group(0).lower()
    return aid.lower()


def generate_rich_case_markdown(case, alerts, output_dir):
    case_name = case.get("name")
    case_id = case_name.split("/")[-1]
    display_name = case.get("displayName", "Unknown Case")
    priority = case.get("priority", "UNKNOWN")
    status = case.get("status", "UNKNOWN")
    stage = case.get("stage", "UNKNOWN")
    assignee = case.get("assignee", "None")
    env = case.get("environment", "Default")

    create_time_ms = case.get("createTime")
    create_time_str = "Unknown"
    if create_time_ms:
        try:
            dt = datetime.fromtimestamp(int(create_time_ms) / 1000, tz=UTC)
            create_time_str = dt.isoformat()
        except Exception:
            create_time_str = "Unknown"

    md = []
    md.append("---")
    md.append('type: "SOAR Case"')
    md.append(f'title: "SOAR Case: {display_name}"')
    md.append(
        f'description: "Chronicle SOAR harvested case {case_id} (Priority: {priority}, Status: {status}) with {len(alerts)} enriched alerts"'
    )
    md.append(f'timestamp: "{create_time_str}"')
    md.append("provenance:")
    md.append('  source_type: "api_response"')
    md.append('  source_tool: "harvest_investigations"')
    md.append(f"  timestamp: \"{datetime.utcnow().isoformat() + 'Z'}\"")
    md.append(f'case_id: "{case_id}"')
    md.append(f'priority: "{priority}"')
    md.append(f'status: "{status}"')
    md.append(f'assignee: "{assignee}"')
    md.append("---")
    md.append("")
    md.append(f"# SOAR Case: {display_name}")
    md.append("")
    md.append(f"* **Case ID**: `{case_id}`")
    md.append(f"* **Priority**: `{priority}`")
    md.append(f"* **Status**: `{status}`")
    md.append(f"* **Stage**: `{stage}`")
    md.append(f"* **Assignee**: `{assignee}`")
    md.append(f"* **Environment**: `{env}`")
    md.append(f"* **Created Time**: `{create_time_str}`")
    md.append("")

    md.append("## Associated Detections (Alerts)")
    if not alerts:
        md.append("No associated alerts found.")
    else:
        for alert in alerts:
            raw_aid = alert.get("responsePlatformInfo", {}).get("alertId") or alert.get(
                "id"
            )
            clean_aid = slugify_id(raw_aid)

            # Extract rule details
            rule_name = "Unknown Rule"
            rule_id = "Unknown ID"
            detections = alert.get("detection", [])
            if detections:
                detection = detections[0]
                rule_name = detection.get("ruleName", rule_name)
                rule_id = detection.get("ruleId", rule_id)

            feedback = alert.get("feedbackSummary", {})
            severity = feedback.get("severityDisplay", "Unknown")
            status = feedback.get("status", "Unknown")
            det_time = alert.get("detectionTime", "Unknown")

            md.append(f"### [{rule_name}](alert_{clean_aid}.md)")
            md.append(f"* **Alert ID**: `{raw_aid}`")
            md.append(f"* **Severity**: `{severity}`")
            md.append(f"* **Status**: `{status}`")
            md.append(f"* **Detection Time**: `{det_time}`")
            md.append("")

            # Extract entities
            entities = {}
            for det in detections:
                for field in det.get("detectionFields", []):
                    key = field.get("key")
                    val = field.get("value")
                    if key and val:
                        entities.setdefault(key, []).append(val)

            if entities:
                md.append("#### Involved Entities:")
                for k, vals in entities.items():
                    unique_vals = ", ".join(sorted(set(vals)))
                    md.append(f"- **{k.capitalize()}**: `{unique_vals}`")
                md.append("")

    # Direct Investigation linking:
    associated_invs = {}
    try:
        # Get list of alert UUIDs
        alert_uuids = set()
        for alert in alerts:
            raw_aid = alert.get("responsePlatformInfo", {}).get("alertId") or alert.get(
                "id"
            )
            if raw_aid:
                alert_uuids.add(extract_uuid(raw_aid))

        if alert_uuids:
            inv_files = glob.glob(os.path.join(output_dir, "*.json"))
            for inf in inv_files:
                filename = os.path.basename(inf)
                if (
                    filename.startswith("alert_")
                    or filename.startswith("case_")
                    or filename in ["knowledge_graph.json"]
                ):
                    continue
                with open(inf) as f:
                    inv = json.load(f)
                inv_id = inv.get("name", "").split("/")[-1]
                alerts_data = inv.get("alerts", {})
                if isinstance(alerts_data, dict):
                    for aid in alerts_data.get("ids", []):
                        if extract_uuid(aid) in alert_uuids:
                            associated_invs[inv_id] = {
                                "id": inv_id,
                                "displayName": inv.get(
                                    "displayName", "Unknown Investigation"
                                ),
                                "verdict": inv.get("verdict", "UNKNOWN"),
                                "confidence": inv.get("confidence", "N/A"),
                                "summary": inv.get("summary", ""),
                            }
    except Exception as e:
        # Keep whatever associations were matched before the failure; a silent
        # reset made reports claim "No associated investigations found" even
        # when links existed.
        print(
            f"WARNING: Association lookup aborted early ({e}); report may be incomplete."
        )

    md.append("## Associated SIEM Investigations")
    if not associated_invs:
        md.append("No associated security investigations found.")
    else:
        for inv_id, inv in associated_invs.items():
            summary_sentence = inv["summary"].split("\n")[0]
            summary_sentence = summary_sentence.strip("*").strip()
            md.append(f"### [{inv['displayName']}]({inv_id}.md)")
            md.append(f"* **Investigation ID**: `{inv_id}`")
            md.append(f"* **Verdict**: `{inv['verdict']}`")
            md.append(f"* **Confidence**: `{inv['confidence']}`")
            md.append(f"* **Summary**: {summary_sentence}")
            md.append("")

    return "\n".join(md)


def slugify_id(alert_id):
    clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", alert_id)
    return clean


def normalize_alert_id(aid):
    if not aid:
        return ""
    return re.sub(r"[^a-zA-Z0-9]", "", aid).lower()


@app.command("detections")
def harvest_detections(
    days_back: int = typer.Option(7, help="How many days back to look for alerts."),
    max_alerts: int = typer.Option(100, help="Maximum number of alerts to harvest."),
    end_date: str = typer.Option(
        None, help="End date in YYYY-MM-DD format (defaults to current time)."
    ),
    query: str = typer.Option(
        'feedback_summary.status != "CLOSED"',
        help="UDM snapshot query to filter alerts, or 'soar_cases' to auto-query alerts from active SOAR cases.",
    ),
):
    os.makedirs(output_dir, exist_ok=True)
    print("Connecting to Chronicle...")
    creds = get_credentials()
    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
    }

    # 1. Fetch SOAR cases to build alert-to-case mapping
    print("Listing SOAR cases to map alerts...")
    url_cases = f"https://us-chronicle.googleapis.com/v1beta/projects/{project_id}/locations/{location}/instances/{instance_id}/cases"
    params = {"pageSize": 100}
    alert_to_case = {}
    case_times = []
    try:
        res_cases = requests.get(url_cases, headers=headers, params=params, timeout=15)
        if res_cases.status_code == 200:
            cases_list = res_cases.json().get("cases", [])
            for case in cases_list:
                case_name = case.get("name")
                case_id = case_name.split("/")[-1]
                ctime_ms = case.get("createTime")
                if ctime_ms:
                    case_times.append(int(ctime_ms))
                url_alerts = f"{url_cases}/{case_id}/caseAlerts"
                res_alerts = requests.get(url_alerts, headers=headers, timeout=15)
                if res_alerts.status_code == 200:
                    case_alerts = res_alerts.json().get("caseAlerts", [])
                    for ca in case_alerts:
                        siem_id = ca.get("siemAlertId")
                        ticket_id = ca.get("ticketId")
                        if siem_id:
                            alert_to_case[normalize_alert_id(siem_id)] = case
                        if ticket_id:
                            alert_to_case[normalize_alert_id(ticket_id)] = case
        print(f"Mapped {len(alert_to_case)} alert IDs to active SOAR cases.")
    except Exception as e:
        print(f"Warning: Failed to fetch SOAR case mappings: {e}")

    print("Initializing SecOpsClient for detections...")
    client = SecOpsClient(service_account_path=sa_path)
    chronicle = client.chronicle(
        customer_id=instance_id, project_id=project_id, region=location
    )

    if query == "soar_cases":
        if not alert_to_case:
            print("No SOAR cases found to query.")
            return

        unique_uuids = set()
        for raw_id in alert_to_case.keys():
            s_id = raw_id
            if s_id.startswith("de"):
                s_id = s_id[2:]
            # Match 32 character hex UUID
            uuid_match = re.search(
                r"[a-f0-9]{8}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{12}", s_id
            )
            if uuid_match:
                u = uuid_match.group(0)
                formatted_uuid = f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}"
                unique_uuids.add(f"de_{formatted_uuid}")

        if not unique_uuids:
            print("No valid UUIDs extracted from SOAR cases.")
            return

        query_to_use = " OR ".join([f'id = "{aid}"' for aid in unique_uuids])

        if case_times:
            min_time = datetime.fromtimestamp(
                min(case_times) / 1000, tz=UTC
            ) - timedelta(days=5)
            max_time = datetime.fromtimestamp(
                max(case_times) / 1000, tz=UTC
            ) + timedelta(days=5)
        else:
            max_time = datetime.now(UTC)
            min_time = max_time - timedelta(days=days_back)

        start_time = min_time
        end_time = max_time
    else:
        query_to_use = query
        if end_date:
            try:
                end_time = datetime.strptime(end_date, "%Y-%m-%d").replace(tzinfo=UTC)
            except ValueError:
                print("Error: end-date must be in YYYY-MM-DD format.")
                return
        else:
            end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=days_back)

    print(
        f"Fetching alerting detections from {start_time.isoformat()} to {end_time.isoformat()} with query: '{query_to_use}' (max: {max_alerts})..."
    )
    alert_response = chronicle.get_alerts(
        start_time=start_time,
        end_time=end_time,
        snapshot_query=query_to_use,
        max_alerts=max_alerts,
    )

    if not isinstance(alert_response, dict):
        print(
            f"Failed to fetch alerts: unexpected response format: {type(alert_response)}"
        )
        return

    alerts = alert_response.get("alerts", {}).get("alerts", [])
    print(f"Found {len(alerts)} alerts matching criteria.")

    harvested_count = 0
    case_to_alerts_map = {}
    for alert in alerts:
        alert_id = alert.get("responsePlatformInfo", {}).get("alertId")
        if not alert_id:
            alert_id = alert.get("id")
        if not alert_id:
            continue

        clean_id = slugify_id(alert_id)
        json_path = os.path.join(output_dir, f"alert_{clean_id}.json")
        md_path = os.path.join(output_dir, f"alert_{clean_id}.md")

        # Check if alert has an associated SOAR case
        associated_case = alert_to_case.get(normalize_alert_id(alert_id))
        associated_case_id = None
        if associated_case:
            associated_case_id = associated_case.get("name").split("/")[-1]
            case_to_alerts_map.setdefault(associated_case_id, []).append(alert)
            alert["associatedCaseId"] = associated_case_id

        # Save JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(alert, f, indent=2)

        # Save Markdown
        md_content = generate_alert_markdown(
            alert, associated_case_id=associated_case_id
        )
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        print(f"Successfully harvested alert: {clean_id}")
        harvested_count += 1

    # Generate and update all case reports with rich metadata, alerts, and investigations
    unique_cases = {}
    for case in alert_to_case.values():
        cid = case.get("name").split("/")[-1]
        unique_cases[cid] = case

    for cid, case in unique_cases.items():
        case_json_path = os.path.join(output_dir, f"case_{cid}.json")
        case_md_path = os.path.join(output_dir, f"case_{cid}.md")

        # Save Case JSON
        with open(case_json_path, "w", encoding="utf-8") as f:
            json.dump(case, f, indent=2)

        # Generate rich Case Markdown
        case_alerts = case_to_alerts_map.get(cid, [])
        rich_md = generate_rich_case_markdown(case, case_alerts, output_dir)
        with open(case_md_path, "w", encoding="utf-8") as f:
            f.write(rich_md)

        print(f"Successfully harvested and updated SOAR case report: {cid}")

    print(
        f"\nAlert and SOAR case harvest complete! Total alerts: {harvested_count} saved to {output_dir}"
    )


if __name__ == "__main__":
    app()
