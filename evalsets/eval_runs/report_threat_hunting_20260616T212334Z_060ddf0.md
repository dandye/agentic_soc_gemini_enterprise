---
type: "Evaluation Report"
title: "Evaluation Report: Proactive Threat Hunting Workflows"
description: "Systematic prompt evaluation scorecard for Proactive Threat Hunting Workflows on commit 060ddf0"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_threat_hunting_20260616T212334Z_060ddf0.md"
timestamp: "2026-06-16T21:23:34.178606Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T21:23:34.178619Z"
---
# Evaluation Report: Proactive Threat Hunting Workflows

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** Proactive Threat Hunting Workflows
* **Overall Score:** **69.0%**
* **Status:** FAIL

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
| [WARNING] | **Hunt - C2 Network Beaconing** | 71.4% | `retrieve_agentic_soc_runbooks`, `get_domain_report`, `search_security_events`, `get_file_report`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `get_security_alerts`, `search_security_rules`, `search_security_events`, `get_rule_detections`, `get_ip_address_report`, `search_security_events`, `get_reference_list`, `save_report_artifact` | tool_trajectory, keyword_matching, tool_name_mentioned, queries_siem_telemetry, provides_impact_assessment |
| [WARNING] | **Hunt - AD Lateral Movement** | 66.7% | `retrieve_agentic_soc_runbooks`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `get_security_alerts`, `get_security_alerts`, `search_security_events`, `search_security_events`, `search_security_events` | tool_trajectory, keyword_matching, traverses_knowledge_graph, identifies_pivoting_accounts |

---

## Detailed Case Runs

### Case 1: Hunt - C2 Network Beaconing (hunt_c2_beaconing)

* **User Query:** "Perform a threat hunt to identify if any internal workstation in our environment has established active network connections or beaconing to the malicious domain 'superstarts.top'."
* **Score:** **71.4%**

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `get_domain_report`
* Called tool: `search_security_events`
* Called tool: `get_file_report`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `get_security_alerts`
* Called tool: `search_security_rules`
* Called tool: `search_security_events`
* Called tool: `get_rule_detections`
* Called tool: `get_ip_address_report`
* Called tool: `search_security_events`
* Called tool: `get_reference_list`
* Called tool: `save_report_artifact`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [X] **tool_trajectory**
* [X] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **tool_name_mentioned**
* [X] **queries_siem_telemetry**
* [X] **provides_impact_assessment**

#### Model Final Response
```markdown
I have completed a thorough threat hunt to investigate potential active network connections or beaconing behavior to the malicious domain `superstarts.top` in our environment.

Below is a detailed breakdown of the tools used, the exact UDM queries, my threat analysis, and containment recommendations.

The finalized technical report has been formally documented and saved as an artifact. You can access the complete report here:
👉 **[superstarts_top_workstation_beaconing_hunt_report.md](https://storage.cloud.google.com/secops-demo-env-adk-artifacts-20260318/2164796008335147008/eval_user/7790216148250787840/superstarts_top_workstation_beaconing_hunt_report.md/0)**

---

### 1. Threat Intelligence Context & Pivoting (GTI Tools)
I initiated the investigation by calling `get_domain_report` for `superstarts.top` to establish reputational context and resolve any associated C2 infrastructure.
* **Reputation Score:** `-57` (Highly Malicious).
* **Malware Associations:** Identified as a known Command-and-Control (C2) node associated with **Gozi / Ursnif (ldr4 variant)**.
* **Infrastructure IP Pivoting:** The domain historically resolved to IPs `31.41.44.27` and `62.173.149.9` (RU Registrar).

---

### 2. Telemetry Lookback & Scoping (SIEM Tools)
I performed lookback queries in our Chronicle SIEM over a **168-hour lookback window (7 days)** using `search_security_events` to locate any internal traffic to these IOCs.

#### UDM Query 1 (DNS and Domain Lookups):
```udm
domain = "superstarts.top" OR ip = "31.41.44.27" OR ip = "62.173.149.9"
```
* **Analysis & Findings:** This query returned **54 network DNS events** originating entirely from a single internal asset: **`malwaretest-win`** (logged as `malwareTest-win10` in Sysmon logs, native IP `192.168.30.20`, NAT IP `50.90.32.142`).
* **Telescopic Beaconing Pattern:** I analyzed the timestamps of the DNS requests and discovered a highly structured, automated **exact 6-minute (360-second) beaconing interval** querying `superstarts.top` (e.g., `16:21`, `16:27`, `16:33`, `16:39`, `16:45`, `16:51`, `16:57` UTC).
* **DNS Resolution Status:** The DNS query returned `9003` (NXDOMAIN), indicating the malicious domain is currently offline or sinkholed, but the host process is persistently attempting connection.

#### UDM Query 2 (Network Connection Scoping):
To understand if other workstations were compromised, I searched for direct enterprise-wide connections to verified Ursnif C2 IPs linked to the domain. I also checked direct connections to Russian IP **`193.106.191.163`** (MTS PJSC, Moscow) which had triggered SIEM alarms.
```udm
ip = "193.106.191.163"
```
* **Analysis & Findings:** This query returned **22 events**, all of which were successful TCP outbound connection closes and connects on **Port 80 (HTTP)** originating from the **same compromised host (`malwaretest-win`)**. No other internal assets were observed contacting this IP, successfully scoping the threat to this single system.

---

### 3. Endpoint Compromise & Process Chain Analysis
I pivoted to investigate the file hash `7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2` utilizing `get_file_report` and reviewed the Sysmon/Falcon event logs.

* **Renamed LOLBIN Execution:** The compromised workstation executed a copy of Microsoft's legitimate `rundll32.exe` utility renamed to **`123.com`** (Process ID `4016`) from a mounted virtual drive/CD-ROM directory (`E:\me\123.com`).
* **The Process Tree & Payload:**
  * **Parent Process:** `wscript.exe` (PID `6212`) executing `"C:\Windows\System32\WScript.exe" "E:\me\canWell.js" hello cexe lldnur revreSretsigeRllD`
  * **Attacking Process:** `E:\me\123.com` launching `"me\123.com me/itsIt.db,DllRegisterServer"`
  * **Dynamic DLL Payload:** Renamed file **`me/itsIt.db`** (actually a malicious Ursnif DLL payload loaded into memory using the DLL registration export).

---

### 4. SIEM Rule Validation
I checked our SIEM detections using `get_rule_detections` for rule **`ursnif_malware_dns`** (`ru_99d1f620-3fe2-41d5-918e-0e1bd2402065`).
* **Verification:** The rule correctly triggered and generated high-severity alerts. Detections were correlated back under active **Case ID `8099e181-cd08-40f3-9482-4cf57a43838c`**, showing that the host has been persistently beaconing and establishing active C2 TCP socket sessions over several weeks since late April / May 2026.

---

### 5. Tactical Containment & Remediation Recommendations (Handover to Tier 2 IR)
Since active outbound command-and-control to Russian infrastructure (`193.106.191.163:80`) is verified, immediate containment is required:

1. **EDR Network Isolation:** Isolate the host `malwaretest-win` (Asset ID `CS:7c94109539fc421f8f535faf6eafd3c8`) immediately from the network via Crowdstrike Falcon to stop active C2 sessions.
2. **Perimeter Firewall Blocking:**
   * Block all outbound TCP connections to the Russian IP `193.106.191.163` at perimeter proxy/firewalls.
   * Configure DNS sinkholing for the domains `superstarts.top` and `superlist.top`.
3. **Host-Level Disinfection:**
   * Kill Process ID `4016` (`123.com`) and script engine `6212` (`wscript.exe`).
   * Unmount the suspicious ISO/virtual drive mounted at `E:\`.
   * Quarantine/Delete files: `E:\me\canWell.js`, `E:\me\123.com`, and `E:\me\itsIt.db`.
4. **Credential Sanitation:** Invalidate all active tokens and force an immediate password reset for the affected domain user **`jsmith`**. Audit Active Directory logs for any lateral movement attempts originating from this host during the compromise window.I will formally document my threat hunt findings and containment recommendations in a technical report and save it as a Markdown artifact using the `save_report_artifact` tool. This report is designed for immediate handover to the Tier 2 Incident Responder for tactical containment and remediation.I will retrieve the definition of the reference list `%ursnif_ip_addresses` from Chronicle SIEM to see if it is currently maintained and if the malicious IP address we found (`193.106.191.163`) is included in it, or if it needs to be updated.I will now perform a targeted SIEM search to check if any **other** hosts in our environment have established connections or communicated with the verified Russian C2 IP address `193.106.191.163` in the last 168 hours. This ensures we identify the full extent of the compromise within the enterprise.I have uncovered extremely critical evidence!

The `ursnif_malware_dns` detection history reveals that while DNS resolutions to `superstarts.top` and `superlist.top` occasionally return `9003` (NXDOMAIN), the malware has successfully established active outbound TCP connections to a known Ursnif C2 IP address:

*   **Active Outbound C2 IP:** `193.106.191.163` (MTS PJSC, Russia)
*   **Protocol & Port:** TCP / 80 (HTTP)
*   **Activity Pattern:** Consistent outbound connection attempts occurring at exactly **16:25:20Z** on:
    *   June 15, 2026
    *   June 12, 2026
    *   June 9, 2026
    *   June 6, 2026
    *   June 3, 2026
    *   May 31, 2026
    *   May 30, 2026
    *   May 27, 2026
    *   May 24, 2026
    *   May 21, 2026
    *   May 18, 2026
    *   May 15, 2026
    *   ... (stretching back into April 2026)
*   **Connection Source:** Station `malwaretest-win` (IP `192.168.30.20`, EDR Asset ID `CS:7c94109539fc421f8f535faf6eafd3c8`).
*   **Responsible Process:** `123.com` (Rundll32, PID `4016`) executing the malicious DLL `me/itsIt.db`.

This confirms that the host is **fully compromised** and has had successful command-and-control (C2) sessions with Russian infrastructure on a regular basis for several weeks.

To enrich our analysis of the C2 infrastructure, I will run an IP Address report on `193.106.191.163`.I will retrieve the historical detections generated by the `ursnif_malware_dns` rule (`ru_99d1f620-3fe2-41d5-918e-0e1bd2402065`) to examine what specific events triggered the alert. This will reveal the complete sequence of network connections or other indicators that caused the detection.I will perform a targeted SIEM search to check for outbound network connections (traffic, socket connections, HTTP) to the malicious IP addresses `31.41.44.27` and `62.173.149.9` associated with `superstarts.top`. This will tell us if there has been successful command and control (C2) communication beyond just DNS queries, which is critical for assessing the actual impact of the compromise.I will search for the rule definition of the rule `ursnif_malware_dns` which triggered our high-severity alert. This will help us confirm the exact detection logic that caught this beaconing behavior and determine if any improvements or exclusions are needed.I will query Chronicle SIEM to see if any security alerts have been generated in the past 168 hours (7 days) for this workstation (`malwaretest-win` or `malwareTest-win10`) or for `superstarts.top`. This will help identify if our detection rules have already triggered alerts, or if this threat went completely undetected.I will query the graph to see if the domain `superstarts.top` or any of its associated files (like `123.com` or `canWell.js`) are already tracked in the Neo4j knowledge base.I will list the hostnames currently stored in our Neo4j knowledge graph to verify if `malwaretest-win` is referenced under a slightly different naming convention or unique identifier.I will check the overall structure of our Security Operations Neo4j graph database to understand what labels and entity types are currently mapped, which will guide us in formulating better queries.I will query our local Neo4j graph database to check if there are other associated events, pivot points, user accounts, or active investigations recorded for the hostname `malwaretest-win` or `malwareTest-win10`. This helps correlate our findings with wider operational telemetry and check for other signs of lateral movement or containment details.I have identified highly suspicious, structured beaconing activity coming from the workstation `malwaretest-win` (also referred to as `malwareTest-win10` in Sysmon logs, native IP `50.90.32.142`).

### Observations from Initial SIEM Query:
*   **Target Domain:** `superstarts.top`
*   **Attacker Infrastructure IPs:** `31.41.44.27`, `62.173.149.9` (associated with Gozi / Ursnif malware)
*   **Compromised Asset:** Workstation `malwaretest-win`
*   **Attacking Process:** `123.com` (Process ID `4016`, original filename `RUNDLL32.EXE`, MD5 `d0432468fa4b7f66166c430e1334dbda`, SHA256 `7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2`). It was launched with the command: `me\123.com me/itsIt.db,DllRegisterServer` from a CD-ROM or mounted ISO path (`E:\me\123.com` / `\Device\CdRom1\me\123.com`).
*   **Parent Process:** `wscript.exe` (command line: `"C:\Windows\System32\WScript.exe" "E:\me\canWell.js" hello cexe lldnur revreSretsigeRllD`). This indicates a script-based infection vector (likely a phishing payload launching a JavaScript downloader, which in turn drops/mounts a virtual disk or ISO containing the malware).
*   **Beaconing Pattern:** The compromised host is attempting to resolve `superstarts.top` at **exact 6-minute (360-second) intervals**. This activity was seen persistently on both **June 12, 2026** and **June 15, 2026**, confirming an ongoing persistent beaconing state.
*   **DNS Resolution Status:** The DNS query response code is `9003` (NXDOMAIN), indicating that the C2 server domain is currently offline or blocked at the DNS layer, but the malware on the workstation is still actively beaconing.

To expand our hunt, I will check if there are any active security alerts or investigations in the SIEM associated with this activity or host. I'll also perform a threat intelligence check on the file hash `7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2`. Let's run a file report on the hash.I will now perform a lookback search in our Chronicle SIEM to see if any network traffic, DNS lookups, or other security events involve the malicious domain `superstarts.top` or its resolved IP addresses (`31.41.44.27`, `62.173.149.9`). I'll use a lookback period of 168 hours (7 days) to ensure we capture any beaconing patterns.I will start by researching and enriching our threat intelligence on the domain `superstarts.top` using Google Threat Intelligence (GTI) tools. This will provide key context about the domain's reputation, associated malware families, campaign context, and DNS resolutions.I will begin by retrieving relevant runbooks from our Agentic SOC knowledge base to ensure we follow our standardized methodology for threat hunting on domains, IOCs, and beaconing behaviors.
```

---
### Case 2: Hunt - AD Lateral Movement (hunt_lateral_movement_path)

* **User Query:** "Conduct a proactive hunt to see if there is any evidence of lateral movement using compromised administrator accounts starting from workstation wrk-shasek."
* **Score:** **66.7%**

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `get_security_alerts`
* Called tool: `get_security_alerts`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [X] **tool_trajectory**
* [X] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **traverses_knowledge_graph**
* [X] **identifies_pivoting_accounts**

#### Model Final Response
```markdown
I have found critical evidence in the PowerShell operational logs for `tim.smith` on `wrk-shasek.stackedpads.local` (IP `10.1.0.50`).

On June 15, 2026, at 14:00:44 UTC, the user `tim.smith` (who is listed as an "Intern" in Stacked Pads IT department) executed a highly suspicious PowerShell password-spraying script named **`G:\spray.ps1`**.

The log shows that this script was actively performing an LDAP-based password spray against 13 domain users using the DirectoryServices namespace (`System.DirectoryServices.DirectoryEntry`):
- It cycled through password patterns: **`capital-14`**, **`capital-15`**, **`capital-16`**, **`capital-17`**, and **`capital-18`**.
- It targeted multiple administrative and domain accounts: **`frank.kolzig`**, **`jerry.thompson`**, **`jane.rodgers`**, **`dave.young`**, **`tyler.taylor`**, **`james.ponder`**, **`jack.white`**, **`john.smith`**, **`ryan.lewis`**, **`steve.oneil`**, **`jeff.armstrong`**, and **`jim.johnson`**.

This explains the pivot logon connections seen in our Neo4j graph for `frank.kolzig` and `tim.smith`!

Now, I will search for events involving **`frank.kolzig`** to see if the password spray succeeded for this account, leading to compromised session logons on `wrk-shasek.stackedpads.local` or the Active Directory domain controller `activedir.stackedpads.local`.The SIEM query translated `wrk-shasek` as `hostname = "wrk-shasek"`, but it didn't find any events. This might be because the machine's full domain name is `wrk-shasek.stackedpads.local` or the identifier is stored in alternative UDM fields (like `principal.hostname` or `target.hostname`).

I will broaden my search to hunt for events involving the administrator account `tim.smith` between June 15, 2026 and June 17, 2026, as this account was identified as a key pivot node in our Neo4j graph.I've identified that the alerts in the environment are from June 2026 (around June 16, 2026). I will now perform a targeted SIEM log search using `search_security_events` to retrieve events involving `wrk-shasek` within the timeframe of June 15, 2026 to June 17, 2026. This will reveal the process execution, logon events, and other security telemetry on the workstation.The SIEM returned an error because my lookback period exceeded the maximum allowed duration of 2160 hours (90 days). I will repeat the call with the maximum lookback of 2160 hours to fetch any recent security alerts.I will query Chronicle SIEM directly using `get_security_alerts` with a broad search window to see if there are any active security alerts generated in this environment, which will help us pinpoint the timeframe of any malicious activity.I will query the database to list all Host names present in the knowledge graph so we know what systems exist in this environment.I will run a query to list all user accounts that have logged on to `activedir.stackedpads.local` or any host containing "activedir" in its name. This will help us identify administrative logons to what is likely a Domain Controller.Since `Investigation` nodes seem to be isolated in this database, I will check what types of relationships are present across the other nodes (e.g., `Host`, `User`, `File`, etc.) to understand how they are connected.I will check if `Investigation` nodes have any relationships whatsoever in the database. This will help us confirm if investigations are isolated nodes or if there's a specific pattern for joining them.I will query the database to discover what types of relationships exist between the `Investigation` nodes and other entity types. This will enable me to join investigations to our target host or user accounts.I see there are indeed 258 `Investigation` nodes in our knowledge graph. I'll inspect a few `Investigation` nodes directly to understand their properties and how they are linked to other nodes.I will query the list of node labels and their counts in the database to understand what kind of nodes are present (e.g., `Host`, `User`, `File`, `Alert`, etc.). This will help me structure my queries more accurately.I will now query the graph to see if any of these pivot users (`tim.smith`, `frank.kolzig`, `steve.hasek`) or the target workstations (`wrk-shasek` / `activedir.stackedpads.local`) are linked to active security alerts or investigations. Identifying linked investigations can help establish a historical verdict on the legitimacy of this multi-host access.I will execute a Cypher query on the Neo4j graph to find potential pivot users. These are users who have logged on to multiple hosts, which is a classic indicator of potential lateral movement. We will look for accounts that have logged on to both `wrk-shasek` and other machines in the domain.I will start the investigation by querying our Neo4j Knowledge Graph (`query_neo4j_graph`) to see what entities, users, active cases, and historical alerts are associated with the host `WRK-SHASEK` (case-insensitive or normalized name). This will help us determine if there are any immediate indicators of compromise, linked cases, or lateral movement patterns represented in the graph.I will begin by retrieving any relevant Threat Hunting and Incident Response runbooks to help guide our search for lateral movement using compromised administrative accounts starting from the host `wrk-shasek`. I'll use the `retrieve_agentic_soc_runbooks` tool to search for instructions on how to structure our lateral movement hunts.
```

---
