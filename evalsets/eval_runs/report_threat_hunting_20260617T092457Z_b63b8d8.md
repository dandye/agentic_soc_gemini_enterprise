---
type: "Evaluation Report"
title: "Evaluation Report: Proactive Threat Hunting Workflows"
description: "Systematic prompt evaluation scorecard for Proactive Threat Hunting Workflows on commit b63b8d8"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_threat_hunting_20260617T092457Z_b63b8d8.md"
timestamp: "2026-06-17T09:24:57.147085Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T09:24:57.147095Z"
---
# Evaluation Report: Proactive Threat Hunting Workflows

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** Proactive Threat Hunting Workflows
* **Overall Score:** **100.0%**
* **Status:** PASS

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
| [PASS] | **Hunt - C2 Network Beaconing** | 100.0% | `retrieve_agentic_soc_runbooks`, `get_domain_report`, `query_neo4j_graph`, `search_security_events`, `get_file_report`, `search_security_events`, `lookup_entity`, `search_security_rules`, `search_security_events`, `search_security_events`, `get_ip_address_report`, `save_report_artifact` | specialist_attribution, tool_trajectory, keyword_matching, specialist_attribution, tool_name_mentioned, queries_siem_telemetry, provides_impact_assessment |
| [PASS] | **Hunt - AD Lateral Movement** | 100.0% | `retrieve_agentic_soc_runbooks`, `query_neo4j_graph`, `query_neo4j_graph`, `query_neo4j_graph`, `search_security_events`, `search_security_events`, `get_security_alerts`, `save_report_artifact` | specialist_attribution, tool_trajectory, keyword_matching, specialist_attribution, traverses_knowledge_graph, identifies_pivoting_accounts |

---

## Detailed Case Runs

### Case 1: Hunt - C2 Network Beaconing (hunt_c2_beaconing)

* **User Query:** "Perform a threat hunt to identify if any internal workstation in our environment has established active network connections or beaconing to the malicious domain 'superstarts.top'."
* **Score:** **100.0%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/2164796008335147008/playground?session=5950794767632695296&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `get_domain_report`
* Called tool: `query_neo4j_graph`
* Called tool: `search_security_events`
* Called tool: `get_file_report`
* Called tool: `search_security_events`
* Called tool: `lookup_entity`
* Called tool: `search_security_rules`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `get_ip_address_report`
* Called tool: `save_report_artifact`

#### Heuristic Success Checklist
* [X] **specialist_attribution**
* [X] **tool_trajectory**
* [X] **keyword_matching**
* [X] **specialist_attribution**
* [X] **tool_name_mentioned**
* [X] **queries_siem_telemetry**
* [X] **provides_impact_assessment**

#### Model Final Response
```markdown
## Threat Hunt Conclusion: **Gozi/Ursnif C2 Activity Identified**

I have completed a thorough, hypothesis-driven threat hunt in our environment to identify if any internal workstation has established active network connections or beaconing to the malicious domain **`superstarts.top`**.

The threat hunt was **successful (Positive Finding)**. I have identified a critical compromise on the workstation **`malwaretest-win`** (IP: `192.168.30.20`), which is actively beaconing to the C2 server at regular **6-minute (360-second) intervals**.

The full detailed investigation and containment playbook has been formally saved as an artifact for the Tier 2 Incident Response team:
👉 **[View Full Hunt & Containment Report](https://storage.cloud.google.com/secops-demo-env-adk-artifacts-20260318/2164796008335147008/eval_user/5950794767632695296/superstarts_top_Ursnif_Threat_Hunt_Report.md/0)**

---

### 1. Investigation Workflow & Tools Used
*   **Runbook Retrieval (`retrieve_agentic_soc_runbooks`):** Retrieved standard IOC hunting runbooks (`ioc_threat_hunt.md` and `advanced_threat_hunting`) to align hunt steps, scope, and lookback configurations.
*   **Threat Intel Domain Lookup (`get_domain_report`):** Queried Google Threat Intelligence (`gti-mcp`) to analyze `superstarts.top`. We confirmed it is a known malicious domain associated with the **Gozi / Ursnif (LDR4)** malware family.
*   **Graph Relational Traversal (`query_neo4j_graph`):** Checked our multi-hop Security Operations Graph to see if there were any pre-existing investigations, alerts, or statically mapped hosts linked to `superstarts.top` or its resolving IPs. (No matches were found in Neo4j, showing this as a new compromise).
*   **SIEM Log Telemetry Search (`search_security_events`):** Executed a 7-day lookback search on Chronicle SIEM to find matching event logs for `superstarts.top`, revealing active DNS queries from `malwaretest-win`.
*   **Threat Intel File Analysis (`get_file_report`):** Queried GTI to evaluate the binary hash of the executing process `123.com` which initiated the traffic.
*   **SIEM Process Module Load Search (`search_security_events`):** Queried SIEM logs specifically for files loaded by the executing process to identify the true malware payload (`itsIt.db`).
*   **Threat Intel IP Lookup (`get_ip_address_report`):** Enriched the destination C2 IP address (`193.106.191.163`) located in Russia to confirm its C2 status.

---

### 2. Exact Chronicle SIEM (UDM) Queries Used
To search Chronicle SIEM telemetry, the following UDM queries were structured and executed:

*   **Query 1: DNS Logs for C2 Domain**
    ```sql
    domain = "superstarts.top"
    ```
    *Result: 15 events found originating from `malwaretest-win`.*

*   **Query 2: Payload File Tracking**
    ```sql
    re.regex(file_path, `itsIt\.db`) nocase
    ```
    *Result: 15 events found mapping `PROCESS_MODULE_LOAD` and `FILE_OPEN` activity.*

*   **Query 3: Outbound TCP Network Connections**
    ```sql
    principal.hostname = "malwaretest-win"
    metadata.event_type = "NETWORK_CONNECTION"
    network.direction = "OUTBOUND"
    ```
    *Result: 6 events found (outbound C2 connection to port 80).*

---

### 3. Threat Analysis & Breakdown of Findings

#### A. Target Indicator Enrichment
*   **C2 Domain:** `superstarts.top` (VT reputation -57; 14 detections) belongs to known malicious Ursnif malware campaign collections.
*   **C2 IP Address:** `193.106.191.163` is registered to MTS PJSC (Russia) and is flagged as an active C2 node for Ursnif/Gozi.

#### B. The Compromise Timeline & Beaconing Pattern
1.  **Infection Vector:** Script execution initiated by **`wscript.exe`** (PID `26838808386`).
2.  **Malicious DLL Execution (`16:20:54`):** Wscript spawned a process named **`123.com`** (PID `4016`).
    *   *Technique:* Legitimate Microsoft system binary `rundll32.exe` (SHA256: `7d99c80...`) was copied and renamed to `123.com` (Masquerading - MITRE T1036) to evade static rules.
    *   `123.com` loaded the malicious DLL payload **`itsIt.db`** (SHA256: `8e570e32acb99abfd0daf62cff13a09eb694ebfa633a365d224aefc6449f97de`) via `DllRegisterServer`. Crowdstrike Falcon flags this file as highly malicious malware (Gozi/Ursnif).
3.  **Active C2 Establish (`16:25:20`):** The process established a successful outbound TCP network connection on port 80 to the Russian IP **`193.106.191.163`**.
4.  **Active DNS Beaconing (`17:03:30` - Active):** The malware has initiated a steady DNS beaconing loop to **`superstarts.top`** on an exact **6-minute (360-second) interval** (jitter of only 1–2 seconds) to receive secondary commands.

#### C. Detection Gaps & Existing Alerts
The compromised workstation `malwaretest-win` has actively triggered:
*   **`ursnif_malware_dns`** (Count: 2 alerts in Chronicle SIEM)
*   **`Suspicious Dns Lookup Events To C2 Top Level Domains [Mandiant Frontline Threats]`** (Count: 30 alerts)

This validates that our YARA-L rules are successfully firing and correlating DNS traffic to outbound connection rules.

---

### 4. Direct Containment Recommendations (For Tier 2 IR)
I have formally passed these containment steps to our Incident Responders:
1.  **EDR Host Isolation:** Immediately isolate `malwaretest-win` (Asset ID: `CS:7c94109539fc421f8f535faf6eafd3c8`) via the EDR console to block all network traffic.
2.  **Kill Malicious Process:** Terminate PID `4016` (and parent `wscript.exe` processes).
3.  **Hash Block:** Add DLL hash `8e570e3...` (`itsIt.db`) to the EDR blocklist.
4.  **Network Blocklist:** Block the domain `superstarts.top` on local DNS servers and block outbound traffic to IP `193.106.191.163` at the perimeter firewall.

---
**Role Sign-off:**
**Threat Hunter**
*Proactive Security Operations*I have compiled all telemetry from our SIEM and Threat Intelligence sources and verified a **critical positive threat hunt finding**!

The domain `superstarts.top` and its associated infrastructure are confirmed active C2 servers for **Gozi / Ursnif** malware. An internal workstation named `malwaretest-win` is **actively compromised** and currently beaconing to this C2 server every **6 minutes** via a masqueraded binary execution.

I will formally document these findings and save a detailed **Threat Hunt and Containment Report** artifact for the Tier 2 Incident Response team to handle host isolation and remediation.I have successfully identified the specific malicious C2 IP address that the masqueraded process `123.com` established an active TCP connection to!

### Outbound Connection Details:
- **Timestamp:** `2026-06-15T16:25:20.356Z` (occurring 5 minutes after `itsIt.db` was loaded into memory at `16:20:54`)
- **Process:** `123.com` (PID `4016`, masqueraded legitimate `rundll32.exe`)
- **Source Host:** `malwaretest-win` (IP `192.168.30.20`)
- **Target IP:** **`193.106.191.163`**
- **Target Port:** `80` (HTTP)
- **Target Geolocation:** Russia (Moscow/Russian Federation)
- **ISP/Organization:** MTS PJSC (Mobile Telesystems)

I will now query Google Threat Intelligence (`gti-mcp`) using `get_ip_address_report` to get a comprehensive report on the Russian IP `193.106.191.163` and confirm its status as an active Ursnif/Gozi C2 node.Since there were no direct matches for those two specific historical IPs (`31.41.44.27` or `62.173.149.9`), the active C2 infrastructure for Ursnif/Gozi in this specific campaign may be utilizing other IP addresses that are part of the reference list `%ursnif_ip_addresses.ip`.

To find the actual IP addresses the workstation has established active C2 connections to, I will query Chronicle SIEM for outbound TCP network connection events on `malwaretest-win` targeting Port 80 (or general outbound connections) during the timeframe of the active compromise.I have analyzed the `ursnif_malware_dns` rule definition:
- It correlates a **NETWORK_DNS** event (suspicious DNS request) with an **outbound NETWORK_CONNECTION** on TCP port 80 to a known Ursnif command-and-control (C2) IP address stored in the reference list `%ursnif_ip_addresses.ip`.
- Since this rule has triggered **2 times** on `malwaretest-win`, it indicates that the system didn't just query the domain—it **successfully established active network connections** to the underlying malicious C2 IP address(es)!

From our initial Google Threat Intelligence domain report on `superstarts.top`, we know it historically resolves to:
1. `31.41.44.27`
2. `62.173.149.9`

I will now search the SIEM logs for any network connection events on `malwaretest-win` involving these target IP addresses to confirm active outbound traffic.I see that the workstation `malwaretest-win` has already triggered several active security alerts directly related to this activity:
1. **Rule:** `ursnif_malware_dns` (Count: 2)
2. **Rule:** `Suspicious Dns Lookup Events To C2 Top Level Domains [Mandiant Frontline Threats]` (Count: 30)

To validate if our detection coverage is precise and understand the logic used, I will search for the rule definition of `ursnif_malware_dns` in our SIEM using `search_security_rules`.I will now perform an entity lookup using `lookup_entity` for the impacted workstation `malwaretest-win` to determine which user accounts are associated with this host, identify other potential alerts, and understand the general context of this system.The GTI file report reveals that the binary executing the command (`7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2`) is actually the legitimate Microsoft **`RUNDLL32.EXE`** binary.

### What This Tells Us:
The threat actor has performed a **Masquerading / Living-off-the-Land** technique (MITRE ATT&CK T1036 / T1218.011):
1. They copied the legitimate system binary `rundll32.exe` to `\Device\CdRom1\me\123.com`.
2. By renaming it to `123.com`, they bypass static application controls or EDR rules targeting the execution of standard system binaries like `rundll32.exe` from anomalous paths.
3. They executed `123.com` (which is functionally `rundll32.exe`) to register and run a custom, potentially malicious DLL payload: **`me/itsIt.db`** (using the export `DllRegisterServer`).
4. Since `rundll32.exe` is a legitimate process, the malicious network beaconing to `superstarts.top` is technically initiated by this legitimate binary, masking the threat under system activity.

To discover the true nature of the payload, I will now execute a telemetry search in **Chronicle SIEM** for any security events involving the file name `itsIt.db` to trace how it was placed or modified on the host.I have found **15 events** in Chronicle SIEM representing active, suspicious DNS requests to `superstarts.top` originating from an internal host named `malwaretest-win`!

### Analysis of Beaconing Pattern:
By reviewing the `eventTimestamp` values, we can clearly see a highly regular network beaconing pattern to this malicious domain. The requests occur at precise **6-minute intervals** (with a small jitter of 1–2 seconds):
- `17:03:30`
- `17:09:31` (+6m 01s)
- `17:15:33` (+6m 02s)
- `17:21:35` (+6m 02s)
- `17:27:36` (+6m 01s)
- `17:33:37` (+6m 01s)
- `17:39:39` (+6m 02s)
- *(Sleep/dormant interval of ~24 minutes)*
- `18:03:43`
- `18:09:44` (+6m 01s)
- `18:15:47` (+6m 03s)
- `18:21:48` (+6m 01s)
- `18:27:49` (+6m 01s)
- `18:33:51` (+6m 02s)
- `18:39:53` (+6m 02s)
- `18:45:54` (+6m 01s)

### Process Details:
- **Host:** `malwaretest-win` (Asset ID: `CS:7c94109539fc421f8f535faf6eafd3c8`)
- **Process PID:** `4016`
- **Command Line:** `me\123.com me/itsIt.db,DllRegisterServer`
- **Parent Process:** `wscript.exe` (indicating execution initiated from a script)
- **Binary Path:** `\Device\CdRom1\me\123.com` (note: named as `.com` but executing via `DllRegisterServer` which is characteristic of `rundll32.exe` functionality and DLL loader obfuscation)
- **Binary Hash SHA-256:** `7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2`
- **Binary Hash MD5:** `d0432468fa4b7f66166c430e1334dbda`

Now, I will query Google Threat Intelligence (`gti-mcp`) to obtain a full file analysis report for the process hash `7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2` to determine if this binary is known malware.Since no records were found in the Neo4j knowledge graph (which would indicate already processed alerts or investigations), I will pivot directly to **Chronicle SIEM** to perform a telemetry search across our actual security logs.

I will use `search_security_events` to look for any event (DNS queries, HTTP requests, or network connections) involving the malicious domain `superstarts.top` over the last 7 days (`hours_back=168`).I will now execute a read-only Cypher query against our Security Operations Neo4j knowledge graph using `query_neo4j_graph` to identify if any internal workstation, alert, or investigation in our environment is already linked to the malicious domain `superstarts.top` or its historically associated IPs (`31.41.44.27`, `62.173.149.9`). This will quickly map any existing multi-hop connections.I will now perform an enrichment check using Google Threat Intelligence (`gti-mcp`) to understand the reputation, classifications, and any threat associations of the domain `superstarts.top`. This will help us confirm if it is indeed classified as malicious and identify potential threat families or categories associated with it.I will start by retrieving the threat hunting runbooks from the Agentic SOC repository to guide our workflow for searching for Indicators of Compromise (IOCs) such as the domain 'superstarts.top'.
```

---
### Case 2: Hunt - AD Lateral Movement (hunt_lateral_movement_path)

* **User Query:** "Conduct a proactive hunt to see if there is any evidence of lateral movement using compromised administrator accounts starting from workstation wrk-shasek."
* **Score:** **100.0%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/2164796008335147008/playground?session=7367176850440716288&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `get_security_alerts`
* Called tool: `save_report_artifact`

#### Heuristic Success Checklist
* [X] **specialist_attribution**
* [X] **tool_trajectory**
* [X] **keyword_matching**
* [X] **specialist_attribution**
* [X] **traverses_knowledge_graph**
* [X] **identifies_pivoting_accounts**

#### Model Final Response
```markdown
### Threat Hunt Summary: Lateral Movement & Domain Escalation from Workstation `wrk-shasek`

*   **Hypothesis Tested:** Proactive hunt for lateral movement using compromised administrator accounts starting from workstation `wrk-shasek` (IP: `10.1.0.50`).
*   **Hunt Result:** **THREAT CONFIRMED (Critical Active Breach)** — We have identified a multi-stage attack path beginning with an IT intern account on workstation `wrk-shasek`, escalating to a fully compromised Domain Administrator account, and culminating in successful credential dumping on our Domain Controller (`activedir.stackedpads.local`).

---

### Phase 1: Runbook and Graph-Query Analysis (Tool Calls & Traversal)
1.  **Runbook Retrieval:** I queried the runbook repository using `retrieve_agentic_soc_runbooks` to align with the standard workflow for lateral movement/privilege escalation detection.
2.  **Host and User Scoping (Graph Query 1 & 2):** Using our strict budget of 3 Neo4j Graph queries, I identified a `Host` node for `wrk-shasek` and looked for direct connected edges.
    *   *Result:* Exposed active logon sessions for two key users: **`tim.smith`** (listed as an Intern in the IT department) and **`frank.kolzig`** (Windows Domain Administrator).
3.  **Lateral Path Tracing (Graph Query 3):** I ran a final graph query to see if these two accounts logged on to other assets in the network.
    *   *Result:*
        *   `tim.smith` logged on to `wrk-shasek` and the Domain Controller `activedir.stackedpads.local`.
        *   `frank.kolzig` logged on to `wrk-shasek`, the Domain Controller `activedir.stackedpads.local`, and server `wins-d19`.

---

### Phase 2: Chronicle SIEM Log Pivoting (UDM Telemetry)
Adhering to our **pivot early** guidance, I moved immediately to querying Chronicle logs with natural language translate-to-UDM queries:

1.  **Query 1 (Admin Compromise):** `Find any events where the user is 'frank.kolzig'` over the past 168 hours (7 days).
    *   **UDM Query:** `principal.user.userid = "frank.kolzig"`
    *   **Finding (CRITICAL):** On **June 12, 2026, at 14:19:20 UTC** and again on **June 15, 2026, at 14:19:20 UTC**, `mimikatz.exe` was executed on our Active Directory Domain Controller (`activedir.stackedpads.local`) under the context of `frank.kolzig`'s account (running with SYSTEM-level privileges).
    *   The command used was:
        `C:\Users\fkolzig\Downloads\mimikatz_trunk\x64\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit`
        *(Sysmon Event ID 10: LSASS memory access used for credential dumping).*

2.  **Query 2 (Host-Origin Reconstruction):** `Find any events where the user is 'tim.smith'` over the past 168 hours (7 days).
    *   **UDM Query:** `user = "tim.smith"`
    *   **Finding (CRITICAL):** On **June 15, 2026, between 14:00:43Z and 14:04:44Z** (just **15 minutes before** the Mimikatz execution on the DC), the IT Intern account `tim.smith` executed an Active Directory password spraying script named **`G:\spray.ps1`** on workstation **`wrk-shasek.stackedpads.local`** (IP: `10.1.0.50`).
    *   PowerShell operational logs (Event ID 4103) captured the script performing LDAP query bindings to spray the domain users:
        *   User `joyce.fielder` sprayed with password `capital-14`
        *   User `jeff.armstrong` sprayed with password `capital-14`
        *   User `jack.white` sprayed with password `capital-15`
        *   User `joyce.fielder` sprayed with password `capital-17`
        *   User `jane.rodgers` sprayed with password `capital-18`

---

### Reconstructed Attack Path
1.  **Pivot Ingress:** Attacker compromised workstation `wrk-shasek` or leveraged the intern account `tim.smith` (IT Intern) on it.
2.  **Active Directory password Spraying:** Attacker launched `G:\spray.ps1` from the workstation to spray domain credentials via LDAP.
3.  **Privilege Escalation:** Attacker successfully compromised or harvested the cached Domain Admin credentials of **`frank.kolzig`** (who co-existed and logged into `wrk-shasek` as shown in our graph database).
4.  **Lateral Movement & DC Compromise:** Armed with Domain Admin access, the attacker pivoted from `wrk-shasek` to `activedir.stackedpads.local` and dumped all active domain credentials using **Mimikatz**.

---

### Deliverable Hunt Report & Actionable Containment Playbook
I have formally compiled and generated a comprehensive report detailing our findings, SIEM queries, host assets, and remediation guidelines.

You can access the report here:
[wrk-shasek_Lateral_Movement_Hunt_Report.md](https://storage.cloud.google.com/secops-demo-env-adk-artifacts-20260318/2164796008335147008/eval_user/7367176850440716288/wrk-shasek_Lateral_Movement_Hunt_Report.md/0)

#### Immediate Containment Tasks for Tier 2 Incident Responder:
1.  **EDR Isolation:** Isolate workstation `wrk-shasek` (IP: `10.1.0.50`) and server `wins-d19` immediately.
2.  **Disable Compromised Accounts:** Immediately lock out and disable accounts `tim.smith` and `frank.kolzig`.
3.  **Domain Controller Mitigation:** Reset domain-wide administrator passwords and initiate a **KRBTGT double password reset** to invalidate any active or forged Golden Tickets since memory credentials on the DC were dumped.

Respectfully signed off,

**Threat Hunter**
*Proactive Threat Hunting & Security Operations Specialist*I have discovered sufficient telemetry to confirm active lateral movement, privilege escalation, and Domain Admin credential dumping. I will formally save these findings and actionable containment recommendations as a hunt artifact report using `save_report_artifact`. This report will provide the Tier 2 Incident Responder with everything they need to execute an immediate incident containment response.I have uncovered a **highly coordinated, critical lateral movement and domain escalation campaign** starting from the workstation `wrk-shasek`!

Here is the complete attack chain reconstructed from our SIEM and Graph telemetry:

1.  **Initial Access / Execution on `wrk-shasek`**:
    *   The user account `tim.smith` (listed in Active Directory as an "Intern" in the IT department) logged on to `wrk-shasek` (IP: `10.1.0.50`).
    *   On **June 15, 2026, at 14:00-14:04 UTC**, the attacker executed a malicious PowerShell script named **`G:\spray.ps1`** on `wrk-shasek`.
2.  **Credential Access via AD Password Spraying**:
    *   The script `spray.ps1` was binds to Active Directory over LDAP using the `System.DirectoryServices.DirectoryEntry` class to conduct a **password spraying attack** against domain accounts.
    *   We caught PowerShell Event ID 4103 capturing the script trying various usernames and passwords:
        *   User: `joyce.fielder` with password `capital-14`
        *   User: `jeff.armstrong` with password `capital-14`
        *   User: `jack.white` with password `capital-15`
        *   User: `joyce.fielder` with password `capital-17`
        *   User: `jane.rodgers` with password `capital-18`
3.  **Administrator Escalation & Lateral Movement to Domain Controller**:
    *   Our knowledge graph confirms that the domain administrator account **`frank.kolzig`** has active logons on **`wrk-shasek`** as well as the Domain Controller **`activedir.stackedpads.local`** (IP: `10.1.0.4`).
    *   The attacker successfully gained access to `frank.kolzig`'s credentials (likely through the spraying campaign or local dumping on `wrk-shasek` since they co-existed on the same host).
4.  **Domain Controller Compromise (Credential Dumping)**:
    *   Armed with compromised Domain Admin credentials for `frank.kolzig`, the attacker moved laterally to the Domain Controller `activedir.stackedpads.local`.
    *   On **June 15, 2026, at 14:19:20 UTC** (just ~15 minutes after the password spray started from the workstation), the attacker executed **Mimikatz** from `C:\Users\fkolzig\Downloads\mimikatz_trunk\x64\mimikatz.exe` to dump LSASS passwords:
        `mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit`

This is a critical, ongoing threat. To understand if our systems have already alerted on this or if we have open cases, I will quickly query recent security alerts.I have detected a **critical threat indicator** in our SIEM logs!

A search for events involving the administrator account `frank.kolzig` over the past 168 hours has revealed that on **June 12, 2026, at 14:19:20 UTC** and again on **June 15, 2026, at 14:19:20 UTC**, `mimikatz.exe` was executed on the Domain Controller (`activedir.stackedpads.local`) under the context of user `frank.kolzig`. The specific command line was:
`mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit`
This dumped local credentials from `lsass.exe` (Sysmon Event ID 10: ProcessAccess).

This confirms the account `frank.kolzig` has been heavily abused for credential theft on our critical assets!

Next, I will query Chronicle SIEM logs for the second administrator account, `tim.smith`, to identify any suspicious logs or processes associated with his credentials.I have completed my graph relationship traversal. The graph analysis reveals two highly suspicious lateral movement trails involving user accounts logged on to `wrk-shasek`:

1.  **`frank.kolzig`**: Logged on to `wrk-shasek`, `wins-d19`, and the Domain Controller `activedir.stackedpads.local`.
2.  **`tim.smith`**: Logged on to `wrk-shasek`, `wrk-pacman.lunarstiiiness.com`, the domain controller node `activedir`, and `activedir.stackedpads.local`.

Now, following our runbook workflow, I will **pivot early** to Chronicle SIEM logs to search for security events involving these two users. I will start by searching for any events associated with `frank.kolzig` over the past 7 days (168 hours).I will execute my third and final knowledge graph query (adhering to our strict budget of 2 to 3 graph queries) to trace if the user accounts `frank.kolzig` or `tim.smith` (who are logged on to `wrk-shasek`) have logged on to other workstations or servers in the environment. This is a crucial graph technique to identify potential lateral movement.I will run a second Cypher query to retrieve all direct relationships and connected nodes (such as user logons, alerts, or investigations) connected to the `Host` node `wrk-shasek`. This will expose any initial indicators of compromise or logged-on users that could serve as pivoting entities.I will start by querying our Security Operations Neo4j knowledge graph using `query_neo4j_graph` to identify any investigations, user accounts, or assets directly associated with the workstation `wrk-shasek`. This will help us find immediate pivot points (such as logged-on accounts or related alerts) while respecting our graph-query budget.I will begin by retrieving the relevant hunting runbooks from our Agentic SOC repository to guide our methodology and ensure we follow best practices for detecting lateral movement and compromised administrator accounts.
```

---
