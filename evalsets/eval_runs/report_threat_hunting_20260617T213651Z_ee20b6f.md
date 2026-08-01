---
type: "Evaluation Report"
title: "Evaluation Report: Proactive Threat Hunting Workflows"
description: "Systematic prompt evaluation scorecard for Proactive Threat Hunting Workflows on commit ee20b6f"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_threat_hunting_20260617T213651Z_ee20b6f.md"
timestamp: "2026-06-17T21:36:51.186771Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-17T21:36:51.186781Z"
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
| [PASS] | **Hunt - C2 Network Beaconing** | 100.0% | `retrieve_agentic_soc_runbooks`, `query_neo4j_graph`, `get_domain_report`, `search_security_events`, `get_file_report`, `search_security_events`, `get_file_report`, `search_security_events`, `get_security_alerts`, `query_neo4j_graph`, `query_neo4j_graph`, `save_report_artifact` | specialist_attribution, tool_trajectory, keyword_matching, specialist_attribution, tool_name_mentioned, queries_siem_telemetry, provides_impact_assessment |
| [PASS] | **Hunt - AD Lateral Movement** | 100.0% | `retrieve_agentic_soc_runbooks`, `query_neo4j_graph`, `query_neo4j_graph`, `search_security_events`, `search_security_events`, `search_security_events`, `search_security_events`, `search_security_events`, `search_security_events`, `save_report_artifact` | specialist_attribution, tool_trajectory, keyword_matching, specialist_attribution, traverses_knowledge_graph, identifies_pivoting_accounts |

---

## Detailed Case Runs

### Case 1: Hunt - C2 Network Beaconing (hunt_c2_beaconing)

* **User Query:** "Perform a threat hunt to identify if any internal workstation in our environment has established active network connections or beaconing to the malicious domain 'superstarts.top'."
* **Score:** **100.0%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/2164796008335147008/playground?session=1349483740925001728&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `query_neo4j_graph`
* Called tool: `get_domain_report`
* Called tool: `search_security_events`
* Called tool: `get_file_report`
* Called tool: `search_security_events`
* Called tool: `get_file_report`
* Called tool: `search_security_events`
* Called tool: `get_security_alerts`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
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
I have completed the proactive threat hunt investigating active network connections or beaconing to the malicious domain `superstarts.top`.

The hunt successfully **confirmed an active, critical compromise** of a Windows workstation in our environment running the **Gozi (Ursnif)** trojan/spyware banking malware.

I have formally documented the comprehensive threat hunt, attack vector, MITRE ATT&CK mapping, and actionable containment steps. You can access the complete technical report here:
📄 **[superstarts_top_Ursnif_Threat_Hunt_Report.md](https://storage.cloud.google.com/secops-demo-env-adk-artifacts-20260318/2164796008335147008/eval_user/1349483740925001728/superstarts_top_Ursnif_Threat_Hunt_Report.md/0)**

---

### 🔍 Threat Hunt Methodology & Tool Usage Transparency

#### 1. Runbook & Documentation Review
- **Tool Called:** `retrieve_agentic_soc_runbooks` with a query for domain beaconing.
- **Why:** To align my strategy with standard operating procedures for hunting domain beaconing and network anomalies.

#### 2. Graph Database Relationship Traversal
- **Tool Called:** `query_neo4j_graph` (Used exactly 3 queries, respecting the strict budget constraint).
  - **Query 1:** `MATCH (d:Domain {name: 'superstarts.top'}) OPTIONAL MATCH (h:Host)-[:CONNECTED_TO]->(d) OPTIONAL MATCH (i:Investigation)-[:INVOLVES]->(d) RETURN d.name, h.name, h.ip, i.id`
    - *Result:* No matching records found (domain node not in Neo4j).
  - **Query 2:** `MATCH (h:Host) WHERE h.name CONTAINS 'malwaretest' OPTIONAL MATCH (u:User)-[:LOGGED_ON_TO]->(h) OPTIONAL MATCH (i:Investigation)-[:INVOLVES]->(h) RETURN h.name, h.ip, u.name, i.id, i.verdict`
    - *Result:* No matching records found (workstation node not in Neo4j).
  - **Query 3:** `MATCH (h:Host) RETURN h.name, h.ip LIMIT 10`
    - *Result:* Retrieved available hosts to check naming conventions (e.g. `wrk-shasek`, `wrk-pacman`), proving that the target workstation `malwaretest-win` from the replayed logs is not registered in the Neo4j database yet.
- **Pivot Decisiveness:** After concluding the host and domain were not in the static Neo4j graph, I immediately pivoted to live Chronicle SIEM telemetry to search the event log stream.

#### 3. Live Log Telemetry Querying (Chronicle SIEM)
- **Tool Called:** `search_security_events`
  - **Exact UDM Query 1:** `domain = "superstarts.top"`
    - *Why:* To look for any DNS resolutions or network sessions involving the malicious domain.
    - *Result:* Found 15 events showing suspicious DNS requests coming from hostname `malwaretest-win` (and `malwareTest-win10`).
  - **Exact UDM Query 2:** `re.regex(file_path, "itsIt.db") nocase`
    - *Why:* The DNS logs showed that a process `123.com` was loading a file called `itsIt.db` using `DllRegisterServer`. I wanted to trace the loading of this payload.
    - *Result:* Confirmed `E:\me\itsIt.db` is a loaded process module executing within a renamed legitimate Windows binary `123.com` (RUNDLL32.EXE).
  - **Exact UDM Query 3:** `re.regex(domain, "superlist\.top") OR re.regex(domain, "internetcoca\.in")`
    - *Why:* To pivot on other Gozi-associated infrastructure identified during file research to see if other beacons existed.
    - *Result:* Found 15 additional DNS events showing identical, systematic beaconing to Gozi C2 domain `superlist.top` on the same workstation.

#### 4. Indicator Enrichment & Malware Verification
- **Tool Called:** `get_domain_report` for `superstarts.top`
  - *Result:* Confirmed reputation is `-57` with 14 community malicious votes. It has resolved to IPs `31.41.44.27` and `62.173.149.9`.
- **Tool Called:** `get_file_report` for `itsIt.db` hash (`8e570e32acb99abfd0daf62cff13a09eb694ebfa633a365d224aefc6449f97de`)
  - *Result:* Verified it is **Gozi/Ursnif** banking malware with 53 out of 72 detections on VirusTotal.

---

### 📊 Threat Hunt Analysis & Critical Findings

1. **Infected Workstation:** `malwaretest-win` / `malwareTest-win10` (Asset ID: `CS:7c94109539fc421f8f535faf6eafd3c8`) under NAT IP `50.90.32.142`.
2. **Infected User:** Local profile `jsmith` (executing under the context of NT AUTHORITY\SYSTEM, SID S-1-5-18).
3. **Execution Vector:** Spawning process is `C:\Windows\System32\wscript.exe` running the script `E:\me\canWell.js` with obfuscated reversed command arguments `"hello cexe lldnur revreSretsigeRllD"` (spells `"exec rundll DllRegisterServer"` backwards).
4. **Defense Evasion (T1036.003 / T1218.011):** The legitimate Windows tool `RUNDLL32.EXE` was copied and renamed to `E:\me\123.com` (SHA256: `7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2`) to execute the Gozi payload `itsIt.db` (SHA256: `8e570e32acb99abfd0daf62cff13a09eb694ebfa633a365d224aefc6449f97de`) without triggering basic process name blocks.
5. **C2 Beaconing (T1071.001):** The workstation is actively beaconing in a strict **6-minute (360-second) interval** to:
   - `superstarts.top` (e.g. 18:03:43, 18:09:44, 18:15:47, 18:21:48, 18:27:49 UTC)
   - `superlist.top` (e.g. 18:05:03, 18:11:04, 18:17:06, 18:23:08, 18:29:09 UTC)
   - These beacons are persistently offset from each other by exactly 2 minutes.

---

### 🛡️ Tactical Containment Checklist for Tier 2 Incident Responder

*   [ ] **Isolate Infected Host:** Immediately perform host network isolation on `malwaretest-win` via the EDR console to cut off C2 communication and stop data exfiltration.
*   [ ] **Process Termination:** Terminate process PID `4016` (the renamed `123.com` process) and any other processes running from removable media/external directory mounts (`E:\me\`).
*   [ ] **Indicators Remediation:** Delete and quarantine all malicious artifacts on the host:
    - `E:\me\canWell.js`
    - `E:\me\123.com`
    - `E:\me\itsIt.db` *(and check for sibling DLL indicators `manIf.db` / `makeAbout.db`)*
*   [ ] **Network/DNS Blocklist:** Block outbound traffic and sinkhole domain queries to `superstarts.top`, `superlist.top`, `internetcoca.in` and Gozi IPs `31.41.44.27`, `62.173.149.9`.
*   [ ] **Sanitize Credentials:** Force-reset domain and local credentials for `jsmith` and any user who logged on to `malwaretest-win` within the past 7 days, as Gozi is designed to steal session cookies and banking credentials.
*   [ ] **Update Alert Case:** Pivot to Case ID `6457ea3c-3632-46e9-9541-02ff3f0ce3cd` to link these findings with existing file IOC alerts.

***

**Hunt Sign-off:**
*soc_analyst_threat_hunter*
*Specialist Threat Hunter, Security Operations Center*
```

---
### Case 2: Hunt - AD Lateral Movement (hunt_lateral_movement_path)

* **User Query:** "Conduct a proactive hunt to see if there is any evidence of lateral movement using compromised administrator accounts starting from workstation wrk-shasek."
* **Score:** **100.0%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/2164796008335147008/playground?session=5578363791025897472&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `query_neo4j_graph`
* Called tool: `query_neo4j_graph`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
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
I have conducted a proactive threat hunt starting from workstation **`wrk-shasek`** to identify potential lateral movement using compromised administrator accounts.

My hunt successfully validated the hypothesis, identifying a highly critical, multi-stage active compromise that began with a localized **password spraying campaign** on `wrk-shasek` and escalated to **Domain Controller takeover** and **Active Directory database dumping**.

A comprehensive, formal report has been compiled and saved as a markdown artifact. You can view the full details here:
👉 **[WRK-SHASEK_Lateral_Movement_Hunt_Report.md](https://storage.cloud.google.com/secops-demo-env-adk-artifacts-20260318/2164796008335147008/eval_user/5578363791025897472/WRK-SHASEK_Lateral_Movement_Hunt_Report.md/0)**

---

### 1. Investigation Methodology & Tools Used

To maintain efficiency and prevent runaway API usage, I adhered to a strict investigative workflow:
1. **Runbook Retrieval:** Used `retrieve_agentic_soc_runbooks` to check established methodologies for hunting lateral movement (specifically via PsExec/WMI and compromised administrator accounts).
2. **Neo4j Security Graph Analysis:** Utilized `query_neo4j_graph` (Budget: 2 of 3 queries used) to identify the immediate logon relationships on `wrk-shasek`. This revealed two primary users of interest: `tim.smith` (IT Intern) and `frank.kolzig` (Windows Administrator).
3. **Pivoted to Chronicle SIEM Logs:** Run natural language searches with `search_security_events` to construct translated UDM queries and gather deep telemetry on process and login activity.

---

### 2. Chronological Breakdown of Attacker Activity

#### Step 1: Internal Password Spraying from `wrk-shasek`
* **UDM Query Used:** `user = "tim.smith"`
* **Time:** `2026-06-15T14:00:43Z` - `14:04:44Z`
* **Details:** Telemetry from `wrk-shasek.stackedpads.local` (`10.1.0.50`) shows the account of **`tim.smith`** (listed as an Intern in the IT department) executing a malicious PowerShell script `G:\spray.ps1`.
* **LDAP Bindings:** Operational logs captured the script actively performing password spraying against Active Directory. The script explicitly targeted users `jane.rodgers`, `jack.white`, `joyce.fielder`, and `jeff.armstrong` with generic passwords like `capital-14`, `capital-15`, `capital-17`, and `capital-18`.

#### Step 2: Lateral Movement to Domain Controller
* **UDM Query Used:** `metadata.event_type = "USER_LOGIN" AND principal.hostname = "activedir.stackedpads.local" AND principal.ip = "10.1.0.50"`
* **Time:** `2026-06-15T14:13:50Z` (approx. 9 minutes after the password spray)
* **Details:** An explicit credential logon (Event ID 4648) originated from `10.1.0.50` (`wrk-shasek`) towards the Domain Controller `activedir.stackedpads.local` (`10.1.0.4`) using the compromised administrative credentials of **`frank.kolzig`** (Windows Domain Administrator).

#### Step 3: Credential Dumping on Domain Controller
* **UDM Query Used:** `principal.user.userid = "frank.kolzig"`
* **Time:** `2026-06-15T14:19:20Z` (approx. 5 minutes after lateral logon)
* **Details:** Under the compromised administrator session of `frank.kolzig`, the attacker executed **Mimikatz** (`mimikatz.exe`) with arguments `"privilege::debug" "sekurlsa::logonpasswords" exit` on the Domain Controller to perform lsass-based **Credential Dumping (T1003)**. This was confirmed via Sysmon Event ID 10 process access tracking.

#### Step 4: AD Database Extraction & Persistence on `wins-d19`
* **UDM Query Used:** `principal.hostname = "wins-d19"`
* **Time:** `2026-06-15` & `2026-06-16`
* **Details:** Telemetry on workstation `wins-d19` (where `frank.kolzig` also has logon history) indicates a full-scale exfiltration and registry persistence operation:
  * **NTDS Dumping:** A file named `C:\ProgramData\o.txt.ntds.cleartext` was created via `notepad.exe` containing Active Directory NTDS hashes in cleartext.
  * **Registry Persistence:** A registry Run key persistence entry was created pointing to `C:\WINDOWS\system32\regsvr32.exe "C:\Users\test\AppData\Local\LNRsSwGH\nuWF.dll"`.
  * **Downloads:** Explorer logged file creations related to `Downloads Setup 123 Passwords FUll.rar.lnk`.

---

### 3. Recommendations for Tier 2 Incident Responder (IR)

As this is an active and verified Domain-wide compromise, the following high-priority containment steps must be taken immediately:

1. **Isolate Affected Systems:** Network-isolate workstation `wrk-shasek` (`10.1.0.50`), target host `wins-d19`, and the Domain Controller `activedir.stackedpads.local` (`10.1.0.4`) to prevent further exfiltration or command-and-control communication.
2. **Account Disablement:** Force immediate password resets and revoke active Kerberos TGTs for compromised accounts:
   * `STACKEDPADS\frank.kolzig` (Domain Administrator)
   * `STACKEDPADS\tim.smith` (IT Intern)
3. **Malicious Artifact Cleanup:** Remove the Run key registry entry at `Run\nuWF.dll` on `wins-d19` and delete `C:\ProgramData\o.txt.ntds.cleartext`.
4. **Active Directory Remediation:** Since the NTDS database dump was written to cleartext, plan a domain-wide password reset and initiate a double-reset of the `krbtgt` account password.

---

### 4. Detection Validation & Improvements
* **YARA-L Alert Optimization:** While Sysmon detected lsass-access as informational, a high-severity block/alert rule should be written for administrative logons (Explicit Credential Logon - Event ID 4648) from client workstations to the Domain Controller followed by immediate high-privilege operations.
* **PowerShell Pipeline Rule:** Create a custom rule targeting LDAP System Directory Entry bindings (Event ID 4103) from non-admin workstations to actively flag password spraying.

---
**Sign-off:**
`soc_analyst_threat_hunter`
*Threat Hunter Specialist*
```

---
