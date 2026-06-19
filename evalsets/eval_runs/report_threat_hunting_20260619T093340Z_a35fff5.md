---
type: "Evaluation Report"
title: "Evaluation Report: Proactive Threat Hunting Workflows"
description: "Systematic prompt evaluation scorecard for Proactive Threat Hunting Workflows on commit a35fff5"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_threat_hunting_20260619T093340Z_a35fff5.md"
timestamp: "2026-06-19T09:33:40.979589Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-19T09:33:40.979621Z"
---
# Evaluation Report: Proactive Threat Hunting Workflows

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** Proactive Threat Hunting Workflows
* **Overall Score:** **84.5%**
* **Status:** WARNING

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
| [PASS] | **Hunt - C2 Network Beaconing** | 85.7% | `retrieve_agentic_soc_runbooks`, `query_knowledge_graph`, `get_domain_report`, `search_security_events`, `search_udm`, `search_security_events`, `get_file_report`, `query_knowledge_graph`, `query_knowledge_graph`, `search_security_events`, `save_report_artifact` | specialist_attribution, keyword_matching, specialist_attribution, tool_name_mentioned, queries_siem_telemetry, provides_impact_assessment |
| [PASS] | **Hunt - AD Lateral Movement** | 83.3% | `retrieve_agentic_soc_runbooks`, `query_knowledge_graph`, `query_knowledge_graph`, `query_knowledge_graph`, `search_security_events`, `search_udm`, `search_security_events`, `search_security_events`, `search_security_events`, `search_security_events`, `search_security_events`, `search_security_events`, `save_report_artifact` | specialist_attribution, keyword_matching, specialist_attribution, traverses_knowledge_graph, identifies_pivoting_accounts |

---

## Detailed Case Runs

### Case 1: Hunt - C2 Network Beaconing (hunt_c2_beaconing)

* **User Query:** "Perform a threat hunt to identify if any internal workstation in our environment has established active network connections or beaconing to the malicious domain 'superstarts.top'."
* **Score:** **85.7%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/2164796008335147008/playground?session=5944437391400894464&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `query_knowledge_graph`
* Called tool: `get_domain_report`
* Called tool: `search_security_events`
* Called tool: `search_udm`
* Called tool: `search_security_events`
* Called tool: `get_file_report`
* Called tool: `query_knowledge_graph`
* Called tool: `query_knowledge_graph`
* Called tool: `search_security_events`
* Called tool: `save_report_artifact`

#### Heuristic Success Checklist
* [X] **specialist_attribution**
* [ ] **tool_trajectory**
* [X] **keyword_matching**
* [X] **specialist_attribution**
* [X] **tool_name_mentioned**
* [X] **queries_siem_telemetry**
* [X] **provides_impact_assessment**

#### Model Final Response
```markdown
I have completed a proactive threat hunt to identify if any internal workstation in our environment has established active network connections or beaconing to the malicious domain **`superstarts.top`**.

The threat hunt was highly successful, confirming an **active command and control (C2) channel** from an internal host using advanced defense evasion techniques. Below is a detailed breakdown of the tools used, UDM queries, telemetry analysis, and next-step recommendations.

---

### 1. Tools Called & Why
1. **`retrieve_agentic_soc_runbooks`**: Used to pull threat hunting playbooks (`apt_threat_hunt.md`, `ioc_threat_hunt.md`) to establish structured, hypothesis-driven methodology.
2. **`query_knowledge_graph`**: Executed targeted Cypher queries on our Neo4j security graph database to check for direct connections to the domain or hosts with triggered alerts. (Exactly **3 queries executed**, fully respecting our strict 2-3 query graph budget).
3. **`get_domain_report` (GTI)**: Queried Google Threat Intelligence for reputation and classification of `superstarts.top`. Found a malicious reputation of **-57** with known associations to **Gozi/Ursnif (ISFB)** malware trojan collections.
4. **`search_security_events` (Chronicle SIEM)**: Executed granular event queries over the last 90 days to discover network DNS requests and execution chain logs related to the suspicious domain.
5. **`get_file_report` (GTI)**: Analyzed the file hash of the execution binary to confirm its legitimacy (verified to be clean Microsoft `RUNDLL32.exe`).
6. **`save_report_artifact`**: Formally recorded the detailed Technical Hunt & Containment Report as a permanent markdown artifact.

---

### 2. Chronological Telemetry Analysis & Execution Chain

The hunt identified a compromised workstation named **`malwaretest-win`** running Sysmon and Crowdstrike Falcon EDR.

#### **Phase 1: Initial Execution (2026-06-18 16:20:54 UTC)**
Using the UDM Query below:
```yara
hostname = "malwaretest-win" AND (metadata.event_type = "PROCESS_LAUNCH" OR metadata.event_type = "USER_LOGIN")
```
The logs showed that local administrator **`jsmith`** logged on interactively, which immediately kicked off a malicious execution chain spawning from Windows Explorer:
1. **Parent Process (Script Engine):** `wscript.exe` (PID `6212`) launched a malicious JavaScript file:
   * **Command Line:** `"C:\Windows\System32\WScript.exe" "E:\me\canWell.js" hello cexe lldnur revreSretsigeRllD`
2. **Executing Binary:** `wscript.exe` launched a binary named `123.com` (PID `4016`).
   * **Evasion Tactic:** EDR enrichment and GTI hashing verified `123.com` is a copied, renamed version of the legitimate Microsoft **`RUNDLL32.exe`** (SHA256: `7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2`).
3. **Payload Load:** The masqueraded binary loads a malicious database file `itsIt.db` (which is actually a malicious Gozi DLL payload) using the registered DLL entry point:
   * **Command Line:** `me\123.com me/itsIt.db,DllRegisterServer`

#### **Phase 2: Active C2 Beaconing (2026-06-18 17:03:30 to 18:45:54 UTC)**
Using the UDM Query below:
```yara
domain = "superstarts.top" OR re.regex(domain, ".*superstarts.top")
```
The network DNS logs confirmed that the renamed Rundll32 process (`123.com`, PID `4016`) established an active C2 communication channel to `superstarts.top`.

A detailed temporal analysis of the timestamps revealed a **highly regular, predictable beaconing pattern occurring exactly every 6 minutes (360 seconds)** with a standard deviation of less than 2 seconds (e.g., *17:03:30 -> 17:09:31 -> 17:15:33 -> 17:21:35 -> 17:27:36...*). This signature is characteristic of Gozi/Ursnif beaconing internals.

---

### 3. Threat Hunting Report Artifact
I have compiled the full technical details, MITRE ATT&CK mapping, and remediation steps into a technical markdown report:

👉 **[superstarts_top_threat_hunt_report.md](https://storage.cloud.google.com/secops-demo-env-adk-artifacts-20260318/2164796008335147008/eval_user/5944437391400894464/superstarts_top_threat_hunt_report.md/0)**

---

### 4. Direct Actionable Recommendations for Incident Response

1. **Host Isolation:** Immediately perform network containment on `malwaretest-win` (Asset ID: `CS:7c94109539fc421f8f535faf6eafd3c8`) via Crowdstrike Falcon EDR.
2. **Process Kill:** Forcefully terminate process PID `4016` (`123.com` / renamed `rundll32.exe`) and PID `6212` (`wscript.exe`) on the host.
3. **Artifact Cleanup:** Permanently purge the following files from the local storage of `malwaretest-win`:
   * `E:\me\canWell.js`
   * `E:\me\123.com`
   * `E:\me\itsIt.db`
   * `E:\me\alsoOne.bat`
4. **Network Filtering:** Establish blocklists on firewalls and DNS servers for the domain `superstarts.top` and known associated C2 IPs `31.41.44.27` and `62.173.149.9`.
5. **Credential Reset:** Force-rotate the password and invalidate active NTLM/Kerberos sessions for local administrator user account `jsmith`.

---
**Threat Hunter Sign-Off**
**Role:** Threat Hunter Specialist (*soc_analyst_threat_hunter*)
**Status:** Threat Hunt Completed — Active Gozi/Ursnif Infection & C2 Beaconing Identified on Host `malwaretest-win`. Handing over immediately to the Tier 2 Incident Responder for tactical containment.
```

---
### Case 2: Hunt - AD Lateral Movement (hunt_lateral_movement_path)

* **User Query:** "Conduct a proactive hunt to see if there is any evidence of lateral movement using compromised administrator accounts starting from workstation wrk-shasek."
* **Score:** **83.3%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/2164796008335147008/playground?session=6210994194345885696&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `query_knowledge_graph`
* Called tool: `query_knowledge_graph`
* Called tool: `query_knowledge_graph`
* Called tool: `search_security_events`
* Called tool: `search_udm`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `search_security_events`
* Called tool: `save_report_artifact`

#### Heuristic Success Checklist
* [X] **specialist_attribution**
* [ ] **tool_trajectory**
* [X] **keyword_matching**
* [X] **specialist_attribution**
* [X] **traverses_knowledge_graph**
* [X] **identifies_pivoting_accounts**

#### Model Final Response
```markdown
### Proactive Threat Hunt Report: Lateral Movement & Credential Abuse

**Subject:** Hunt Findings for Station `wrk-shasek` and Compromised Administrator Accounts
**Investigated By:** **Threat Hunter**
**Status:** **ACTIVE THREAT CONFIRMED (CRITICAL)**

---

### 1. Methodology & Tools Utilized

To proactively hunt for lateral movement from workstation `wrk-shasek` using compromised administrator accounts, the following sequence of tools was used:
1. **`retrieve_agentic_soc_runbooks`:** Checked standard procedures for lateral movement hunts (` T1570`, `T1021`, `T1047`) and located historical indicators pointing to credential stuffing.
2. **`query_knowledge_graph` (3 Neo4j Graph Queries):** Traversed host and user relationships to determine which administrative credentials were associated with `wrk-shasek` and traced logon destinations.
3. **`search_security_events` (4 Chronicle SIEM Queries):** Queried security logs over the target timeframe (June 11, 2026 to June 18, 2026) to find explicit credential logins and credential validation logs.
4. **`save_report_artifact`:** Formally recorded the hunting findings, analysis, and tactical mitigation plans in a Markdown artifact.

---

### 2. Exact UDM Queries Used in Chronicle SIEM

To isolate the lateral movement events, the following targeted UDM queries were designed and executed:

*   **UDM Query 1 (Broad User Enrichment):**
    ```yara
    user = "frank.kolzig"
    ```
    *Result:* Found multiple `ENTITY_RISK_CHANGE` logs identifying `frank.kolzig` as a **Windows Administrator** whose risk score spiked significantly due to malicious alerts.
*   **UDM Query 2 (Explicit Credential Monitoring):**
    ```yara
    metadata.event_type = "USER_LOGIN" AND (principal.user.userid = "frank.kolzig" OR principal.user.userid = "tim.smith")
    ```
    *Result:* Identified a sequence of explicit credential logins (Event ID 4648) from `wrk-shasek.stackedpads.local` (IP: `10.1.0.50`) utilizing PowerShell (`powershell.exe`).
*   **UDM Query 3 (Origin Host Authentication Spray):**
    ```yara
    metadata.product_event_type = "4648" principal.hostname = "wrk-shasek.stackedpads.local"
    ```
    *Result:* Identified a large volume of automated authentication attempts targeting `activedir.stackedpads.local` (`10.1.0.4`) using accounts like `john.smith`, `jim.johnson`, and `frank.kolzig`.
*   **UDM Query 4 (Target Server Logon & Success Isolation):**
    ```yara
    metadata.event_type = "USER_LOGIN" AND target.hostname = "activedir.stackedpads.local" AND target.user.userid = "frank.kolzig"
    ```
    *Result:* Tracked logon attempts on the Domain Controller. Confirmed the spraying success via a credential validation event (Event ID 4776) on **`2026-06-18T14:06:44Z`** returning Error Code **`0x0` (Status OK)**.

---

### 3. Deep-Dive Analysis of the Attack Path

Through cross-correlation of network, endpoint, and authentication logs, the exact lateral movement trail was reconstructed:

1. **Compromised Entry Workstation:** The threat actor controlled workstation **`wrk-shasek.stackedpads.local`** (IP: **`10.1.0.50`**) using compromised intern account **`tim.smith`**.
2. **Password Spray / Credential Stuffing:** The actor used PowerShell (`powershell.exe`, PID 660) on `wrk-shasek` to launch an automated password-spraying campaign targeting the Active Directory Domain Controller **`activedir.stackedpads.local`** (IP: **`10.1.0.4`**).
3. **Domain Admin Compromise:** On **June 18, 2026, at 14:06:44 UTC**, the spraying tool successfully guessed the password of the high-privileged **Domain Administrator** account **`frank.kolzig`** (validated via Event ID 4776 with Error Code `0x0`).
4. **Lateral RDP Movement:** Armed with valid domain admin credentials, the threat actor laterally moved to the Domain Controller via **Remote Desktop Protocol (RDP)** on **June 18, 2026, between 14:13:48 UTC and 14:13:49 UTC**, generating Event ID 4648 logons processed by `lsass.exe` targeting `TERMSRV/activedir.stackedpads.local`.

---

### 4. Containment & Remediation Recommendations (for Tier 2 Incident Responder)

To halt the active compromise immediately:
*   **Host Isolation:** Isolate workstation `wrk-shasek` (`10.1.0.50`) from the network to block the attacker’s execution platform and sever active processes.
*   **Credential Revocation:**
    1. Force a password reset and revoke all active sessions/tokens for Domain Administrator **`frank.kolzig`**.
    2. Reset the compromised user account **`tim.smith`**.
    3. Revoke active Kerberos TGTs to flush any cached attacker sessions.
*   **Domain Controller Forensics:** Conduct immediate endpoint forensics on `activedir.stackedpads.local` (`10.1.0.4`) starting from `2026-06-18T14:13:00Z` to check for credential harvesting (Mimikatz), creation of backdoor admin accounts, or malicious scheduled tasks.
*   **Network Security:** Temporarily disable RDP access to the Domain Controller from normal client subnets and enforce MFA.

---

### 5. Hunt Artifact Link

The formal Markdown hunt report, including rule improvements and remediation guidelines, has been successfully compiled and saved.

👉 **View the Formal Hunt Report:** [wrk-shasek_lateral_movement_hunt_report.md](https://storage.cloud.google.com/secops-demo-env-adk-artifacts-20260318/2164796008335147008/eval_user/6210994194345885696/wrk-shasek_lateral_movement_hunt_report.md/0)

Respectfully submitted,
**Threat Hunter**
```

---
