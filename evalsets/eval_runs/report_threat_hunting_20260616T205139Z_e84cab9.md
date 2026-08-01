---
type: "Evaluation Report"
title: "Evaluation Report: Proactive Threat Hunting Workflows"
description: "Systematic prompt evaluation scorecard for Proactive Threat Hunting Workflows on commit e84cab9"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_threat_hunting_20260616T205139Z_e84cab9.md"
timestamp: "2026-06-16T20:51:39.472350Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T20:51:39.472361Z"
---
# Evaluation Report: Proactive Threat Hunting Workflows

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** Proactive Threat Hunting Workflows
* **Overall Score:** **53.6%**
* **Status:** FAIL

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
| [WARNING] | **Hunt - C2 Network Beaconing** | 57.1% | `retrieve_agentic_soc_runbooks`, `get_domain_report`, `get_ioc_matches`, `search_security_events`, `get_file_report`, `lookup_entity`, `lookup_entity`, `search_security_rules`, `search_security_events` | keyword_matching, tool_name_mentioned, queries_siem_telemetry, provides_impact_assessment |
| [WARNING] | **Hunt - AD Lateral Movement** | 50.0% | `retrieve_agentic_soc_runbooks`, `search_security_events`, `find_udm_field_values`, `search_udm`, `search_udm`, `search_udm`, `get_security_alerts`, `get_security_alerts`, `search_security_events`, `search_udm`, `search_udm`, `search_udm`, `search_security_rules` | keyword_matching, traverses_knowledge_graph, identifies_pivoting_accounts |

---

## Detailed Case Runs

### Case 1: Hunt - C2 Network Beaconing (hunt_c2_beaconing)

* **User Query:** "Perform a threat hunt to identify if any internal workstation in our environment has established active network connections or beaconing to the malicious domain 'superstarts.top'."
* **Score:** **57.1%**

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `get_domain_report`
* Called tool: `get_ioc_matches`
* Called tool: `search_security_events`
* Called tool: `get_file_report`
* Called tool: `lookup_entity`
* Called tool: `lookup_entity`
* Called tool: `search_security_rules`
* Called tool: `search_security_events`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [ ] **tool_trajectory**
* [X] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **tool_name_mentioned**
* [X] **queries_siem_telemetry**
* [X] **provides_impact_assessment**

#### Model Final Response
```markdown
I have retrieved the logic for the `ursnif_malware_dns` rule.

### Rule Logic Assessment
The rule `ursnif_malware_dns` is a **multi-event correlation rule** that requires:
1. A DNS lookup event (`SuspiciousDnsRequest`) to an Ursnif domain.
2. A subsequent outbound network connection on port 80 (TCP) to an IP address that must be in the `%ursnif_ip_addresses.ip` reference list.

To verify if an active TCP network connection occurred to `superstarts.top`'s resolved IP addresses (`31.41.44.27` and `62.173.149.9`), I will perform a search for any connections to these IP addresses in the SIEM logs. This will confirm whether the malware successfully established C2 communications beyond DNS lookups.I'll now search for the detection rule `ursnif_malware_dns` in our SIEM to understand the logic currently deployed to detect this Ursnif activity. This will help us evaluate if there are any gaps in our detection.I will also query `lookup_entity` for `malwareTest-win10` to ensure we capture all associated SIEM alerts and telemetry recorded under that hostname variant.I have analyzed the process hash `7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2`.

### Binary Integrity Verification
- **Reputation Check:** Safe/Legitimate (72 undetected engines, 0 malicious).
- **Attribution:** The binary is a legitimate Microsoft Windows Host Process (`rundll32.exe`) utility.
- **TTP Identified:** This confirms a **Defense Evasion (Masquerading - Rename System Utilities: T1036.003)** technique. The threat actor copied or renamed the legitimate Microsoft `rundll32.exe` tool to `E:\me\123.com` to bypass basic filename-based application controls and executed a malicious payload `me/itsIt.db` disguised as a database.

I will now enrich our understanding of the affected workstation `malwaretest-win` (and `malwareTest-win10`) by calling `lookup_entity` to see what else has been recorded in the SIEM regarding this system. This will help determine if there are other symptoms of compromise or related active alerts.I have successfully found active DNS beaconing activity to `superstarts.top` from our internal environment.

### Threat Hunt Findings Analysis
- **Communicating Workstation:** `malwaretest-win` (Sysmon logs report `malwareTest-win10`)
- **Compromised User Account:** `jsmith` (Domain: `MALWARETEST-WIN`)
- **Malicious Process:**
  - **Executable:** `E:\me\123.com` (which maps to `\Device\CdRom1\me\123.com`)
  - **Command Line:** `me\123.com me/itsIt.db,DllRegisterServer`
  - **Process Hash (SHA256):** `7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2`
  - **Process Hash (MD5):** `d0432468fa4b7f66166c430e1334dbda`
  - **Original File Name (Exif):** `RUNDLL32.EXE` (This indicates `rundll32.exe` was renamed to `123.com` to evade detection).
  - **Target Library:** `me/itsIt.db` (which is likely a renamed DLL/payload file containing Gozi/Ursnif code, executed via the `DllRegisterServer` export).

- **Evasive Execution Pattern:**
  - **Parent Process:** `C:\Windows\System32\wscript.exe` (PID: `6212`)
  - **Parent Command Line:** `"C:\Windows\System32\WScript.exe" "E:\me\canWell.js" hello cexe lldnur revreSretsigeRllD`
  - **Obfuscation Detail:** The arguments passed to `canWell.js` include `"cexe lldnur revreSretsigeRllD"`, which is **reversed string obfuscation** for `DllRegisterServer rundll32 exec`. The script likely reverses these strings dynamically during execution to evade static analysis.

- **Beaconing Analysis:**
  - Lookups occur **exactly every 6 minutes** (360 seconds).
  - **DNS Query Status:** `9003` (`NXDOMAIN`). The domain is currently non-existent or inactive, but the host remains persistently infected and continues to beacon.

I will now call `get_file_report` on the process hash `7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2` to see if it is indeed a legitimate Microsoft `rundll32.exe` binary or a modified malicious binary. Following that, I will check the workstation context.I checked the top 20 recent IOC matches via Chronicle's integrated threat feeds, and while there are matches for other threats, `superstarts.top` does not appear in the top 20 matches.

Next, I will perform a SIEM event search to hunt for any network activity (such as DNS requests, HTTP traffic, or generic network connections) targeting the domain `superstarts.top` or its resolved IP addresses over the past 96 hours.

I will use `search_security_events` to search for:
1. Connections or lookups to `superstarts.top`
2. Connections to the IP `31.41.44.27`
3. Connections to the IP `62.173.149.9`

I'll start by querying for any event referencing the domain `superstarts.top` in the last 96 hours.I have successfully retrieved the domain intelligence report for `superstarts.top`.

### Threat Intelligence Context
- **Reputation:** Highly suspicious (Reputation Score: -57, 14 malicious detections).
- **Adversary/Malware Association:** The domain is strongly associated with **Gozi / Ursnif** malware collections (e.g., `threatfox_win_gozi`, `analysis_virustotal_zenbox_ursnif`). Gozi/Ursnif is a notorious banking trojan and info-stealer.
- **Infrastructure:**
  - A Records: `31.41.44.27` and `62.173.149.9`
  - Registrar: ERANET INTERNATIONAL LIMITED (registrant country: RU)
  - Name Servers: `a.dnspod.com`, `b.dnspod.com`, `c.dnspod.com`

### Hunt Task List
1. **[Completed]** Gather Threat Intelligence on `superstarts.top`.
2. **[In Progress]** Check SIEM for historical IOC matches.
3. **[Next]** Run comprehensive UDM searches in Chronicle for both `superstarts.top` and the resolved IPs (`31.41.44.27`, `62.173.149.9`) to find active connections or beaconing.
4. **[Next]** Identify and analyze any communicating internal hosts/workstations and involved users.
5. **[Next]** Generate a final report and provide tactical containment recommendations.

I will now call `get_ioc_matches` to check for any integrated feed matches for the past 96 hours (default).I will start the threat hunt by creating a Task Todo List for this investigation and simultaneously gathering intelligence on the domain `superstarts.top` using Google Threat Intelligence (`get_domain_report`) to understand its reputation, associated malware families, and tactics. This will help us tailor our search queries.I will start by retrieving the relevant threat hunting runbooks to guide our process for searching for Indicators of Compromise (IOCs) such as the domain 'superstarts.top' in our environment. I will call `retrieve_agentic_soc_runbooks` to search for runbooks related to IOC threat hunting.
```

---
### Case 2: Hunt - AD Lateral Movement (hunt_lateral_movement_path)

* **User Query:** "Conduct a proactive hunt to see if there is any evidence of lateral movement using compromised administrator accounts starting from workstation wrk-shasek."
* **Score:** **50.0%**

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `search_security_events`
* Called tool: `find_udm_field_values`
* Called tool: `search_udm`
* Called tool: `search_udm`
* Called tool: `search_udm`
* Called tool: `get_security_alerts`
* Called tool: `get_security_alerts`
* Called tool: `search_security_events`
* Called tool: `search_udm`
* Called tool: `search_udm`
* Called tool: `search_udm`
* Called tool: `search_security_rules`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [ ] **tool_trajectory**
* [X] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **traverses_knowledge_graph**
* [X] **identifies_pivoting_accounts**

#### Model Final Response
```markdown
To get detailed insights, I will search for the configuration and rule ID of `win_repeatedAuthFailure_thenSuccess_T1110_001`. Once I have the rule ID, I can retrieve its historical detections, which will contain the exact successful logons (and subsequent lateral movement events) associated with this compromise.I will query specifically for Windows Event ID **4624 (An account was successfully logged on)** during the same June 15 to June 16, 2026 timeframe. This bypasses any array filtering constraints on `security_result.action` and relies on the direct Windows security log event type.To expand my scope, I will perform a broader UDM query to list **all successful logons** (`security_result.action = "ALLOW"`) in the environment between **June 15, 2026 and June 16, 2026**. This will help us track which accounts were successfully logged into around the timeframe of the credential validation attempts originating from `WRK-SHASEK`.I have analyzed the retrieved security events for `WRK-SHASEK`. I see a substantial volume of Microsoft-Windows-Security-Auditing Event 4776 logs (Credential Validation) indicating a large number of authentication failures with error code `0xC0000064` (account does not exist/misspelled) for accounts `jeff.armstrong` and `steve.oneil`.

To see if any administrator accounts were compromised, I will now run a UDM query searching for any **successful logins** (`security_result.action = "ALLOW"`) originating from `WRK-SHASEK` within the same timeframe (June 12, 2026, to June 16, 2026). This will reveal if any account (such as an administrative account) was successfully logged into.I see that standard alerts exist from **June 16, 2026**. Since the Chronicle system clock is active in this simulation period, I will perform a search for security events involving the capitalized hostname `WRK-SHASEK` across a lookback window of **168 hours** (7 days), which covers this time window perfectly. This will reveal events originating from or targetting the workstation.The maximum time range for retrieving security alerts is 2160 hours (90 days). If the simulated environment is currently running with its system clock set to 2026, then a standard lookback of 168 hours (7 days) or up to 2160 hours should work perfectly. I will query the alerts with a lookback of 168 hours first to check if we can see recent alerts.I will query the SIEM for recent security alerts. Since the environment's logs are simulated in 2026, I will use a very large lookback window (e.g., 24,000 hours, which is around 2.7 years) to capture any alerts generated in this timeframe. This will help us find specific events and rules that have already triggered.I will try a simpler and more specific query focusing only on `principal.hostname = "WRK-SHASEK"` within the exact timeframe of **June 14, 2026 to June 18, 2026** to ensure no logical operator syntax conflicts are interfering with the search.I notice from the `find_udm_field_values` results that the ingestion times of the logs are around June 16, 2026. This indicates the logs in this simulated environment are situated around that timeframe. I will adjust my UDM search to explicitly target the window of **June 14, 2026, to June 18, 2026** to find the relevant events.I see that the hostname is capitalized as `WRK-SHASEK` in the environment. I will now perform a direct UDM query to retrieve all events where the principal hostname is `WRK-SHASEK`. This will show us all actions originating from this workstation. I'll search across the last 72 hours.The initial query returned no events. I will use the `find_udm_field_values` tool to search for any occurrences of "shasek" or "wrk-shasek" in the UDM data. This will help identify the exact hostname format or any associated administrator accounts.I will begin my proactive hunt by querying the SIEM for all security events involving the workstation `wrk-shasek` over the last 72 hours to understand its baseline activity and identify any initial leads.I will start by retrieving the relevant Incident Response Plans (IRPs), runbooks, or hunting procedures for proactive threat hunts and lateral movement from the Agentic SOC repository to guide my process.
```

---
