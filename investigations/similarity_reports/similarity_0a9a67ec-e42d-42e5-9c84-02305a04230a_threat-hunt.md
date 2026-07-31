---
type: "Evaluation Report"
title: "Investigation Similarity Report: Volume Shadow Copy Creation"
description: "Multi-modal similarity analysis for investigation 0a9a67ec-e42d-42e5-9c84-02305a04230a using AlloyDB pgvector and Threat Actor & Campaign Hunting scoring profile."
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/investigations/similarity_reports/similarity_0a9a67ec-e42d-42e5-9c84-02305a04230a_threat-hunt.md"
timestamp: "2026-07-31T00:01:11Z"
provenance:
  source_type: "python_generated"
  source_tool: "Vertex AI Gemini 2.5 Flash + AlloyDB Multi-Modal Engine"
  timestamp: "2026-07-31T00:01:11Z"
---

# Investigation Similarity Report: Volume Shadow Copy Creation

> **Scoring Profile:** `Threat Actor & Campaign Hunting` (Biases for shared MITRE TTPs and semantic attack tradecraft across multiple or disparate hosts.)
> **Weight Distribution:** Semantic: 35%, Entity: 5%, TTP: 45%, Flow: 10%, Time: 5%

## Target Investigation Overview

| Attribute | Value |
| :--- | :--- |
| **Investigation ID** | `0a9a67ec-e42d-42e5-9c84-02305a04230a` |
| **Display Name** | Volume Shadow Copy Creation |
| **Verdict** | `FALSE_POSITIVE` (HIGH_CONFIDENCE) |
| **Published Time** | 2026-06-14 10:17:36.481722+00:00 |
| **MITRE Tactics** | TA0006 |
| **MITRE Techniques** | T1003.003 |
| **Key Entities** | `HOST:activedir.stackedpads.local`, `USER:frank.kolzig`, `FILE:WmiPrvSE.exe`, `FILE:cmd.exe`, `IP:10.1.0.4`, `HASH:bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527` |

### Target Investigation Summary

* A Volume Shadow Copy was created on the host ' **activedir.stackedpads.local**' by user ' **frank.kolzig**' using ' **cmd.exe**' via 'wmiprvse.exe'. This activity is often associated with threat actors attempting to extract sensitive data like NTDS.DIT.

* The command `**cmd /c vssadmin create shadow /for=C:**` was executed on ' **activedir.stackedpads.local**' by user ' **frank.kolzig**'. This command is considered malicious and is frequently used by ransomware and other threat actors for data exfiltration or to hinder recovery. The execution was initiated by 'wmiprvse.exe', a legitimate Windows process, which then launched ' **cmd.exe**' to create the shadow copy. No other users or assets were found to have executed this specific malicious command. Prior to this activity, user ' **frank.kolzig**' had multiple failed logon attempts to ' **activedir.stackedpads.local**' from ' **wrk-shasek.stackedpads.local**', followed by successful logons. Additionally, several explicit credential logons for ' **frank.kolzig**' were initiated by ' **tim.smith**' from ' **wrk-shasek.stackedpads.local**' around the same time.

## Threat Actor Tradecraft & Campaign Analysis (AI Synthesis)

## Security Investigation Analysis: Volume Shadow Copy Creation on Active Directory

This analysis examines a target security investigation concerning Volume Shadow Copy creation on an Active Directory server and correlates it with five highly similar historical investigations. The objective is to provide objective, highly analytical security insights into the detected activity.

### 1. Executive Threat & Campaign Correlation

The target investigation and all historical matches exhibit identical threat actor tradecraft, binary/script usage, and attack methodology. The core activity involves the creation of a Volume Shadow Copy on the host `activedir.stackedpads.local` by user `frank.kolzig`. This action is typically associated with the MITRE ATT&CK technique T1003.003 (OS Credential Dumping: NTDS.DIT) under the Tactic TA0006 (Credential Access). Threat actors commonly use VSS to create a snapshot of the volume containing the NTDS.DIT database, allowing them to copy the database offline for credential extraction without interfering with the live system.

The attack methodology consistently involves `cmd.exe` executing the command `vssadmin create shadow /for=C:`, with `wmiprvse.exe` identified as the parent process. This `wmiprvse.exe` parent process can indicate legitimate administrative actions leveraging WMI, but it can also be abused by adversaries for code execution, often as part of remote execution or persistence techniques, before launching further commands. The specific targeting of `activedir.stackedpads.local`, a domain controller, significantly elevates the criticality of this activity, as compromise of NTDS.DIT could lead to full domain compromise.

The target investigation provides additional context not explicitly detailed in the summaries of historical matches: multiple failed logon attempts by `frank.kolzig` to `activedir.stackedpads.local` from `wrk-shasek.stackedpads.local`, followed by successful logons, and explicit credential logons for `frank.kolzig` initiated by `tim.smith` from the same workstation. This additional context suggests a broader attack chain potentially involving initial access on `wrk-shasek.stackedpads.local`, followed by lateral movement or privilege escalation attempts targeting the Active Directory server (`activedir.stackedpads.local`) to execute the VSS creation command as `frank.kolzig`. This aligns with typical threat actor campaign stages involving reconnaissance, credential access, and preparation for data exfiltration.

### 2. Entity & Infrastructure Overlap

There is a complete and consistent overlap of critical entities and infrastructure across the target investigation and all five historical matches, indicating highly concentrated and recurring activity rather than isolated incidents.

Shared entities include:
*   **Host**: `activedir.stackedpads.local` (This indicates a single, highly critical asset is repeatedly involved).
*   **User**: `frank.kolzig` (The same user account is performing this action in all instances).
*   **Process Name**: `cmd.exe`, `WmiPrvSE.exe` (Consistently showing the same execution chain).
*   **IP Address**: `10.1.0.4` (Likely the IP address of `activedir.stackedpads.local`).
*   **Hash**: `bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527` (This shared hash, likely associated with one of the involved binaries or a related artifact, further reinforces the identical nature of these events).

The high degree of entity overlap suggests a persistent pattern on a specific Active Directory server, executed under the same user context. This eliminates the possibility of disparate or unrelated incidents from an entity perspective. The `TTP: 1.0` and `entity: 1.0` sub-scores for all historical matches strongly corroborate this assessment. The consistency points towards either a highly repetitive legitimate administrative task, a consistently compromised user account, or an internal threat.

### 3. Historical Precedent & Verdict Analysis

The historical verdicts present a critical inconsistency that requires immediate attention. The target investigation is classified as `FALSE_POSITIVE` with `HIGH_CONFIDENCE`. Four out of five historical matches are also classified as `FALSE_POSITIVE` with `HIGH_CONFIDENCE`, reflecting identical security event patterns. However, one historical match (Rank 2: `19231038-c0c7-4dad-a9b7-4a5cb5c14684`) for the *exact same activity*, involving the *same user, host, processes, and command*, was classified as `TRUE_POSITIVE` with `HIGH_CONFIDENCE`.

This discrepancy is highly problematic:
*   **Inconsistent Adjudication**: The existence of a `TRUE_POSITIVE` for an otherwise identical event suggests that either the `FALSE_POSITIVE` classifications were incorrect, or the `TRUE_POSITIVE` had additional, crucial context that is not captured in the summary and was missed in other adjudications. Given the sensitive nature of an Active Directory server and the specific TTP (credential dumping preparation), a `TRUE_POSITIVE` for this activity should be the default assumption unless definitively proven otherwise.
*   **Risk of Under-Triaging**: Consistently classifying this activity as `FALSE_POSITIVE` creates a significant blind spot. If `frank.kolzig` is a legitimate administrator who routinely creates shadow copies on the domain controller for backups or specific tasks, this needs to be rigorously documented and baselined. Without such justification, this repetitive activity, especially on an AD controller, is highly suspicious.
*   **Target Investigation Context**: The additional details in the target investigation regarding failed logons and explicit credential logons by `tim.smith` targeting `frank.kolzig`'s account on the AD server further reduce the likelihood of this being a benign, routine `FALSE_POSITIVE`. This context points towards potential account compromise or misuse, which would align with a `TRUE_POSITIVE` verdict.

The prevailing `FALSE_POSITIVE` verdicts might stem from a lack of subsequent activity being observed (e.g., no actual NTDS.DIT exfiltration) or a misinterpretation of `wmiprvse.exe`'s role as purely legitimate, without considering its potential for abuse. The single `TRUE_POSITIVE` case implies that at least once, an analyst found compelling evidence that this specific activity was indeed malicious.

### 4. Actionable SOC Recommendations

To address the identified threats and the inconsistencies in historical verdicts, the following actions are recommended:

#### Triage Steps:

1.  **Immediate Re-evaluation of Target Investigation**: Change the target investigation's verdict from `FALSE_POSITIVE` to `UNRESOLVED` or `SUSPICIOUS` until a comprehensive investigation is completed.
2.  **User Activity Review (frank.kolzig)**:
    *   Determine if `frank.kolzig`'s role legitimately requires creating Volume Shadow Copies on `activedir.stackedpads.local`. If so, ascertain the frequency, timing, and typical parent processes.
    *   Interview `frank.kolzig` and their manager regarding this specific activity and any associated administrative tasks or issues.
3.  **Logon Anomaly Investigation**:
    *   Thoroughly investigate the failed and successful logon attempts for `frank.kolzig` from `wrk-shasek.stackedpads.local` immediately preceding the VSS creation. Look for brute-force attempts, password spraying, or credential stuffing.
    *   Investigate the explicit credential logons by `tim.smith` for `frank.kolzig`. Determine if this is a legitimate practice, if `tim.smith` has elevated privileges, or if `tim.smith`'s account or workstation (`wrk-shasek.stackedpads.local`) might be compromised.
4.  **Host Examination (`activedir.stackedpads.local`)**:
    *   Examine `activedir.stackedpads.local` for post-VSS creation activity, such as `esentutl.exe` usage, archival utility execution (e.g., `7z.exe`, `winrar.exe`), or unusual network connections that could indicate exfiltration attempts.
    *   Check for other signs of compromise, including persistence mechanisms, suspicious running processes, or modified system configurations.
5.  **Workstation Examination (`wrk-shasek.stackedpads.local`)**:
    *   Investigate `wrk-shasek.stackedpads.local` for signs of compromise, as it appears to be the origin point for the anomalous logons. Look for malware, C2 activity, or evidence of credential harvesting.
6.  **Review `TRUE_POSITIVE` Historical Context**: If available, pull the full investigation details for the `TRUE_POSITIVE` incident (ID `19231038-c0c7-4dad-a9b7-4a5cb5c14684`) to understand what additional context led to that verdict. This can inform future triage and detection logic.

#### Containment Actions (Conditional):

1.  **Credential Reset**: If `frank.kolzig`'s activity cannot be immediately justified as legitimate, or if `tim.smith`'s explicit credential usage is unauthorized, force password resets for both `frank.kolzig` and `tim.smith`.
2.  **Account Lockout**: If suspicious login attempts persist or indicate compromise, temporarily disable `frank.kolzig`'s and/or `tim.smith`'s accounts.
3.  **Host Isolation**: If evidence of further compromise (e.g., exfiltration, persistence) is found on `activedir.stackedpads.local` or `wrk-shasek.stackedpads.local`, isolate the affected hosts from the network to prevent further damage.

#### Detection Rule Tuning Suggestions:

1.  **Contextual Whitelisting**: Instead of broadly alerting on `vssadmin create shadow`, implement a granular whitelist:
    *   **User-Specific**: Only allow `frank.kolzig` to perform this action if it's a confirmed, legitimate administrative task. Even then, consider requiring a specific parent process or script, not direct `cmd.exe` from `wmiprvse.exe` unless justified.
    *   **Host-Specific**: For high-value assets like Active Directory controllers, this activity should be highly scrutinized. Consider a default block or high-severity alert unless explicitly whitelisted with strong justification.
2.  **Parent Process Scrutiny**: Enhance detection to flag `wmiprvse.exe` launching `cmd.exe` to execute sensitive commands like `vssadmin`, especially if not part of a known, approved automation.
3.  **Chained Event Correlation**: Create a correlation rule that elevates the severity when VSS creation (T1003.003) is immediately preceded by:
    *   Multiple failed logon attempts on the same host and user.
    *   Explicit credential logons initiated by a different user.
    *   Followed by `esentutl.exe` execution or unusual file transfers/compression on the target host.
4.  **Baseline Administrative Activity**: Establish a baseline for `frank.kolzig`'s typical activities on `activedir.stackedpads.local`. Alert on deviations from this baseline (e.g., VSS creation at unusual times, frequencies, or from unexpected source hosts).
5.  **Review Adjudication Guidelines**: Update SOC playbooks and analyst training to ensure consistent and accurate adjudication of `Volume Shadow Copy Creation` events, particularly on domain controllers. Explicitly address the conditions under which such an event should be considered a `TRUE_POSITIVE` (e.g., lack of legitimate justification, preceding suspicious activity, post-activity signs of exfiltration).

## Top Similar Historical Investigations

| Rank | Investigation ID | Display Name | Verdict | Composite Score | Sub-Score Breakdown (Sem / Ent / TTP / Flow / Time) | Shared Telemetry |
| :---: | :--- | :--- | :--- | :---: | :---: | :--- |
| 1 | [`b170c702...`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/investigations/b170c702-b405-4a5f-8f21-232d2af504da.md) | Volume Shadow Copy Creation | `FALSE_POSITIVE` | **0.9945** | `1.00 / 1.00 / 1.00 / 1.00 / 0.92` | Ent: `HASH:bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527`, `FILE:WmiPrvSE.exe` (+4)<br>TTP: T1003.003 |
| 2 | [`19231038...`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/investigations/19231038-c0c7-4dad-a9b7-4a5cb5c14684.md) | Volume Shadow Copy Creation | `TRUE_POSITIVE` | **0.9798** | `0.98 / 1.00 / 1.00 / 1.00 / 0.75` | Ent: `HASH:bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527`, `FILE:WmiPrvSE.exe` (+4)<br>TTP: T1003.003 |
| 3 | [`a240eec6...`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/investigations/a240eec6-cab1-4cef-ab2c-b3989abff745.md) | Volume Shadow Copy Creation | `FALSE_POSITIVE` | **0.9726** | `0.99 / 1.00 / 1.00 / 1.00 / 0.53` | Ent: `HASH:bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527`, `FILE:WmiPrvSE.exe` (+4)<br>TTP: T1003.003 |
| 4 | [`5f80038b...`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/investigations/5f80038b-b849-4e9c-a369-2f6f756d247a.md) | Volume Shadow Copy Creation | `FALSE_POSITIVE` | **0.9704** | `0.99 / 1.00 / 1.00 / 0.80 / 0.88` | Ent: `HASH:bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527`, `FILE:WmiPrvSE.exe` (+4)<br>TTP: T1003.003 |
| 5 | [`4a166db4...`](file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/investigations/4a166db4-fd04-4eb5-968d-d9e72cb357fe.md) | Volume Shadow Copy Creation | `FALSE_POSITIVE` | **0.9576** | `0.99 / 1.00 / 1.00 / 0.67 / 0.92` | Ent: `HASH:bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527`, `FILE:WmiPrvSE.exe` (+4)<br>TTP: T1003.003 |

## Detailed Match Breakdown

### Match #1: Volume Shadow Copy Creation (`b170c702-b405-4a5f-8f21-232d2af504da`)

- **Verdict:** `FALSE_POSITIVE` (Confidence: `HIGH_CONFIDENCE`)
- **Composite Score:** **0.9945**
- **Semantic Vector Similarity:** `0.9962`
- **Entity Overlap Score:** `1.0000`
- **MITRE TTP Overlap:** `1.0000`
- **Flow Steps Overlap:** `1.0000`
- **Temporal Decay Factor:** `0.9169`

**Shared Entities:**
- `[HASH]` `bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527` — **VT Severity**: `SEVERITY_NONE`
- `[FILE]` `WmiPrvSE.exe` — No enrichment data available.
- `[HOST]` `activedir.stackedpads.local` — Host active in SIEM logs. (Identity details retrieved from Chronicle)
- `[IP]` `10.1.0.4` — No enrichment data available.
- `[FILE]` `cmd.exe` — No enrichment data available.
- `[USER]` `frank.kolzig` — **Identity**: Frank Kolzig (frank.kolzig@stackedpad.local)

- **Shared Techniques:** T1003.003
- **Shared Tactics:** TA0006

**Investigation Summary:**
> * A Volume Shadow Copy was created on the host ' **activedir.stackedpads.local**' by user ' **frank.kolzig**' via ' **cmd.exe**'. This activity is often associated with threat actors attempting to extract sensitive data like NTDS.DIT.

* The command `**cmd /c vssadmin create shadow /for=C:**` was executed on ' **activedir.stackedpads.local**' by user ' **frank.kolzig**'. While this command is legitimate, it is frequently abused by malicious actors for data exfiltration or ransomware preparation. The execution was initiated by `wmiprvse.exe` and subsequently launched `**vssadmin.exe**`. No other instances of this command were found across other hosts or users within a 6-day timeframe, suggesting an isolated incident. Prior to this, user ' **frank.kolzig**' had multiple failed logon attempts from ' **WRK-SHASEK**' to ' **activedir.stackedpads.local**', interspersed with successful explicit credential logons via PowerShell and LSASS processes, some also involving ' **tim.smith**'.

### Match #2: Volume Shadow Copy Creation (`19231038-c0c7-4dad-a9b7-4a5cb5c14684`)

- **Verdict:** `TRUE_POSITIVE` (Confidence: `HIGH_CONFIDENCE`)
- **Composite Score:** **0.9798**
- **Semantic Vector Similarity:** `0.9783`
- **Entity Overlap Score:** `1.0000`
- **MITRE TTP Overlap:** `1.0000`
- **Flow Steps Overlap:** `1.0000`
- **Temporal Decay Factor:** `0.7481`

**Shared Entities:**
- `[HASH]` `bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527` — **VT Severity**: `SEVERITY_NONE`
- `[FILE]` `WmiPrvSE.exe` — No enrichment data available.
- `[HOST]` `activedir.stackedpads.local` — Host active in SIEM logs. (Identity details retrieved from Chronicle)
- `[IP]` `10.1.0.4` — No enrichment data available.
- `[FILE]` `cmd.exe` — No enrichment data available.
- `[USER]` `frank.kolzig` — **Identity**: Frank Kolzig (frank.kolzig@stackedpad.local)

- **Shared Techniques:** T1003.003
- **Shared Tactics:** TA0006

**Investigation Summary:**
> * A Volume Shadow Copy was created on the Active Directory server ' **activedir.stackedpads.local**' by user ' **frank.kolzig**'. This activity, initiated by 'wmiprvse.exe' and executed via ' **cmd.exe**', is often used by threat actors to extract sensitive data like NTDS.DIT.

* The execution of ' **cmd /c vssadmin create shadow /for=C:**' on the Active Directory server ' **activedir.stackedpads.local**' by user ' **frank.kolzig**' is highly suspicious and indicative of credential dumping. This activity was preceded by multiple failed login attempts for ' **frank.kolzig**' from ' **wrk-shasek.stackedpads.local**', immediately followed by successful explicit credential logons for the same user from ' **wrk-shasek.stackedpads.local**'. These explicit credential logons were associated with PowerShell execution on ' **wrk-shasek.stackedpads.local**' targeting ' **activedir.stackedpads.local**'. This pattern suggests a successful credential stuffing or brute-force attack against ' **frank.kolzig**'s account, leading to the compromise of the Active Directory server. The parent process 'wmiprvse.exe' for the suspicious command was launched by the SYSTEM account, further indicating a potential privilege escalation or abuse of legitimate system processes.

### Match #3: Volume Shadow Copy Creation (`a240eec6-cab1-4cef-ab2c-b3989abff745`)

- **Verdict:** `FALSE_POSITIVE` (Confidence: `HIGH_CONFIDENCE`)
- **Composite Score:** **0.9726**
- **Semantic Vector Similarity:** `0.9892`
- **Entity Overlap Score:** `1.0000`
- **MITRE TTP Overlap:** `1.0000`
- **Flow Steps Overlap:** `1.0000`
- **Temporal Decay Factor:** `0.5269`

**Shared Entities:**
- `[HASH]` `bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527` — **VT Severity**: `SEVERITY_NONE`
- `[FILE]` `WmiPrvSE.exe` — No enrichment data available.
- `[HOST]` `activedir.stackedpads.local` — Host active in SIEM logs. (Identity details retrieved from Chronicle)
- `[IP]` `10.1.0.4` — No enrichment data available.
- `[FILE]` `cmd.exe` — No enrichment data available.
- `[USER]` `frank.kolzig` — **Identity**: Frank Kolzig (frank.kolzig@stackedpad.local)

- **Shared Techniques:** T1003.003
- **Shared Tactics:** TA0006

**Investigation Summary:**
> * An alert was triggered for the creation of a Volume Shadow Copy on the Active Directory server ' **activedir.stackedpads.local**' by user ' **frank.kolzig**'. This activity is often associated with threat actors attempting to extract sensitive data like NTDS.DIT.

* The command `**cmd /c vssadmin create shadow /for=C:**` was executed on `**activedir.stackedpads.local**` by user `**frank.kolzig**`. This command is considered malicious and is frequently used by attackers for data manipulation or in preparation for ransomware. The process tree shows that `**cmd.exe**` was launched by `WmiPrvSE.exe`, which is a legitimate Windows process. The user `**frank.kolzig**` had elevated privileges during this activity and had multiple failed login attempts from `**WRK-SHASEK**` ( **10.1.0.50**) prior to a successful remote interactive logon.

### Match #4: Volume Shadow Copy Creation (`5f80038b-b849-4e9c-a369-2f6f756d247a`)

- **Verdict:** `FALSE_POSITIVE` (Confidence: `HIGH_CONFIDENCE`)
- **Composite Score:** **0.9704**
- **Semantic Vector Similarity:** `0.9903`
- **Entity Overlap Score:** `1.0000`
- **MITRE TTP Overlap:** `1.0000`
- **Flow Steps Overlap:** `0.8000`
- **Temporal Decay Factor:** `0.8756`

**Shared Entities:**
- `[HASH]` `bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527` — **VT Severity**: `SEVERITY_NONE`
- `[FILE]` `WmiPrvSE.exe` — No enrichment data available.
- `[HOST]` `activedir.stackedpads.local` — Host active in SIEM logs. (Identity details retrieved from Chronicle)
- `[IP]` `10.1.0.4` — No enrichment data available.
- `[FILE]` `cmd.exe` — No enrichment data available.
- `[USER]` `frank.kolzig` — **Identity**: Frank Kolzig (frank.kolzig@stackedpad.local)

- **Shared Techniques:** T1003.003
- **Shared Tactics:** TA0006

**Investigation Summary:**
> * A Volume Shadow Copy Creation event was detected on **activedir.stackedpads.local**, where user **frank.kolzig** initiated a command to create a shadow copy of drive C:. This activity is often associated with threat actors attempting to extract sensitive data like NTDS.DIT.

* The command line ' **cmd /c vssadmin create shadow /for=C:**' was executed on the host ' **activedir.stackedpads.local**' by user ' **frank.kolzig**'. This command is considered malicious and is a known precursor to ransomware attacks or data exfiltration. The execution was initiated by 'WmiPrvSE.exe', which was itself launched by 'svchost.exe'. While 'WmiPrvSE.exe' is a legitimate Windows process, its use to launch a malicious command is suspicious. Further investigation revealed that user ' **frank.kolzig**' had multiple successful logins to ' **activedir.stackedpads.local**' from ' **wrk-shasek.stackedpads.local**' ( **10.1.0.50**) via remote interactive and network logons, which were preceded by multiple failed logon attempts, suggesting a potential brute-force or password spraying attack. Additionally, explicit credential logons for ' **frank.kolzig**' were initiated by ' **tim.smith**' from ' **wrk-shasek.stackedpads.local**', some via PowerShell.

### Match #5: Volume Shadow Copy Creation (`4a166db4-fd04-4eb5-968d-d9e72cb357fe`)

- **Verdict:** `FALSE_POSITIVE` (Confidence: `HIGH_CONFIDENCE`)
- **Composite Score:** **0.9576**
- **Semantic Vector Similarity:** `0.9853`
- **Entity Overlap Score:** `1.0000`
- **MITRE TTP Overlap:** `1.0000`
- **Flow Steps Overlap:** `0.6667`
- **Temporal Decay Factor:** `0.9223`

**Shared Entities:**
- `[HASH]` `bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527` — **VT Severity**: `SEVERITY_NONE`
- `[FILE]` `WmiPrvSE.exe` — No enrichment data available.
- `[HOST]` `activedir.stackedpads.local` — Host active in SIEM logs. (Identity details retrieved from Chronicle)
- `[IP]` `10.1.0.4` — No enrichment data available.
- `[FILE]` `cmd.exe` — No enrichment data available.
- `[USER]` `frank.kolzig` — **Identity**: Frank Kolzig (frank.kolzig@stackedpad.local)

- **Shared Techniques:** T1003.003
- **Shared Tactics:** TA0006

**Investigation Summary:**
> * A Volume Shadow Copy was created on the host **activedir.stackedpads.local** ( **10.1.0.4**) by user **frank.kolzig**. This activity, initiated by `wmiprvse.exe` and executed via `**cmd.exe**` with the command `**cmd /c vssadmin create shadow /for=C:**`, is often associated with attempts to extract NTDS.DIT or the SYSTEM registry hive.

* The investigation revealed that the `vssadmin create shadow` command, while dual-use, was executed on a domain controller ( **activedir.stackedpads.local**) by user **frank.kolzig**. Prior to this, **frank.kolzig** had multiple failed login attempts from workstation **WRK-SHASEK** ( **10.1.0.50**), followed by a successful network logon with special privileges. Additionally, several explicit credential logons for **frank.kolzig** from **WRK-SHASEK** were observed, suggesting potential credential reuse or privilege escalation attempts. No other instances of this command were found across other hosts in the environment, indicating an isolated event. Registry modifications related to the Background Activity Moderator (BAM) service were observed for `**cmd.exe**` and `WmiPrvSE.exe`, which is normal for process execution tracking.
