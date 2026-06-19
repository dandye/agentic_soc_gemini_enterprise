---
type: "Evaluation Report"
title: "Evaluation Report: CTI Research Workflows"
description: "Systematic prompt evaluation scorecard for CTI Research Workflows on commit a35fff5"
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/evalsets/eval_runs/report_cti_research_20260618T212142Z_a35fff5.md"
timestamp: "2026-06-18T21:21:42.259789Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-18T21:21:42.259804Z"
---
# Evaluation Report: CTI Research Workflows

> [!NOTE]
> This evaluation was executed programmatically against the live deployed Reasoning Engine in the cloud.

## Executive Summary

* **Evaluation Set:** CTI Research Workflows
* **Overall Score:** **51.0%**
* **Status:** FAIL

---

## Scorecard

| Status | Case Name | Score | Tool Trajectory | Key Assertions Passed |
|--------|-----------|-------|-----------------|----------------------|
| [WARNING] | **Threat Actor Analysis - APT29** | 50.0% | `retrieve_agentic_soc_runbooks`, `search_threat_actors`, `get_entities_related_to_a_collection`, `get_collection_report`, `get_entities_related_to_a_collection`, `get_collection_mitre_tree`, `get_security_alerts`, `search_security_events`, `save_report_artifact` | keyword_matching, includes_confidence_level, includes_source_attribution, maps_to_mitre_attack |
| [WARNING] | **IOC Reputation Check - IP Address** | 71.4% | `retrieve_agentic_soc_runbooks`, `get_ip_address_report`, `get_entities_related_to_an_ip_address`, `get_entities_related_to_an_ip_address`, `get_file_report`, `get_file_behavior_summary` | tool_trajectory, keyword_matching, tool_name_mentioned, provides_verdict, includes_context |
| [FAIL] | **IOC Analysis - File Hash** | 16.7% | *None* | keyword_matching |
| [WARNING] | **Malware Family Research - Emotet** | 50.0% | `retrieve_agentic_soc_runbooks`, `search_malware_families`, `get_collection_mitre_tree`, `get_ioc_matches`, `search_security_rules`, `get_threat_intel`, `save_report_artifact` | keyword_matching, includes_behavioral_analysis, maps_to_mitre_attack |
| [WARNING] | **Domain Reputation Check** | 66.7% | `retrieve_agentic_soc_runbooks`, `get_domain_report`, `lookup_entity`, `get_collection_report`, `get_collection_report` | tool_trajectory, keyword_matching, provides_verdict, definitive_answer |

---

## Detailed Case Runs

### Case 1: Threat Actor Analysis - APT29 (threat_actor_apt29)

* **User Query:** "Analyze the APT29 threat actor. What are their recent campaigns and TTPs?"
* **Score:** **50.0%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/7203198091455889408/playground?session=421363985686724608&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `search_threat_actors`
* Called tool: `get_entities_related_to_a_collection`
* Called tool: `get_collection_report`
* Called tool: `get_entities_related_to_a_collection`
* Called tool: `get_collection_mitre_tree`
* Called tool: `get_security_alerts`
* Called tool: `search_security_events`
* Called tool: `save_report_artifact`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [ ] **tool_trajectory**
* [X] **keyword_matching**
* [ ] **specialist_attribution**
* [ ] **mentions_cti_researcher**
* [X] **includes_confidence_level**
* [X] **includes_source_attribution**
* [X] **maps_to_mitre_attack**

#### Model Final Response
```markdown
I have conducted a thorough Cyber Threat Intelligence (CTI) investigation into the **APT29** threat actor (also known as *Midnight Blizzard*, *Cozy Bear*, *Nobelium*, *BlueBravo*, and *Cloaked Ursa*). Below is a high-level summary of my findings, focusing on their recent campaigns, custom toolset ecosystem, and strategic Tactics, Techniques, and Procedures (TTPs) mapped to the MITRE ATT&CK framework.

I have compiled my full threat research and diagnostic findings into a formal CTI report. You can access the complete briefing document here:
### **[APT29 CTI Threat Briefing Report](https://storage.cloud.google.com/secops-demo-env-adk-artifacts-20260318/7203198091455889408/eval_user/421363985686724608/APT29_Threat_Intelligence_Briefing.md/0)**

---

### Key Intelligence Findings Summary

#### 1. Threat Actor Identity & Suspected Sub-Clusters
APT29 is highly assessed to be operated by the **Russian Foreign Intelligence Service (SVR)**. They are characterized by their extreme operational discipline, high operational security (OPSEC), stealthy persistence, and aggressiveness when attempting to evade remediation. My research highlighted several prominent threat clusters associated with them:
*   **UNC5837** (aka *Midnight Blizzard*): Distributed malicious Remote Desktop Protocol (RDP) files disguised as Amazon Web Services (AWS) or Microsoft tech support to target European governments and militaries.
*   **UNC6293**: Targeted prominent academics and critics of Russia, using spear-phishing to harvest App-Specific Passwords (ASPs) for Google accounts.
*   **UNC3524**: Extremely stealthy group operating since late 2019, leveraging a large IoT device botnet and exhibiting overlaps with both APT28 and APT29.

---

#### 2. Recent & High-Profile Campaigns (2021–2024+)
*   **European Government RDP Phishing Campaign (Late 2024 | CAMP.24.065)**: Targeted European diplomatic and military agencies using compromised email accounts to deliver malicious RDP files. Executing the RDP file initiated outbound connections via RDP's *RemoteApp* feature, downloading a custom payload (`DESKPIRATE`) to compromise the host.
*   **JetBrains TeamCity Supply Chain Compromise (Late 2023 | GLOBAL.23.005)**: Active, widespread exploitation of **CVE-2023-42793** (RCE in on-premises JetBrains TeamCity server appliances) to backdoor software build pipelines and compromise software supply chains.
*   **IoT Camera Proxy & Email Harvesting (2021–2022 | CAMP.22.007)**: Compromised internet-exposed video conferencing cameras as proxy servers to mask C2 traffic. Deployed `QUIETEXIT` (a Go-based SSH tunneler modified from Dropbear) to mine emails of employees working on corporate development and M&A transactions.
*   **Cloud Provider Pivots & Golden SAML (2021 | CAMP.21.024)**: Compromised Cloud Service Providers (CSPs) to pivot into downstream customer networks, stealing Active Directory Federation Services (AD FS) signing keys to perform **Golden SAML** attacks, completely bypassing Multi-Factor Authentication (MFA) to exfiltrate mailboxes.

---

#### 3. Malware Ecosystem & Custom Tools
*   **`DESKPIRATE`**: Windows Remote Desktop Protocol (RDP) config-file downloader exploiting RemoteApp functionality to load payloads.
*   **`COOKIESNATCH`**: A custom browser credential-stealing utility. It executes as a JavaScript payload in browser processes to exfiltrate valid session cookies, allowing the actor to bypass MFA on hijacked sessions.
*   **`QUIETEXIT`**: A Go-based tunneling tool modified from Dropbear SSH used to maintain secure, obfuscated outbound tunnels.
*   **`SIXPLUS` (WellMess) & `SEVENMINUS` (WellMail)**: Sophisticated lightweight Go backdoors communicating over HTTP, HTTPS, or DNS, famously utilized in the espionage campaigns targeting global COVID-19 vaccine research.
*   **`ROOTSAW` (HTML Smuggler)**: An HTML-based dropper masquerading as diplomatic invitations to initiate in-memory payload delivery of next-stage downloaders like `BEATDROP`, `BOOMMIC`, and `FANCYBEAT`.

---

#### 4. Strategic TTP Mapping (MITRE ATT&CK)

| Tactic | Key Techniques Deployed by APT29 | Defensive Detection & Mitigations |
| :--- | :--- | :--- |
| **Initial Access** | Phishing via Spearphishing Attachment/Link (**T1566**), Supply Chain Compromise (**T1195**), Exploit Public-Facing Application (**T1190**), Trusted Relationship CSP Pivots (**T1199**). | Strict ingress filtering, immediate pipeline patching, and MFA hardening. |
| **Execution** | Command/Scripting Interpreter (**T1059**) via PowerShell/cmd/JS, DLL Side-Loading (**T1574.002**), Service Execution (**T1569.002**). | Enforce Application Whitelisting (WDAC/AppLocker) and block execution of unnecessary LOLBins. |
| **Persistence / PrivEsc** | Registry Run Keys (**T1547.001**), Scheduled Tasks (**T1053.005**), Trust Modification (**T1484.002**) via Golden SAML, Cloud Accounts (**T1078.004**). | Audit of AD FS signing certificates, restriction of cloud tenant administrators, and endpoint persistence monitoring. |
| **Defense Evasion** | Impair Defenses (**T1562.001**) by disabling EDRs, Timestomping (**T1070.006**), HTML Smuggling (**T1027.006**), lolbin proxy execution via Rundll32/Mshta (**T1218**). | Restrict LOLBins, deploy behavioral EDR protections, and alert on system log clearing (`wevtutil`). |
| **Credential Access** | OS Credential Dumping (**T1003**) via LSASS/DCSync/NTDS, Steal Web Session Cookie (**T1539**) via `COOKIESNATCH`, Password Spraying (**T1110.003**). | Enforce FIDO2-compliant hardware keys, restrict LSASS memory access, and disable legacy auth. |
| **Collection** | Remote Email Collection (**T1114.002**) (Exchange/M365), Data from Information Repositories (**T1213**) (SharePoint), Cloud Storage (**T1530**). | Alert on anomalous mailbox delegation modifications (`Add-MailboxPermission`) and silent forwarding rules. |
| **Command & Control** | Non-Standard Ports (**T1571**), Protocol Tunneling (**T1572**) over SSH/RDP, Multi-hop Proxies (**T1090.003**) using compromised IoT/routers. | Monitor outbound RDP connections to external IPs, restrict port 3389 outbound, and establish proxy reputation checks. |

---

### Internal Log Verification (Chronicle SIEM)
I cross-referenced these threat indicators within our own Chronicle SIEM log repository over the last 168 hours to check for organizational exposure:
1.  **Direct Threat Searches**: No active security events or threat detections returned hits for signature strings such as `DESKPIRATE`, `BEATDROP`, `COOKIESNATCH`, `ROOTSAW`, `FANCYBEAT`, or `CEELOADER`.
2.  **Related Campaign Indicators**: I identified an open low-severity alert regarding **"Stolen Images Evidence Campaign-related LNK File Creation and DLL execution"** (associated with case `b99d3ed6-d25c-45e2-a809-68e50a55ef71`). Historically, Russian-nexus actors (including APT29/Cozy Bear) have deployed identical pretexts (using LNK files and DLL side-loading disguised as copyright infringement warnings) to infect victims. This case is currently under close observation by our triage team.

*For complete details, please download and review the full threat briefing saved in our secure cloud repository linked above.*I am going to synthesize all the researched threat intelligence regarding APT29, their associated clusters, their prominent recent campaigns, their custom malware ecosystem, and their comprehensive MITRE ATT&CK framework mapping. I will then save this detailed threat briefing as a markdown artifact (`APT29_Threat_Intelligence_Briefing.md`).I will perform a search in our security events for any sightings of specific malware and custom tools associated with APT29 campaigns, such as "DESKPIRATE" or "BEATDROP". This allows me to verify if there's any active indicators or execution matching these profiles in our log repository.I will check our Chronicle SIEM alerts to see if there have been any triggers or detections related to "APT29", "Midnight Blizzard", or "Cozy Bear" in our internal logs, demonstrating local threat correlation.I will now retrieve the MITRE ATT&CK framework mapping (tactics and techniques) for APT29 (`threat-actor--7a39953e-0dae-569a-9d49-d52a4a8865b1`) to detail their specific tactical tradecraft.I will retrieve the malware families associated with APT29 to identify their custom toolsets and malware.I will retrieve the report details for campaign `campaign--a53dfa82-6f1c-52c4-80a8-7c4ef9f5181b` which is associated with UNC5837 (aka Midnight Blizzard, a confirmed alias of APT29) to understand their more recent activities and techniques (late 2024 / recent periods).I have successfully identified the core Google Threat Intelligence collection for the APT29 threat actor: `threat-actor--7a39953e-0dae-569a-9d49-d52a4a8865b1`.

I also found key threat actor clusters associated with APT29, specifically:
- **UNC5837** (aka Midnight Blizzard/APT29), which targets European government/military agencies using fake AWS/Microsoft tech support RDP files.
- **UNC6293**, a Russian espionage threat cluster targeting academics and critics of Russia using App-Specific Password (ASP) credential theft.
- **UNC3524**, a highly stealthy espionage cluster with low-malware footprint and an IoT device botnet.

Now, I will query the relationships of the primary APT29 threat actor collection to uncover its linked campaigns, malware families, and specific attack techniques.I will first search for the APT29 threat actor in Google Threat Intelligence using the `search_threat_actors` tool to identify its unique collection ID and get an initial set of descriptors.I am going to retrieve relevant runbooks and standard operating procedures from our Agentic SOC repository to guide my cyber threat intelligence research on the APT29 threat actor. This ensures I follow the correct structure, best practices, and templates for threat actor profiling and TTP mapping.
```

---
### Case 2: IOC Reputation Check - IP Address (ioc_reputation_ip)

* **User Query:** "Check the reputation of IP address 198.51.100.42"
* **Score:** **71.4%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/7203198091455889408/playground?session=2780124290522021888&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `get_ip_address_report`
* Called tool: `get_entities_related_to_an_ip_address`
* Called tool: `get_entities_related_to_an_ip_address`
* Called tool: `get_file_report`
* Called tool: `get_file_behavior_summary`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [X] **tool_trajectory**
* [X] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **tool_name_mentioned**
* [X] **provides_verdict**
* [X] **includes_context**

#### Model Final Response
```markdown
The communicating file `windows_update_service.exe` (SHA256: `209de4e3f85276a6a875c5eedebf9d820d59445b0248d715b380e103f60253fc`) contacted `198.51.100.42`, as well as `150.171.22.17` and `52.111.229.48`.
It also contacted domains that masquerade as legitimate update infrastructure:
- `c2.malicious-update.com`
- `update.windows-patch.net`

I will now query the file behavior summary for this malicious file using `get_file_behavior_summary` to understand its execution characteristics, registry changes, process spawns, and sandbox detection.I have found very significant indicators associated with this IP address:
The associated URLs represent classical malicious patterns:
- Phishing logins: `http://198.51.100.42/customer/verify/login.html` and `http://198.51.100.42/phish/login.html`
- Malware payload hosting: `http://198.51.100.42/payload.ps1`, `http://198.51.100.42/payload.exe`, and `http://198.51.100.42/downloads/payload.exe`
- Command & Control / Stealer Admin Panel: `http://198.51.100.42/gate.php` and `http://198.51.100.42:1337/stealer/panel/login` (likely an infostealer admin interface)

To further enrich this threat intelligence, I will query a file report for one of the communicating files, starting with `209de4e3f85276a6a875c5eedebf9d820d59445b0248d715b380e103f60253fc`, to identify the malware family.I have identified five communicating files associated with this IP address:
1. `209de4e3f85276a6a875c5eedebf9d820d59445b0248d715b380e103f60253fc`
2. `354b29859105e13fe446be5d24c82a0e744cfbde132c243bf882073511d46b49`
3. `367af53a60e0681d0efdb4b32643c6a13496dc42a453a2dc59cfa3f671ae11f7`
4. `45db88874cca5a0e9b1ac80b41d52ad3101762f4d28fdc9515778945d898aaaa`
5. `6022be5e9ae7fb483c3542e11518d34bcb0c7e14b8a70d92a484a3feee9276bb`

Next, I will query URLs related to this IP address using `get_entities_related_to_an_ip_address`. This will help us determine if any malicious web resources or C2 endpoints have resolved to this IP address.I notice that while the IP address itself has a direct detection score of 0 (no threat engines reporting it as malicious), its threat severity metadata includes `has_bad_communicating_files_high: true` and `has_bad_communicating_files_medium: true`. Additionally, the WHOIS data indicates that this IP falls within the **198.51.100.0/24** range (TEST-NET-1), which is reserved by the IETF in RFC 5737 for documentation and sample configurations and should never appear on live network configurations.

To understand why there are bad communicating files and gather deeper threat intelligence, I will query relationships associated with this IP address (specifically `communicating_files` and `urls`) using `get_entities_related_to_an_ip_address`. This aligns with the "Deep Dive IOC Analysis Runbook".I will execute the first step of the "Atomic Runbook: Get IP Address Reputation from GTI" (`RB-ATOM-IP-001`) by calling `get_ip_address_report` for the IP address `198.51.100.42` using the Google Threat Intelligence (GTI) MCP server. This will give us the reputation and analysis metadata for this IP address.I will retrieve any relevant Agentic SOC runbooks to see if there is a specific standard operating procedure or template for checking an IP address or IOC reputation.
```

---
### Case 3: IOC Analysis - File Hash (ioc_file_hash)

* **User Query:** "Analyze this file hash: 44d88612fea8a8f36de82e1278abb02f"
* **Score:** **16.7%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/7203198091455889408/playground?session=3149419459966402560&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
*No tools called.*

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [ ] **tool_trajectory**
* [X] **keyword_matching**
* [ ] **specialist_attribution**
* [ ] **tool_name_mentioned**
* [ ] **hash_type_identified**

#### Model Final Response
```markdown

```

---
### Case 4: Malware Family Research - Emotet (malware_family_emotet)

* **User Query:** "Research the Emotet malware family. What are its TTPs and how does it spread?"
* **Score:** **50.0%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/7203198091455889408/playground?session=5335917079054778368&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `search_malware_families`
* Called tool: `get_collection_mitre_tree`
* Called tool: `get_ioc_matches`
* Called tool: `search_security_rules`
* Called tool: `get_threat_intel`
* Called tool: `save_report_artifact`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [ ] **tool_trajectory**
* [X] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **includes_behavioral_analysis**
* [X] **maps_to_mitre_attack**

#### Model Final Response
```markdown
I have completed in-depth Cyber Threat Intelligence (CTI) research on the **Emotet** malware family. To ensure a structured investigation, I followed a strict threat profiling workflow:

1. **Intake and Methodology Validation**: I called `retrieve_agentic_soc_runbooks` to align my research steps with standardized Threat Intelligence profiling runbooks.
2. **Threat Intelligence Enrichment (GTI)**: I queried the Google Threat Intelligence platform using `search_malware_families` to identify Emotet's primary intelligence collections (`malware--f1151a22-9d9c-589d-90ad-1157ea90033e` and `malpedia_win_emotet`).
3. **Behavioral & TTP Mapping**: I called `get_collection_mitre_tree` to fetch the complete MITRE ATT&CK tactic/technique mapping and analyzed signature rules from sandbox executions.
4. **Exposure Verification (SIEM)**: I checked our internal security posture and log history using `get_ioc_matches` and `search_security_rules` to confirm whether our environment had active detections or historical matches. (None were currently found, indicating no active infection).
5. **Documentation & Artifact Saving**: I formalized this compiled research into a comprehensive threat intelligence report and used `save_report_artifact` to save the markdown file.

The detailed Threat Intelligence Profile has been successfully saved. **You can access and download the full document here:**
👉 **[EMOTET_Threat_Intelligence_Profile.md](https://storage.cloud.google.com/secops-demo-env-adk-artifacts-20260318/7203198091455889408/eval_user/5335917079054778368/EMOTET_Threat_Intelligence_Profile.md/0)**

Below is a detailed summary of my research, detailing Emotet's nature, how it spreads, its MITRE ATT&CK techniques, and a preserved list of 100% of the discovered indicators of compromise (IOCs).

---

## 1. What is Emotet?
**Emotet** (also known as **Heodo** or **Geodo**) is a modular, polymorphic downloader written in C/C++. First discovered in 2014 as a financial banking trojan targeting credentials, it has evolved into a global **"Infrastructure-as-a-Service" (IaaS)** delivery vehicle.

Emotet's primary purpose today is to establish initial access and deploy high-severity secondary payloads on behalf of other threat actors (such as TA542/Mummy Spider). Payloads delivered via Emotet historically include **TrickBot, QakBot, IcedID, and Cobalt Strike**, which frequently culminate in ransomware attacks by gangs like **Ryuk** and **Conti**.

Although global law enforcement coordinated a major takedown of its infrastructure in January 2021 (Operation LadyBird), Emotet was rebuilt and resurrected by November 2021. Researchers track its infrastructure in active distribution campaigns divided into separate botnet clusters called **"epochs"** (Epoch 1 through Epoch 5).

---

## 2. How Emotet Spreads (Infection Vectors)
Emotet employs highly automated, volume-driven social engineering campaigns as its primary spreading mechanism.

### A. Phishing & Email Thread Hijacking
The primary distribution channel is mass spam and spearphishing email campaigns (**T1566**).
*   **Outlook Email Harvesting**: Once a machine is infected, Emotet executes credential-stealing and email-scraping modules. It harvests contact lists, email sender addresses, and email body contents.
*   **Thread Hijacking**: Emotet uses this harvested content to insert itself into actual, ongoing email conversations. It sends phishing emails appearing to be "replies" in legitimate threads to the victim's contacts. Because the email thread is real and trusted, recipients are highly likely to download and execute the payload.

### B. Malicious Lures & Downloader Formats
The phishing emails contain links or attachments that initiate the multi-stage delivery process:
*   **Malicious Office Macros**: Historically, attachments consisted of Word (`.doc`) or Excel (`.xls`/`.xlsm`) files with heavily obfuscated VBA macros (**T1564.007**).
*   **Template Injection (T1221)**: Poses as benign Office files but fetches remote, malicious templates containing exploits or macros.
*   **Windows Shortcut (.LNK) Files**: Following Microsoft's default block on internet-sourced VBA macros, Emotet shifted to `.lnk` shortcut files. When opened, the shortcut executes an obfuscated, Base64-encoded PowerShell command (**T1059.001**) to fetch and run the payload DLL.
*   **OneNote Attachments**: Emotet has distributed `.one` files with embedded scripts (VBScript or JS) that execute when clicked under the guise of fake "Double-Click to View Document" templates.
*   **Mark-of-the-Web (MOTW) Bypass (T1553.005)**: Phishing lures often wrap payloads inside container formats (ZIP, ISO, VHD). When mounted or extracted, the internal files frequently bypass NTFS Alternate Data Stream Zone Identifier tags (MOTW), bypassing SmartScreen blocklists.

### C. Self-Propagation
*   **Wi-Fi Spreader**: Emotet has historically used a specialized Wi-Fi Spreader module (`Trojan.EmotetWifiSpreader`) to scan nearby wireless access points, brute-force their WPA/WEP security keys, connect, and spread to other endpoints on that wireless network.

---

## 3. Core Tactics, Techniques, and Procedures (TTPs)
Mapping Emotet's behaviors directly to the **MITRE ATT&CK** framework reveals a highly evasive execution chain:

*   **Initial Access**: **Phishing: Spearphishing Attachment (T1566.001)** and **Phishing: Spearphishing Link (T1566.002)** using fake invoices, shipping notices, or thread-hijacked emails.
*   **Execution**:
    *   **Command and Scripting Interpreter (T1059)**: PowerShell (`T1059.001`) and Visual Basic (`T1059.005`) are heavily utilized to download and unpack the payload.
    *   **System Binary Proxy Execution**: Uses **Rundll32 (T1218.011)** or **Regsvr32 (T1218.010)** to execute its malicious DLL payloads, mimicking standard Windows operations.
    *   **Native API (T1106)**: Directly interacts with Windows kernel APIs (e.g., `VirtualAlloc`, `NtDelayExecution`) to bypass user-land hooks of security tools.
*   **Persistence**:
    *   **Registry Run Keys (T1547.001)**: Writes keys to local paths like `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
    *   **Windows Service (T1543.003)**: Installs itself as a persistent local system service to run automatically on system boot.
    *   **Scheduled Task/Job (T1053.005)**: Schedules Windows tasks to ensure recurring execution.
*   **Defense Evasion**:
    *   **Obfuscated Files or Information (T1027)**: Payload code is heavily obfuscated.
    *   **Software Packing (T1027.002)**: Emotet DLLs are packed (e.g., UPX, MPRESS) to hide static signatures.
    *   **Dynamic API Resolution (T1027.007)**: Bypasses static analysis and the Import Address Table (IAT) by resolving API functions during runtime using custom name hashing (often ROR13).
    *   **Process Injection (T1055)** and **Process Hollowing (T1055.012)**: Injects decrypted payloads into legitimate host processes (such as `svchost.exe`, `explorer.exe`) to hide execution.
    *   **Virtualization/Sandbox Evasion (T1497)**: Performs time-based delays (`T1497.003`), checks for debuggers (`T1622`), monitors mouse cursor movements, and queries CPU/RAM limits to detect sandbox environments before disengaging.
    *   **Timestomping (T1070.006)**: Modifies file metadata and creation times to mimic legitimate system binaries.
*   **Discovery**:
    *   **System Owner/User Discovery (T1033)** and **Process Discovery (T1057)**: Profiles the target victim's usernames, privilege levels, and active security processes.
    *   **System Language Discovery (T1614.001)**: Queries the user keyboard layout and system language. **Emotet has hardcoded guardrails to terminate execution immediately if Russian, Ukrainian, or Cyrillic languages are detected.**
*   **Credential Access & Collection**:
    *   **Keylogging (T1056.001)** and **Clipboard Data (T1115)**: Steals text inputs and clipboard buffers.
    *   **Credentials from Password Stores (T1555)** / **Web Browsers (T1555.003)**: Accesses local password stores and decrypts browser-saved login credentials.
*   **Command and Control (C2)**:
    *   **Application Layer Protocol (T1071.001 / T1071.003)**: Communicates with C2 backends over HTTP/HTTPS, or SMTP/Mail protocols.
    *   **Encrypted Channel (T1573)**: Traffic is encrypted using Elliptic-Curve Cryptography (ECC) for key exchanges and RC4/AES for stream encryption.
    *   **Non-Standard Port (T1571)**: Connects over unusual port configurations (e.g., `8080`, `7080`, `8443`) to bypass standard web filters.

---

## 4. Preserved Indicator of Compromise (IOC) List
*In accordance with security preservation standards, below is 100% of the explicitly extracted indicators discovered during our intelligence collection.*

### A. IP Addresses (Command & Control / Hosting)
*   `54.37.228.122`
*   `213.176.36.147` (Port `8080`)
*   `84.21.179.51`
*   `87.106.136.232` (Port `8080`)
*   `67.205.85.243` (Port `8080`)
*   `91.121.54.71` (Port `8080`)
*   `173.94.215.84` (Port `80`)
*   `137.119.36.33` (Port `80`)
*   `46.29.183.211` (Port `8080`)
*   `110.93.196.197` (Port `80`)
*   `87.118.70.45` (Port `8080`)
*   `104.236.137.72` (Port `8080`)
*   `212.51.142.238` (Port `8080`)
*   `189.226.151.198` (Port `7080`)
*   `116.202.234.183` (Port `8080`)
*   `181.129.96.162` (Port `8080`)
*   `217.199.160.224` (Port `7080`)
*   `197.254.221.174` (Port `80`)
*   `60.108.144.104` (Port `443`)
*   `37.139.21.175` (Port `8080`)
*   `75.188.107.174` (Port `80`)

### B. Domains (Delivery & C2 infrastructure)
*   `kupondigital.stormapp.in`
*   `farschid.de`
*   `trainingchallenges.xyz`
*   `choicepestcontrol.xyz`
*   `unada.us`
*   `roaming.svc.cloud.microsoft`
*   `nexus.officeapps.live.com`
*   `odc.officeapps.live.com`
*   `officeclient.microsoft.com`
*   `r13.c.lencr.org`

### C. URLs (Payload Download & C2 endpoints)
*   `https://kupondigital.stormapp.in/mido-nicu/9NSRCfZB/`
*   `http://farschid.de/verkaufsberater_service/uADJw/`
*   `http://7gallery.com/bbeauty_download/HpOjrjExAb6PY/`
*   `http://e5web.com.br/wp-content/4TPDUppb/`
*   `https://dwwmaster.com/wp-content/tfNs1crHYZd6F5/`
*   `http://clubmanager.net.ar/prueba/7llR9qWfQdqlnImliUE/`
*   `http://r13.c.lencr.org/29.crl`
*   `http://213.176.36.147:8080/C4M7Wl8XrbqLEBZM/`
*   `http://84.21.179.51/kp4pCPfiz9mGG6R9/`
*   `http://213.176.36.147:8080/g1vI/SHtvj/jJP7KYlfMH5s/mSoyjZVDQRpyJ/rMSml0jxn45dRC9fqLI/`
*   `http://87.106.136.232:8080/PG6TZIE/xU6Oi9HlJS0ynepD/5iqrKL3YWbrFpj/eHNVq5ovhvRNZSR/sVke/MWeE4LhvS3/`
*   `http://67.205.85.243:8080/R1BEbfqg/5Gdg3s/7s6U7twH8/`
*   `http://91.121.54.71:8080/QD2FSZit/`
*   `http://173.94.215.84:80/b68ljAlWnUFtK/mXiRfLHm/IoJXM48xGCH4/wpwhryJSFi0/fHDfXyZI31KXxsDQT/9n4gDoIfuQ/`
*   `http://137.119.36.33:80/TEgawyTh4qamMmq3Hhl/Z0ufkarqZ8yWB/`

### D. Preserved Filenames, Directories & Paths
*   `library.dll`
*   `attachment.dll`
*   `hexalistof.exe`
*   `msdmo.exe`
*   `deployipmi.exe`
*   `createadigital.exe`
*   `WpPortingLibrary.exe`
*   `mprmsg.exe`
*   `groupwow.exe`
*   `footernetsh.exe`
*   `httpapi.exe`
*   `wksprtPS` (Directory)
*   `kbdhebl3` (Directory)
*   `Tojeqpfb` (Directory)
*   `treeeditor.exe`
*   `164268d9950b137d7a23f09eb213b9e9fedb7d4a025b5f1075e3929c.dll`
*   `message_0211.xls`
*   `lista_6.xlsm`
*   `bank transfer copy ach.xlsm`
*   `form.xlsm`
*   `sNhYaMMPOU.ps1` (PowerShell Script)
*   `LqwxbPrZJz.LMo` (Dropped Binary)
*   `readme.dll`
*   `TaskMgr.pdb` (PDB Path context)
*   `ClipRgn.pdb` (PDB Path context)
*   `Clacium.pdb` (PDB Path context)
*   `TabDrives.pdb` (PDB Path context)
*   `PreviewCtrl.pdb` (PDB Path context)

---

## 5. Security Recommendations

### A. Detection Engineering
*   **Monitor System Proxy Binaries**: Create high-fidelity rules in Chronicle SIEM for `rundll32.exe` and `regsvr32.exe` launching DLLs from volatile, writable user directories (like `%Temp%`, `%AppData%`, or `%LocalAppData%`).
*   **Track Office Network Connections**: Trigger alerts when Microsoft Office executables (`excel.exe`, `winword.exe`) establish socket connections to remote IP addresses on non-standard HTTP ports (such as `8080`, `7080`, or `8443`).

### B. Prevention & Host Hardening
*   **Disable Office Macros Globally**: Apply group policies (GPOs) to block macros in internet-sourced documents.
*   **LNK Association Restriction**: Block shortcut files (`.lnk`) or scripts (`.vbs`, `.js`) received via Email Security Gateways, or disable direct user-execution of scripts via default file association modification.
*   **Implement Application Control / AppLocker**: Prevent executing unsigned binaries from the `%userprofile%` structure.I will now compile all my findings, including the detailed technical analysis of Emotet, its distribution mechanisms, and its comprehensive MITRE ATT&CK mapping. I will save this synthesized intelligence as a formal Threat Intelligence Profile artifact named `EMOTET_Threat_Intelligence_Profile.md` using the `save_report_artifact` tool.I will query Google Gemini Threat Intel inside our Chronicle platform using `get_threat_intel` to gather the latest Google-curated intelligence insights regarding Emotet's active distribution campaigns and typical payloads.I will search our configured security detection rules in Chronicle SIEM using `search_security_rules` to see if we have active rules specifically targeting Emotet-related activity (such as its C2 check-ins or DLL loading patterns).I will check our Chronicle SIEM instance using the `get_ioc_matches` tool to see if any Indicators of Compromise (IOCs) from threat intelligence feeds have matched historical log data in our enterprise environment. This is a crucial step to check for any organizational exposure to Emotet.I will retrieve the MITRE ATT&CK tactics and techniques associated with the primary Google Threat Intelligence (GTI) Emotet collection (`malware--f1151a22-9d9c-589d-90ad-1157ea90033e`) to get a comprehensive view of its TTPs.I will search for the "Emotet" malware family on the Google Threat Intelligence (GTI) platform to locate its primary intelligence collection and metadata.I will begin by searching for relevant runbooks or guidelines related to investigating a threat collection, malware family, or conducting threat intelligence research. This will ensure my profiling of the Emotet malware family is structured and thorough.
```

---
### Case 5: Domain Reputation Check (domain_reputation)

* **User Query:** "Is the domain malicious.com safe or malicious?"
* **Score:** **66.7%**
* **GEAP Playground:** [Open Interactive Session in GCP Console](https://console.cloud.google.com/agent-platform/runtimes/locations/us-central1/agent-engines/7203198091455889408/playground?session=8371343227902492672&project=secops-demo-env&userId=eval_user)

#### Tool Trajectory
* Called tool: `retrieve_agentic_soc_runbooks`
* Called tool: `get_domain_report`
* Called tool: `lookup_entity`
* Called tool: `get_collection_report`
* Called tool: `get_collection_report`

#### Heuristic Success Checklist
* [ ] **specialist_attribution**
* [X] **tool_trajectory**
* [X] **keyword_matching**
* [ ] **specialist_attribution**
* [X] **provides_verdict**
* [X] **definitive_answer**

#### Model Final Response
```markdown
The first collection `5f2578719e9edd5a7ac6b54ae2bb8c5d0b8f03f4a74815758187e666ed106d10` is a generic crowdsourced "Raw Items Collection" that was auto-generated to parse raw security indicator lists.

Let's query the second collection ID: `76ee1ca0816ffe6e2bd9f04ee464353f6bd04999e944be45dddc541e7f159171` to see if it provides more specific attribution, such as a known threat campaign or actor.I see that `malicious.com` has **0 events and 0 alerts** in our Chronicle SIEM logs, which means the internal network currently has no exposure or traffic to this domain.

To better profile this threat, I will retrieve the collection reports for the associated Threat Intelligence Collections. This will help us identify what campaigns, malware, or threat actors have used `malicious.com` in their operations. I will start by querying the first collection ID: `5f2578719e9edd5a7ac6b54ae2bb8c5d0b8f03f4a74815758187e666ed106d10`.I have obtained the domain report for `malicious.com` from Google Threat Intelligence.

Here are the key points from the initial reputation check:
- **Reputation Score:** -64 (strongly negative, indicating maliciousness).
- **VirusTotal Detection Stats:** 13 security vendors flag this domain as **malicious**, 31 undetected, and 47 harmless.
- **Threat Severity Data:** It is associated with a "bad collection" and has "bad communicating files" of high and medium severity.
- **Registrar:** GoDaddy.com, LLC.
- **Creation Date:** August 7, 1998.
- **Associated GTI Collections:**
  - `5f2578719e9edd5a7ac6b54ae2bb8c5d0b8f03f4a74815758187e666ed106d10`
  - `76ee1ca0816ffe6e2bd9f04ee464353f6bd04999e944be45dddc541e7f159171`
  - `6baab70afd2d982213e92f603f74e63406e85b0a499a5fe35b50bca296ef9ab9`

Next, I will call `lookup_entity` in Chronicle SIEM for `malicious.com` to see if there is any historical log presence of this domain in our environment. I will also query the collection details for the associated GTI collections to understand what campaign, threat actor, or malware family this domain is linked to.I have retrieved the runbooks for basic and deep-dive IOC analysis. To evaluate whether `malicious.com` is safe or malicious, I will perform the following actions:
1. Call `get_domain_report` from `gti-mcp` to retrieve threat intelligence details, reputation, classification, and metadata for `malicious.com`.
2. Call `lookup_entity` from `secops-mcp` (Chronicle SIEM) to determine if this domain has historically appeared in our environment's security logs, indicating internal exposure.

Let's execute these steps.I am beginning my investigation into the domain `malicious.com` to determine whether it is safe or malicious.

First, I will retrieve our security runbooks to see if there is an established standard operating procedure or investigation template for evaluating domain indicators and performing Cyber Threat Intelligence (CTI) research.
```

---
