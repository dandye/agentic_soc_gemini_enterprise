---
name: mitre_ttp_mapping
description: MITRE ATT&CK Enterprise Matrix mapping heuristics for correlating graph behaviors with RAG CTI dossiers.
---

# MITRE ATT&CK TTP Mapping Skill

This skill provides heuristics and systematic mapping guidelines for translating observed security graph behaviors, host telemetry, and investigation indicators to the MITRE ATT&CK Enterprise Matrix, and correlating them with Cyber Threat Intelligence (CTI) dossiers and Incident Response Playbooks (IRPs).

## 1. MITRE ATT&CK Enterprise Tactics Framework

The Enterprise ATT&CK matrix structures adversary behaviors into 14 distinct tactical objectives:

1. **Initial Access (TA0001)**: Vectors used to gain entry into the corporate network (e.g., T1566 Phishing, T1190 Exploit Public-Facing Application, T1078 Valid Accounts).
2. **Execution (TA0002)**: Execution of adversary-controlled code on local or remote systems (e.g., T1059 Command & Scripting Interpreter, T1047 WMI, T1569 System Services).
3. **Persistence (TA0003)**: Maintaining access across restarts, credential changes, or network interruptions (e.g., T1053 Scheduled Task/Job, T1136 Create Account, T1098 Account Manipulation).
4. **Privilege Escalation (TA0004)**: Gaining higher-level permissions (e.g., SYSTEM, root, Domain Admin) (e.g., T1068 Exploitation for Privilege Escalation, T1548 Abuse Elevation Control Mechanism).
5. **Defense Evasion (TA0005)**: Techniques used to avoid detection by security tools (e.g., T1070 Indicator Removal, T1562 Impair Defenses, T1036 Masquerading).
6. **Credential Access (TA0006)**: Stealing credentials such as usernames and passwords or tickets (e.g., T1003 OS Credential Dumping, T1110 Brute Force, T1558 Steal or Forge Kerberos Tickets).
7. **Discovery (TA0007)**: Gaining knowledge of the internal network, users, and system configuration (e.g., T1087 Account Discovery, T1018 Remote System Discovery, T1082 System Information Discovery).
8. **Lateral Movement (TA0008)**: Pivoting between systems on the network (e.g., T1021 Remote Services, T1550 Use Alternate Authentication Material).
9. **Collection (TA0009)**: Gathering sensitive target data (e.g., T1560 Archive Collected Data, T1005 Data from Local System, T1114 Email Collection).
10. **Command and Control (TA0011)**: Establishing communication channels with controlled infrastructure (e.g., T1071 Application Layer Protocol, T1573 Encrypted Channel).
11. **Exfiltration (TA0010)**: Stealing and egressing data from the enterprise (e.g., T1048 Exfiltration Over Alternative Protocol, T1567 Exfiltration Over Web Service).
12. **Impact (TA0040)**: Disrupting availability or integrity of systems and business data (e.g., T1486 Data Encrypted for Impact, T1489 Service Stop).

---

## 2. Graph Behavior to TTP Mapping Heuristics

Translate observed Neo4j operational security graph relationships and traversal paths into specific ATT&CK techniques:

| Observed Graph Pattern | Graph Query / Relationship | Mapped MITRE TTPs |
|:---|:---|:---|
| **Multi-Hop Lateral Pivot to DC** | `MATCH p = shortestPath((src)-[*1..3]-(dst:DomainController))` | **T1021.002** (SMB/Windows Admin Shares), **T1021.001** (Remote Desktop Protocol), **T1078.002** (Domain Accounts) |
| **Credential Blast Radius Expansion** | `MATCH (u:User)-[:CAN_ACCESS\|ADMIN_ON*1..3]->(target)` | **T1078** (Valid Accounts), **T1098** (Account Manipulation), **T1069** (Permission Groups Discovery) |
| **User Session on Multiple Endpoints** | `MATCH (u:User)-[:LOGGED_IN]->(h:Host)` where `count(h) > 5` | **T1078** (Valid Accounts), **T1110.003** (Password Spraying), **T1550** (Pass the Hash / Pass the Ticket) |
| **Direct Access to Tier 0 Assets** | `MATCH (h:Host)-[:CONNECTS_TO]->(d:DomainController)` | **T1018** (Remote System Discovery), **T1021** (Remote Services) |
| **New Service / Process Execution on Host** | `(h:Host)-[:EXECUTED]->(p:Process)` | **T1059** (Command and Scripting Interpreter), **T1569.002** (Service Execution) |

---

## 3. RAG CTI Dossier & Playbook Correlation

Correlate identified TTP IDs and threat behaviors with enterprise CTI dossiers and Incident Response Playbooks using `retrieve_enterprise_docs`:

### A. Threat Actor Dossier Retrieval
- Query the enterprise RAG corpus using mapped TTP codes:
  - Example: `"CTI threat actor profile using T1078 Valid Accounts and T1021 SMB lateral movement Scattered Spider"`
- Analyze threat actor attribution, known command infrastructure patterns, and preferred secondary persistence mechanisms.

### B. Incident Response Playbook (IRP) Lookup
- Retrieve specific mitigation and containment playbooks matching identified techniques:
  - Example: `"Incident response playbook containment steps for T1003 OS Credential Dumping and T1558 Kerberoasting"`
- Extract prescribed containment actions (e.g., krbtgt password rotation, LSASS protection enforcement, account lockouts).

---

## 4. ATT&CK Evidence Synthesis Template

When preparing investigative summaries, structure TTP mappings in the following format:

```markdown
### MITRE ATT&CK TTP Alignment
- **Tactic**: Lateral Movement (TA0008) / Credential Access (TA0006)
- **Techniques**:
  - `T1021.002` - SMB/Windows Admin Shares (Pivoting from WS-104 to SRV-APP01 via svc-backup)
  - `T1078.002` - Domain Accounts (Compromised domain user credentials used across 4 hosts)
  - `T1003.001` - OS Credential Dumping: LSASS Memory (Detected on WS-104)
- **Graph Evidence**: Shortest path WS-104 -> SRV-APP01 -> DC01 (2 hops).
- **Correlated CTI / Playbook**: Playbook IRP-04 (Domain Compromise & Credential Revocation).
```
