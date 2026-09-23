---
name: incident_memory_correlation
description: Methodologies for correlating current indicators with cross-session investigation memory notes and active hypotheses.
---

# Incident Memory Correlation Skill

This skill provides methodologies for tracking volatile investigation notes, recording containment actions, and correlating active indicators with cross-session investigation memory and historical cases.

## 1. Investigation Memory Architecture

During an active security investigation, analysts and automated agents uncover transient clues, form hypotheses, and execute containment operations. The Incident Memory system persists these observations across agent turns and cross-session handoffs.

### Memory Storage Layers
1. **ADK Session State Memory**:
   - Stores in-flight hypothesis notes within the active ADK session context (`session.state["investigation_memory"]`).
   - Ensures memory is maintained across multi-turn reasoning chains.
2. **Persistent Historical Memory**:
   - Integrates with historical incident memory stores to correlate fresh IOCs with past investigation findings, threat actor campaigns, and repeated compromised assets.

---

## 2. Structured Investigation Tagging Taxonomy

To facilitate rapid retrieval and semantic correlation, tag all notes using the following standard categories:

| Tag | Purpose & Description | Example Notes |
|:---|:---|:---|
| `credential_spray` | Multi-account authentication attempts, Kerberoasting, anomalous NTLM logins, password spraying. | `"Observed 45 failed NTLM auth attempts on DC01 originating from 10.0.4.15 within 2 minutes."` |
| `lateral_movement` | Observed pivot hops between endpoints via SMB, WinRM, SSH, WMI, or RDP. | `"Workstation WS-104 initiated outbound SMB sessions to file server FS-01 using compromised svc-backup account."` |
| `persistence` | Modifications to auto-runs, scheduled tasks, cron jobs, registry keys, or newly created backdoor accounts. | `"Discovered scheduled task 'SystemUpdateCheck' running powershell.exe hidden beacon every 30 minutes on SRV-APP02."` |
| `data_exfiltration` | High-volume outbound data transfers, archive compression (7z/rar), staging in temporary directories, cloud storage API calls. | `"Staging archive /tmp/archive_2026.tar.gz created and uploaded via curl to external IP 198.51.100.44."` |
| `c2` | Command and control communications, recurring beaconing intervals, dynamic DNS queries, Cobalt Strike malleable profiles. | `"Process svchost.exe (PID 4412) establishing TLS connection to unknown external host update.evil-c2.net on port 8443."` |
| `containment` | Active mitigation and containment actions executed by SOC analysts or playbooks. | `"Host WS-104 isolated via CrowdStrike EDR; active Kerberos TGT tickets invalidated for user jdoe."` |
| `general` | Contextual entity information, user role confirmation, business justification notes, or false-positive notes. | `"User confirmed to be on PTO; logon activity from Singapore IP considered anomalous."` |

---

## 3. Indicator Correlation & Hypothesis Testing Lifecycle

When investigating multi-stage incidents, follow this iterative correlation loop:

```
[ New Indicator / Alert ]
         │
         ▼
[ 1. Query Existing Memory ] ──▶ Check if entity or IOC has prior notes (query_investigation_memory)
         │
         ▼
[ 2. Formulate Hypothesis ] ──▶ Combine alert context + graph topology + historical memory
         │
         ▼
[ 3. Record Note / Tag ] ───▶ Persist new finding with appropriate tag (add_investigation_note)
         │
         ▼
[ 4. Verify & Contain ] ────▶ Log containment action with tag="containment"
```

### Correlation Workflows

1. **Entity Linking**:
   - Normalize entity identifiers before query: lowercased hostnames (strip domain if needed), IP addresses, email addresses/usernames, SHA256 hashes.
   - Query memory by entity:
     ```python
     await query_investigation_memory(entity="ws-104.corp.local")
     ```

2. **Semantic Keyword & Lifecycle Filtering**:
   - Correlate across multiple related entities using semantic terms or tags:
     ```python
     await query_investigation_memory(query="powershell beacon", tag="c2")
     ```

3. **Containment State Verification**:
   - Before executing containment, query memory with `tag="containment"` to verify whether the host or account was previously quarantined, preventing duplicate or conflicting actions.

---

## 4. Integration with Memory Tools

- **`add_investigation_note(entity: str, note: str, tag: str = "general", ctx: Optional[Any] = None)`**:
  - Record findings immediately upon discovering evidence.
  - Keep notes clear, concise, timestamped (automatic), and actionable.
- **`query_investigation_memory(entity: Optional[str], query: Optional[str], tag: Optional[str], max_results: int = 10, ctx: Optional[Any] = None)`**:
  - Retrieve relevant observations sorted chronologically (most recent first).
