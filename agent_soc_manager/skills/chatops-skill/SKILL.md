---
name: chatops-skill
description: Enables the agent to communicate with human security analysts for notifications and high-stakes confirmations (Human-in-the-loop).
references:
 - https://developers.google.com/workspace/chat/design-interactive-card-dialog
---

### ChatOps and Human Interaction Implementation
You are equipped with the capability to send rich notifications and action requests to human security analysts via ChatOps (Google Chat / Webhooks). Use this skill when you need a human to perform a task, confirm a state-changing action, or stay informed about a critical event.

**Instructions:**
1. **Critical Actions (HITL):** Before performing any irreversible or high-risk state-changing actions (e.g., isolating a host, blocking a user account, or wiping a machine), you MUST propose the action to a human analyst for confirmation using the `request_human_confirmation` tool.
2. **Incident Notifications:** When you identify a confirmed CRITICAL or HIGH severity incident, immediately notify the human team using the `notify_human_incident` tool.
3. **Custom Alerts:** Use the `send_chatops_card` tool for general-purpose notifications or status reports that require a structured card format.
4. **Transparency:** When you send a notification or a request to a human, include this in your orchestrator synthesis (e.g., "I've requested a human confirmation for the host isolation action...").
5. **Human Context:** Always provide clear rationale and evidence when requesting human input, so the analyst has the necessary context to make a decision.

**Tools Summary:**
- **request_human_confirmation:** Propose a specific action with context for approval/denial (legacy flow).
- **notify_human_incident:** Alert the team to a confirmed incident with severity and IDs.
- **send_chatops_card:** Send any custom card by raw widget layout.
- **verify_user_travel:** Send an impossible travel confirmation card directly to a user.
- **request_triage_approval:** Send a pre-formatted approval card for host isolation or emergency patching.
- **deliver_report:** Send a card providing a secure download link for a finalized triage report.
- **generic_notification:** Dispatcher for any `ai_*` chatops card template by its Python filename.

### Example Card Layout Patterns
When using `send_chatops_card`, follow these modernized patterns for the `sections` argument to ensure a premium analyst experience:

**1. IOC Enrichment Layout (Columns + materialIcon)**
```json
[
  { "widgets": [
    { "columns": { "columnItems": [
      { "widgets": [ { "decoratedText": { "topLabel": "CrowdStrike", "text": "APT28 / Fancy Bear", "startIcon": { "materialIcon": { "name": "flag" } } } } ] },
      { "widgets": [ { "decoratedText": { "topLabel": "VirusTotal", "text": "45/70 Detections", "startIcon": { "materialIcon": { "name": "security" } } } } ] }
    ] } },
    { "buttonList": { "buttons": [{ "text": "Investigate History", "color": { "red": 0.1, "green": 0.5, "blue": 1.0 }, "onClick": { "openLink": { "url": "https://..." } } }] } }
  ]}
]
```

**2. Runtime / Threat Detection Layout (Grouped Metrics)**
```json
[
  { "widgets": [
    { "columns": { "columnItems": [
      { "widgets": [ { "decoratedText": { "topLabel": "Target Pod", "text": "auth-api-88x", "startIcon": { "materialIcon": { "name": "layers" } } } } ] },
      { "widgets": [ { "decoratedText": { "topLabel": "CPU Usage", "text": "100%", "startIcon": { "materialIcon": { "name": "speed" } } } } ] }
    ] } },
    { "textParagraph": { "text": "Cryptominer signatures identified. Action required to contain threat." } },
    { "buttonList": { "buttons": [
      { "text": "Kill & Redeploy", "color": { "red": 0.8, "green": 0, "blue": 0 }, "onClick": { "openLink": { "url": "https://..." } } },
      { "text": "Debug Console", "onClick": { "openLink": { "url": "https://..." } } }
    ]} }
  ]}
]
```

**3. User/Entity Context (Location side-by-side)**
```json
[
  { "widgets": [
    { "columns": { "columnItems": [
      { "widgets": [ { "decoratedText": { "topLabel": "Current Login", "text": "London, UK", "startIcon": { "materialIcon": { "name": "place" } } } } ] },
      { "widgets": [ { "decoratedText": { "topLabel": "Previous Login", "text": "New York, US", "startIcon": { "materialIcon": { "name": "place" } } } } ] }
    ] } },
    { "buttonList": { "buttons": [ { "text": "Require MFA", "color": { "red": 0, "green": 0.5, "blue": 1.0 }, "onClick": { "openLink": { "url": "https://..." } } } ] } }
  ]}
]
```

### Reference Scenarios for ChatOps
The following scenarios are pre-defined as high-value for human interaction. Use the tools indicated for each:

**Access & Identity (Use `request_human_confirmation`)**
- `ai_credential_reset_approval`: Request approval before forcing a password reset on a high-value account.
- `ai_privilege_access_v2`: Propose and approve privilege access requests using the newer V2 card format.
- `ai_privileged_session_recording`: Notify and request logic for initiating recording on a sensitive session.
- `ai_stale_account_cleanup`: Propose deletion of identified stale or dormant accounts.
- `ai_suspicious_login_location`: Request user/analyst confirmation for logins from new geo-locations.
- `ai_user_privilege_audit`: Request privilege review for users with excessive permissions.
- `impossible_travel_verification`: Request verification from the affected user regarding an impossible travel event.
- `temp_admin_request`: Propose and approve temporary administrative/break-glass access.
- `mfa_api_key_alert`: Notify and request MFA enforcement for vulnerable service keys.
- `ai_security_group_audit`: Propose modifications to firewall groups or IAM policies after a security audit.

**Containment & Remediation (Use `request_human_confirmation`)**
- `ai_brute_force_source_block`: Request approval to block an IP address at the firewall after brute force detection.
- `ai_data_exfiltration_block`: Request to block an egress point once exfiltration is suspected.
- `ai_firewall_bypass_request`: Request approval for a temporary firewall bypass rule.
- `ai_malicious_container_kill`: Request approval to terminate a compromised K8s pod or container.
- `ai_suspicious_process_kill`: Request approval before killing a process on a critical server.
- `ai_wipe_host_approval`: **MANDATORY HITL**: Never wipe a host without explicit human approval.
- `ai_data_exfiltration_block`: Request to block an egress point once exfiltration is suspected.
- `ai_malicious_domain_sinkhole`: Propose redirection of malicious domain traffic to a sinkhole.
- `host_isolation_approval`: Propose isolating an infected host from the network.
- `vulnerability_patch_approval`: Seek approval for applying emergency security patches to production systems. For testing/demos, use the **Ivanti Endpoint Manager (CVE-2026-1603)** example.

**Alerting & Intel (Use `notify_human_incident` / `send_chatops_card`)**
- `ai_threat_intel_sharing`: Use `send_chatops_card` to share new IOCs discovered during an investigation.
- `ai_compliance_violation_alert`: Notify humans of identified policy or compliance drifts.
- `ai_dns_exfiltration_detection`: Notify humans of anomalous DNS patterns indicative of tunneling.
- `ai_forensic_image_approval`: Request permission to take a forensic disk/memory image.
- `ai_threat_hunt_hypothesis`: Present a new threat hunting hypothesis to human analysts for feedback.
- `brute_force_alert`: Notification to the team of a detected brute force attack.
- `impossible_travel_alert`: Notification of a potential impossible travel login event.
- `ioc_enrichment_card`: Visual card showing multi-vendor intelligence for an IP, Domain, or Hash.
- `malware_sandbox_report`: Summary of automated sandbox analysis (static and dynamic behavior).
- `phishing_report_summary`: Overview of user-reported phishing attempts and identified risk.
- `ai_canary_token_deployment`: Propose the deployment of honeytokens/canaries in sensitive environments.
- `shadow_it_discovery`: Alert on newly discovered unmanaged cloud resources or applications.

**Operational Workflow (Use `send_chatops_card` / `request_human_confirmation`)**
- `ai_draft_comms_review`: Propose a draft email/notification for a human to review before sending.
- `ai_playbook_selection`: Ask the human which strategy to prioritize if multiple playbooks apply.
- `ai_incident_summary_confirm`: Request a human to review your final incident summary before closure.
- `ai_incident_closure_confirm`: Final sign-off required from an analyst before officially closing an incident.
- `ai_incident_retrospective_request`: Trigger a post-mortem or retrospective task after a significant incident.
- `ai_network_scan_approval`: Request approval before initiating an active network vulnerability scan.
- `ai_sensitive_log_access`: Request approval for a security analyst to access highly sensitive logs.
- `bulk_deletion_verification`: Require human dual-control for any bulk deletion of logs or records.
- `ai_false_positive_tuning`: Propose logic changes to detection rules to reduce noise.
- `ai_user_interview_request`: Ask an analyst to interview a user to confirm suspicious (but potentially benign) activity.
- `ai_data_classification_request`: Request a human to classify sensitive data found in an unconventional location.
- `ai_vulnerability_revalidation`: Request a human to manually verify that a reported vulnerability has been fixed.
- `forensics_evidence_ready`: Notify the team that requested forensic evidence collection has finished.
