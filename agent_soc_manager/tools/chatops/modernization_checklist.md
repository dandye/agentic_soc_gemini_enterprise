# ChatOps Card Modernization Checklist

This document tracks the migration of legacy Google Chat cards to the new **Secure Action Pattern** (HMAC Signing + Agent Engine Integration).

## Core Integration Status
- [x] Secure Utility (`security.py`)
- [x] Webhook Handler (`webhook_handler.py` / Cloud Run)
- [x] Card Client Context Support (`card_client.py`)
- [x] ADK Tool Integration (`chatops_tools.py`)

---

## AI Analysts (Pre-fixed with `ai_`)
These have been updated using the automated `fix_templates.py` script.

- [x] `ai_brute_force_source_block.py`
- [x] `ai_canary_token_deployment.py`
- [x] `ai_compliance_violation_alert.py`
- [x] `ai_credential_reset_approval.py`
- [x] `ai_data_classification_request.py`
- [x] `ai_data_exfiltration_block.py`
- [x] `ai_dns_exfiltration_detection.py`
- [x] `ai_draft_comms_review.py`
- [x] `ai_false_positive_tuning.py`
- [x] `ai_firewall_bypass_request.py`
- [x] `ai_forensic_image_approval.py`
- [x] `ai_incident_closure_confirm.py`
- [x] `ai_incident_retrospective_request.py`
- [x] `ai_incident_summary_confirm.py`
- [x] `ai_malicious_container_kill.py`
- [x] `ai_malicious_domain_sinkhole.py`
- [x] `ai_network_scan_approval.py`
- [x] `ai_playbook_selection.py`
- [x] `ai_privilege_access_v2.py`
- [x] `ai_privileged_session_recording.py`
- [x] `ai_security_group_audit.py`
- [x] `ai_sensitive_log_access.py`
- [x] `ai_stale_account_cleanup.py`
- [x] `ai_suspicious_login_location.py`
- [x] `ai_suspicious_process_kill.py`
- [x] `ai_threat_hunt_hypothesis.py`
- [x] `ai_threat_intel_sharing.py`
- [x] `ai_user_interview_request.py`
- [x] `ai_user_privilege_audit.py`
- [x] `ai_vulnerability_revalidation.py`
- [x] `ai_wipe_host_approval.py`

---

## Legacy/Operational Cards (Action Required)
These do not have the `ai_` prefix and need manual review for modernization.

- [X] `brute_force_alert.py`
- [X] `bulk_deletion_verification.py`
- [X] `forensics_evidence_ready.py`
- [X] `host_isolation_approval.py`
- [X] `impossible_travel_alert.py`
- [X] `ioc_enrichment_card.py`
- [X] `malware_sandbox_report.py`
- [X] `mfa_api_key_alert.py`
- [X] `phishing_report_summary.py`
- [X] `shadow_it_discovery.py`
- [X] `temp_admin_request.py`
- [X] `vulnerability_patch_approval.py`

---

## Instructions for Migration
To modernize a card, ensure the `get_card` function accepts:
1. `session_id`: `str`
2. `agent_engine_id`: `str`
3. `user_id`: `str` (Optional, defaults to `None`)

Then generate signed URLs for all interactive buttons:
```python
from card_client import generate_action_url

button_url = generate_action_url(
    "Your Action Name",
    session_id=session_id,
    agent_engine_id=agent_engine_id,
    user_id=user_id
)
```
