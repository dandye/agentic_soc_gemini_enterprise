---
name: secops-wiz-cloud-security
license: Apache-2.0
description: >-
  Correlates Wiz posture and runtime findings with Google SecOps UDM telemetry
  and authors Chronicle YARA-L 2.0 (YL2) correlation rules.
---

# Wiz and Google SecOps Runbook

## Investigation, Hunting, and YARA-L 2.0 Workflow

1. **Case Triage to Wiz Context**: Query `list_cases`, `get_case`, and `udm_search` (`projectId`, `customerId`, `region`, `query`) across `principal.hostname`, `target.hostname`, `principal.ip`, `principal.user.email_addresses`, `security_result.threat_id`, and `security_result.category_details`. Pivot via Wiz `wiz_discover` and `wiz_execute` across `detections` (`list_detections`, `get_threat`), `vulnerabilities` (`list_vulnerability_findings`), `network_exposure` (`list_network_exposure`), `issues` (`list_issues`, `get_issue`), `iam_and_graph` (`list_service_account_paths`), and `ai_spm` (`list_ai_spm_findings`) to confirm runtime CVEs, process lineage, Dockerfile/VCS owners, and blast radius.
2. **Wiz Exposure Hunt and YARA-L 2.0 Authoring**: Sweep `udm_search` (`72h` -> `168h` across `WIZ_IO`, `GCP_CLOUDAUDIT`, `GCP_FIREWALL`, `GCP_DNS`). Never query external CTI on RFC 1918 IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or block signed OS LOLBins (`/usr/bin/python3`, `/usr/bin/curl`, `/usr/bin/java`, `rundll32.exe`, `wscript.exe`). Author multi-event **YARA-L 2.0 (YL2)** Chronicle SIEM UDM rules (distinct from standard file/payload YARA) to suppress unexploited `TOXIC_COMBINATION` noise while excluding benign `ci-deployer` and `terraform` activity.
3. **Benign Admin / CI-CD Override and Guarded Closure**: When Wiz (`RESOLVED` / `DAST_ATTACKER`) or `principal.user.email_addresses` indicates authorized `ci-deployer`, `terraform`, or scanner activity, confirm zero post-window C2 or IAM drift via `udm_search` before selecting `tune_detection` or `benign_or_inconclusive`.

## 4-Way Disposition Matrix

- **`escalate_incident`**: Corroborated compromise across >=2 sources -> contain host/account/external C2 (with operator confirmation) and post sync notes (`create_case_comment`, Wiz issue comment).
- **`contain_and_patch`**: Exploited internet-facing CVE without lateral movement -> isolate host or block external C2, patch image, and rotate keys.
- **`tune_detection`**: Verified `ci-deployer`, `terraform`, `DAST_ATTACKER` scan, or unexploited noise -> propose rule tuning and `create_case_comment`; zero containment.
- **`benign_or_inconclusive`**: Clean `168h` sweep and verified benign Wiz disposition -> document evidence and close case as `NOT_MALICIOUS` after operator confirmation.
