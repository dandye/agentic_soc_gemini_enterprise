---
name: asset_criticality_evaluation
description: Guidelines for classifying asset criticality tiers (Tier 0 Crown Jewels, Tier 1 Core Infra, Tier 2 Workstations) and blast radius impact.
---

# Asset Criticality Evaluation Skill

This skill defines standardized guidelines for evaluating enterprise asset criticality tiers, assessing blast radius impact, and prioritizing security incident response actions.

## 1. Asset Criticality Tier Framework

Enterprise assets are categorized into three primary criticality tiers based on their role in identity trust, data sensitivity, and operational disruption:

### Tier 0: Crown Jewels & Identity Trust Root
- **Definition**: Core identity, authentication, cryptographic, and mission-critical data assets whose compromise results in complete organizational compromise.
- **Representative Asset Types**:
  - **Identity & Directory Services**: Active Directory Domain Controllers (DCs), Entra ID Connect sync servers, Okta / PingFederate IdPs, Kerberos Key Distribution Centers (KDCs).
  - **Cryptographic & Key Management**: Hardware Security Modules (HSMs), Enterprise PKI / Root Certificate Authorities (CAs), HashiCorp Vault clusters, Cloud KMS master keys.
  - **Production Core Databases**: Enterprise ERP databases, production AlloyDB / Cloud Spanner clusters containing PII, PHI, financial records, or customer secrets.
  - **Cloud Organization Root Infrastructure**: GCP Organization root nodes, AWS Management Accounts, root IAM super-admin break-glass roles.
- **Incident Response Priority**: **P0 / Critical**. Immediate containment, host isolation, and executive SOC escalation required.

### Tier 1: Core Infrastructure & Business Applications
- **Definition**: Critical business systems, developer infrastructure, and network control planes that support business continuity or could facilitate pivoting to Tier 0.
- **Representative Asset Types**:
  - **CI/CD & Source Code Control**: GitHub Enterprise / GitLab servers, Jenkins / Cloud Build runners, artifact registries.
  - **Application Workloads**: Production GKE / Kubernetes clusters, API gateways, load balancers, customer-facing web services.
  - **Network & Perimeter Infrastructure**: Edge firewalls, VPN concentrators, bastion hosts, privileged jump boxes.
  - **Internal Corporate Services**: Messaging servers (Exchange, corporate Slack/Chat bridges), HR and payroll application servers.
- **Incident Response Priority**: **P1 / High**. Rapid investigation, credential revocation, and perimeter fencing.

### Tier 2: Workstations, End-User Devices & Peripheral Infrastructure
- **Definition**: End-user compute devices, staging environments, and non-sensitive peripheral hardware.
- **Representative Asset Types**:
  - **End-User Computing**: Corporate laptops, developer workstations, VDI desktop instances.
  - **Development & Staging**: Sandbox GCP projects, QA testing databases, staging clusters with synthetic data.
  - **Peripheral & IoT Devices**: Office printers, conference room VoIP systems, environmental IoT sensors.
- **Incident Response Priority**: **P2 / Medium** (unless identified as an active lateral movement bridge toward Tier 1/0).

---

## 2. Blast Radius Impact Assessment Methodology

When evaluating an asset under active investigation, calculate blast radius using the following three dimensions:

### A. Direct Compromise Impact
- Does the asset store, process, or transmit regulated sensitive data (PCI-DSS, HIPAA, GDPR, customer secrets)?
- What is the business continuity downtime cost if the asset is isolated or rendered unavailable?

### B. Privilege & Credential Escalation Vector
- **Cached Credentials**: Are Domain Admin, Cloud Admin, or service account credentials active or cached in memory on the machine (e.g. LSASS)?
  - *Rule*: A Tier 2 workstation running a Tier 0 administrator session must be escalated to **Tier 0 risk profile**.
- **Delegated IAM Roles**: Does the asset hold workload identity permissions allowing privilege escalation across cloud projects?

### C. Downstream Dependency & Lateral Reachability
- How many downstream assets are reachable via direct network routes or stored SSH/RDP connection profiles?
- Can the asset be used as a proxy/pivot into protected network enclaves (e.g. PCI DMZ, prod VPC)?

---

## 3. Integration with Asset Catalog (`query_asset_catalog`)

Leverage the `query_asset_catalog` tool to extract authoritative metadata from AlloyDB / Omnia:

1. **Exact Asset Lookup (`search_mode="exact_asset"`)**:
   - Query by exact hostname, IP address, or asset ID.
   - Extract `tier`, `business_unit`, `owner`, `data_classification`, and `environment`.

2. **Semantic Case History (`search_mode="semantic_case_history"`)**:
   - Query past security incident tickets to discover historical vulnerabilities, prior compromised states, and previous false-positive baselines.

3. **Hybrid Search with Tier Filtering (`search_mode="hybrid"`, `asset_tier_filter="Tier 0"`)**:
   - Locate adjacent assets in the same subnet or business group matching specific criticality requirements.

---

## 4. Decision Matrix for Response Actions

| Identified Asset Tier | Observed Attacker Activity | Recommended Response Action |
|:---|:---|:---|
| **Tier 0** | Any unauthorized access, anomaly, or credential access | Immediate network isolation, global credential revocation, emergency bridge invocation. |
| **Tier 1** | Remote code execution, beaconing, or unauthorized admin logons | Fencing network ingress/egress, terminating active sessions, forensic snapshot capture. |
| **Tier 2** | Commodity malware, phishing execution, initial payload drop | Endpoint isolation via EDR, host credential reset, memory dump collection. |
| **Tier 2 (Escalated)** | Tier 2 host with cached Tier 0 credentials or lateral path to DC | Treat as Tier 0 threat: isolate host, reset all cached credentials across the domain. |
