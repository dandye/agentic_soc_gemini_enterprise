---
type: "Documentation"
title: "Multi-Modal Similarity Scoring Profiles for AlloyDB"
description: "Comprehensive guide to multi-modal similarity profiles in AlloyDB, defining mathematical weight sets, operational use cases (threat hunting, compromise pivot, false positive triage, semantic discovery), and usage workflows."
resource: "file:///Users/dandye/Projects/agentic_soc_agentspace__worktrees/harvest_detection_reports/docs/similarity_profiles.md"
timestamp: "2026-07-30T19:54:00Z"
provenance:
  source_type: "python_generated"
  source_tool: "Antigravity"
  timestamp: "2026-07-30T19:54:00Z"
---

# Multi-Modal Similarity Scoring Profiles for AlloyDB

## 1. Overview & Operational Rationale

In a Security Operations Center (SOC), the concept of "investigation similarity" depends heavily on the analyst's operational objective:

- **When hunting a threat actor or campaign**: The analyst searches for identical tradecraft (MITRE ATT&CK techniques, script blocks, command syntax) deployed across *multiple or disparate hosts and accounts*. Exact host/user entity matches are down-weighted because an adversary moves across different infrastructure.
- **When investigating an active compromise**: The analyst needs to understand the *blast radius and lateral movement* around a specific compromised host, account, or IP address. Here, entity overlap and tight temporal proximity (activity clustered within minutes, hours, or days) are paramount.
- **When triaging repetitive alerts**: The analyst checks whether an incoming alert is a recurring false positive on benign administrative software (e.g. MSBuild, scheduled tasks, authorized scripts). Exact binary hash, script path, host, and detection rule matches take precedence.
- **When exploring novel or unknown attacks**: The analyst relies on dense semantic vector similarity to uncover conceptually similar behavior described in analyst summaries and execution logs, regardless of specific entity names.

To address these distinct operational needs, the **AlloyDB Multi-Modal Similarity Engine** provides **parameterized scoring profiles**.

---

## 2. Similarity Dimensions & Mathematical Formulation

The composite similarity score $S_{total}(A, B) \in [0.0, 1.0]$ between target investigation $A$ and candidate report $B$ is computed as:

$$S_{total}(A, B) = w_s \cdot S_{semantic}(A, B) + w_e \cdot S_{entity}(A, B) + w_t \cdot S_{ttp}(A, B) + w_f \cdot S_{flow}(A, B) + w_{time} \cdot S_{time}(A, B)$$

Where $\sum w_i = 1.0$.

### Sub-Score Definitions

1. **Semantic Vector Cosine Similarity ($S_{semantic}$)**:
   - Dense vector cosine similarity computed via `pgvector` on 768-dimensional `text-embedding-004` embeddings:
   $$S_{semantic}(A, B) = 1 - (embedding_A \Leftrightarrow embedding_B)$$

2. **Weighted Entity Overlap ($S_{entity}$)**:
   - Inverse Document Frequency (IDF) weighted Jaccard similarity across shared entities (hosts, users, IPs, file paths, hashes):
   $$IDF(e) = \ln\left(\frac{N_{total} + 1}{N(e) + 1}\right) + 1$$
   $$S_{entity}(A, B) = \frac{\sum_{e \in E_A \cap E_B} IDF(e)}{\sum_{e \in E_A \cup E_B} IDF(e)}$$

3. **Behavioral MITRE TTP Overlap ($S_{ttp}$)**:
   - Hierarchical Jaccard overlap on MITRE ATT&CK techniques and tactics:
   $$S_{ttp}(A, B) = 0.70 \cdot \frac{|Tech_A \cap Tech_B|}{|Tech_A \cup Tech_B|} + 0.30 \cdot \frac{|Tac_A \cap Tac_B|}{|Tac_A \cup Tac_B|}$$

4. **Investigation Flow Similarity ($S_{flow}$)**:
   - Jaccard similarity over investigation step types and query fingerprints from `investigation_steps` JSONB.

5. **Temporal Campaign Decay ($S_{time}$)**:
   - Exponential time-decay function based on the elapsed time between reports ($\tau = 14 \text{ days}$):
   $$S_{time}(A, B) = \exp\left(-\frac{|\Delta t|}{14 \text{ days}}\right)$$

---

## 3. Parameterized Scoring Profiles

| Profile Key | Profile Name | Primary Objective | Semantic ($w_s$) | Entity ($w_e$) | TTP ($w_t$) | Flow ($w_f$) | Time ($w_{time}$) |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `balanced` | **Balanced Alert Triage** | Standard multi-modal blend across all 5 dimensions for routine triage and verdict verification. | **35%** | **30%** | **20%** | **10%** | **5%** |
| `threat-hunt` | **Threat Actor & Campaign Hunting** | Biases for shared MITRE TTPs and semantic attack tradecraft across multiple or disparate hosts. | **35%** | **5%** | **45%** | **10%** | **5%** |
| `compromise-pivot` | **Compromise Blast Radius & Lateral Movement** | Biases heavily for compromised hosts/users/IPs and temporal proximity to detect lateral movement. | **15%** | **45%** | **5%** | **5%** | **30%** |
| `false-positive` | **False Positive Triage & Precedent** | Biases for exact entity matches, binary hashes, and matching detection rules to identify recurring benign noise. | **20%** | **40%** | **25%** | **10%** | **5%** |
| `semantic` | **Semantic & Behavioral Concept Discovery** | Biases for dense vector cosine similarity to discover conceptually related attacks regardless of specific entities. | **60%** | **5%** | **15%** | **15%** | **5%** |

---

## 4. Operational Scenarios & Profile Selection Guide

### Scenario 1: Threat Hunting (`--profile threat-hunt`)
- **Analyst Intent**: "We observed PowerShell downloading an encoded payload (`T1059.001`). Did this same technique or payload appear on any other workstations in the organization?"
- **Why this profile**: Host and username overlap is down-weighted to 5%, while MITRE techniques (45%) and semantic tradecraft (35%) dominate the scoring. Reports on different machines using the same attack technique surface at the top of the candidate list.

### Scenario 2: Compromise Blast Radius & Lateral Movement (`--profile compromise-pivot`)
- **Analyst Intent**: "Workstation `wins-d19` had a credential dumping alert. What other alerts, processes, or network events occurred on or around `wins-d19` and user `lisawalker` around that same time?"
- **Why this profile**: Entity overlap (45%) and temporal proximity (30%) receive 75% of the total weight. Events involving the same host or user that occurred within hours or days are strongly prioritized to uncover the full incident blast radius.

### Scenario 3: Alert Triage & False-Positive Deduplication (`--profile false-positive`)
- **Analyst Intent**: "An alert fired for `MSBuildShell Utility Abuse`. Is this an authorized developer activity or an established false positive?"
- **Why this profile**: Entity weight (40%) and detection rule overlap (25%) ensure that past investigations involving the same file name, hash, and detection rule are retrieved to check previous resolution notes and verdict precedents.

### Scenario 4: Behavioral Concept Discovery (`--profile semantic`)
- **Analyst Intent**: "Find any past incidents where an attacker used living-off-the-land binaries (LOLBins) to bypass allowlists."
- **Why this profile**: Semantic vector cosine similarity receives 60% weight, allowing the engine to match related attack behaviors across entirely different detection rules and host environments.

---

## 5. Usage Examples

### Listing Available Profiles

```bash
# Via Unified Python CLI
python manage.py alloydb profiles

# Via Justfile
just alloydb-profiles
```

### Running Similarity Searches with Profiles

```bash
# Threat hunting profile (MITRE TTP & Tradecraft bias)
python manage.py alloydb find-similar 10fbb728-6739-420f-91a3-4f5fcdad1cbc --profile threat-hunt --limit 5

# Compromise blast radius profile (Host & Temporal bias)
python manage.py alloydb find-similar 00351f48-2646-4450-ae2d-6fefeae32f2d --profile compromise-pivot --limit 5 --explain

# False positive triage profile
python manage.py alloydb find-similar 03cbf404-9914-4d40-be82-f97c15a676be --profile false-positive --limit 3

# Using custom weight overrides on top of a profile
python manage.py alloydb find-similar 00351f48-2646-4450-ae2d-6fefeae32f2d --profile balanced --entity-weight 0.50 --time-weight 0.20
```

### Via Justfile

```bash
# Threat hunt profile
just alloydb-find-similar 10fbb728-6739-420f-91a3-4f5fcdad1cbc 5 threat-hunt

# Compromise pivot profile
just alloydb-find-similar 00351f48-2646-4450-ae2d-6fefeae32f2d 5 compromise-pivot
```

### Via AI SOC Agent Tools

Within `agent_soc_manager/agent.py`, the `find_similar_alloydb_investigations` tool supports the `profile` argument:

```python
# The agent can invoke:
find_similar_alloydb_investigations(
    investigation_id="10fbb728-6739-420f-91a3-4f5fcdad1cbc",
    limit=5,
    profile="threat-hunt",  # or 'compromise-pivot', 'false-positive', 'semantic', 'balanced'
)
```
