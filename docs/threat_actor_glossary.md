---
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T20:19:00Z"
---
# Design Proposal: Threat Actor Alias Resolution via Knowledge Catalog Glossary

This document outlines the architectural design and implementation plan for using Google Cloud's **Knowledge Catalog Glossaries** to natively resolve threat actor aliases across our Security Operations (SOC) Multi-Agent System.

---

## 1. The Threat Intel Naming Problem

Threat actor groups are tracked under disparate names by different cybersecurity vendors and intelligence agencies. For example, the Russian state-sponsored group **Cozy Bear** is also tracked as:
* **APT29** (Chronicle / Mandiant / MITRE)
* **Midnight Blizzard** (Microsoft / GEAP Grounding)
* **Nobelium** (Legacy Microsoft)
* **CozyDuke** (F-Secure)
* **UNC2452** (FireEye tracker)

When an analyst or AI agent queries our security corpus for `"Midnight Blizzard"`, a traditional exact-match or simple keyword search will fail to return reports that only mention `"APT29"`.

To solve this, we must build a **semantic alias resolution layer** that translates vendor-specific actor names to a single canonical term before executing search queries.

---

## 2. Natively Resolving Synonyms via Knowledge Catalog

Rather than implementing custom synonym-expansion dictionaries in our Python application code, we can leverage the native **Glossary** and **Term** capabilities of Google Cloud's Knowledge Catalog:

```
       [User / Agent Search] "Midnight Blizzard"
                             │
                             ▼
     ┌──────────────────────────────────────────────┐
     │          Knowledge Catalog Glossary          │
     │  Resolves "Midnight Blizzard" ──► "APT29"    │
     └──────────────────────────────────────────────┘
                             │
                             ▼
       [OKF Grounding Corpus Search] "APT29"
                             │
                             ▼
      [Results Returned] Reports containing "APT29"
        or any synonym, fully correlated!
```

### Key Architectural Benefits:
* **Decoupled Business Logic:** Synonym mapping is offloaded to the Google Cloud platform layer, leaving our agent code simple, stateless, and focused on core triage logic.
* **Alias-Aware Search:** Gemini Enterprise (GemEnt) and GEAP groundings automatically leverage the Knowledge Catalog Glossary. Queries using *any* alias will natively return assets tagged with the canonical term.
* **Dynamic Updates without Code Deployments:** New threat actor aliases discovered by threat intelligence can be synced to the glossary terms in real-time, making all downstream agent applications instantly aware without rebuilding indexes or redeploying code.

---

## 3. Glossary Data Model

We will define a unified SOC Glossary (`secops-threat-intel`) in the Knowledge Catalog containing terms representing major threat actors:

### Term Structure:
* **Canonical Name (Term ID):** `APT29`
* **Display Name:** `APT29 (Cozy Bear)`
* **Description:** `Russian state-sponsored cyber espionage group active since at least 2008, associated with the Foreign Intelligence Service (SVR).`
* **Synonyms / Aliases:** `["Cozy Bear", "Midnight Blizzard", "Nobelium", "CozyDuke", "UNC2452", "Office Monkeys"]`
* **Classification / Tags:** `intel/threat-actor`

---

## 4. Implementation Plan for `manage_glossary.py`

We will create a unified management CLI **`installation_scripts/manage_glossary.py`** to programmatically interact with the Google Cloud Dataplex / Knowledge Catalog Glossary APIs.

### Command-Line Interface (Typer-based):
1. **`python manage.py glossary create-catalog`**
   * Initializes the root Glossary (`secops-threat-intel`) in the designated GCP project and location.
2. **`python manage.py glossary sync-cti`**
   * Queries Google Threat Intelligence (GTI) and local threat actor mappings to automatically compile threat actor profiles, creating or updating Glossary Terms and their synonyms in the catalog.
3. **`python manage.py glossary list`**
   * Displays all active terms, descriptions, and alias mappings in the glossary.

### Class Blueprint (`manage_glossary.py`):
```python
from google.cloud import dataplex_v1

class GlossaryManager:
    def __init__(self, project_id: str, location: str):
        self.project_id = project_id
        self.location = location
        self.client = dataplex_v1.CatalogServiceClient()

    def create_glossary(self, glossary_id: str, display_name: str):
        """Creates the root Glossary resource in Knowledge Catalog."""
        pass

    def upsert_term(self, glossary_id: str, term_id: str, display_name: str, description: str, synonyms: list[str]):
        """Creates or updates a specific Threat Actor Term with its aliases."""
        pass
```
