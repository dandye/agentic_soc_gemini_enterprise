---
type: "Troubleshooting"
title: "Troubleshooting Guide"
description: "This section outlines common errors encountered during local development, database connection setups, and cloud deployments, along with."
resource: "docs/troubleshooting.md"
timestamp: "2026-08-01T16:24:01Z"
provenance:
  source_type: "generative_ai"
  source_tool: "Antigravity"
  timestamp: "2026-06-16T15:30:00Z"
---
# Troubleshooting & FAQs

This section outlines common errors encountered during local development, database connection setups, and cloud deployments, along with their resolutions.

## 1. Elasticsearch Connection & Authentication Errors

### Error: `401 security_exception: missing authentication credentials for REST request`
**Cause:** Your GCE Elasticsearch instance has security enabled (basic authentication), but the credentials are missing or incorrect in your `.env` file.
**Resolution:**
1. Open your `.env` file and verify that `ELASTICSEARCH_USER=elastic` is set.
2. Confirm that `ELASTICSEARCH_PASSWORD` matches the password configured on your VM.
3. Run `just elastic-info` to test the authenticated connection.

### Error: `ConnectionRefusedError: [Errno 61] Connection refused`
**Cause:** The Elasticsearch server is either offline or blocked by a firewall.
**Resolution:**
1. SSH into your GCE VM and verify that the Elasticsearch service is active:
   ```bash
   sudo systemctl status elasticsearch
   ```
2. Confirm that your GCP firewall allows inbound TCP traffic on port `9200` from your development IP.

---

## 2. Neo4j Connection Issues

### Error: `ServiceUnavailable: Failed to establish connection`
**Cause:** The Neo4j server is not running or the Bolt protocol port `7687` is blocked.
**Resolution:**
1. Verify that your `.env` `NEO4J_URI` uses the `bolt://` protocol and points to your VM's correct external IP.
2. Ensure that your GCP Firewall rule `allow-neo4j-bolt` is active and allows incoming TCP traffic on ports `7687` (Bolt) and `7474` (Web Console).

---

## 3. Reasoning Engine Regional Mismatches

### Error: `Failed to route task: gRPC regional mismatch`
**Cause:** The Orchestrator and the remote specialist agent (e.g. Tier 2 Responder) are deployed in different GCP regions, and their regional clients are attempting to connect across mismatched zones.
**Resolution:**
1. During deployment/update, ensure that `GCP_LOCATION` in your `.env` matches the native hosting region of the target agent (e.g. `us-east4` for the Orchestrator, `us-central1` for the Tier 2 Responder).
2. Verify that the routing client's regional configurations are correctly resolved from the environment variables in `agent_soc_manager/agent.py`.

---

## 4. macOS & Airlock Package Installation Issues

### Error: `401 Unauthorized` or `No matching distribution found` during pip/uv installs
**Cause:** Your development machine resides behind a corporate Airlock proxy that restricts package resolution to approved repositories, blocking access to public PyPI indexes.
**Resolution:**
1. Bypass the corporate private registry lock by installing packages directly from the public PyPI index:
   ```bash
   .venv/bin/pip install --index-url https://pypi.org/simple -r requirements.txt
   ```
2. If the package resolution failure persists, run `gcert` to refresh your security certificates and re-authenticate your environment.

---

## 5. OAuth Authorization Expiration

### Error: `OAuth credentials expired` or authorization failures when connecting to GEAP
**Cause:** The active OAuth session token has expired, or the client credentials configuration has changed.
**Resolution:**
1. Re-run the OAuth setup flow using your client secret JSON key file:
   ```bash
   just client_secret=client_secret.json oauth-setup
   ```
2. Re-create the OAuth authorization in Discovery Engine:
   ```bash
   just oauth-create-auth
   ```

---

## 6. App Visibility in Gemini Enterprise Web UI

### Issue: Deployed app or agent is not visible in the Gemini Enterprise web console
**Cause:** When creating apps via CLI or API (rather than the Cloud Console UI), they default to restricted settings and do not show up unless specific intranet and vertical options are supplied.
**Resolution:**
1. You must explicitly include `--app-type APP_TYPE_INTRANET` and `--industry-vertical GENERIC` when creating the application:
   ```bash
   python manage.py agentspace create-app \
     --name "My Agent App" \
     --type SOLUTION_TYPE_CHAT \
     --no-datastore \
     --app-type APP_TYPE_INTRANET \
     --industry-vertical GENERIC
   ```
