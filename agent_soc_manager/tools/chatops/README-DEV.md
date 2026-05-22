# ChatOps Development & Design Guide (README-DEV.md)

This document outlines the engineering philosophy, security design, and roadmap for the SOC ChatOps integration with Vertex AI Agent Engine.

## Design Considerations

### 1. Modern Card UX (v2)
We have transitioned from legacy JSON layouts to the **Google Chat Card v2** schema. 
- **Icons**: Selective use of `materialIcon` (e.g., `security`, `vpn_lock`, `bug_report`) to provide instant visual context.
- **Color Coded Actions**: Primary buttons use a rich blue/red/green HSL-tailored palette to distinguish between "Approve" (Green), "Block/Deny" (Red), and "Investigate" (Blue).
- **Widgets**: Heavy use of `decoratedText` and `columns` to present structured security data (e.g., side-by-side travel locations) rather than raw text blobs.

### 2. Security: HMAC-SHA256 Tokenization
To prevent button spoofing, we generate a signed token (`t`) instead of passing raw session or entity IDs in the URL.
- **Secret Management**: A shared UUID secret (`CHRONICLE_CHATOPS_SECRET`) is used for the cryptographic handshake.
- **Stateless Verification**: The webhook handler does not need a database; it simply recalculates the HMAC of the payload and compares it to the signature in the URL.
- **TTL (Expiration)**: Every token contains an `exp` claim. After 1 hour, the link automatically becomes invalid, preventing "stale" approvals.

### 3. Session Impersonation (Playground vs Production)
A major technical discovery was the `vais-query-reasoning-engine` identity. 
- **V6 API Constraint**: Vertex AI Reasoning Engine sessions are strictly owned by the creator.
- **Discovery**: We successfully bypassed the "Session does not belong to user" error by identifying the internal system ID used by the Google Cloud Console. This allow the ChatOps system to "impersonate" the playground user for high-fidelity testing.

### 4. Triage Report PDF Downloads (GCS Pre-Signed URLs)
The "Download Full PDF" button inside the `triage_report_ready` ChatOps card intentionally does *not* route through the standard `generate_action_url` webhook loop. To provide a secure, direct download of the PDF without requiring an intermediate Cloud Function proxy, the codebase natively initializes a `google-cloud-storage` client and securely vends a generated pre-signed URL (expiring in 24 hours). 

- **IAM Permissions**: The ambient runtime service account attached to the Agent Engine container MUST have the explicit **Service Account Token Creator** (`roles/iam.serviceAccountTokenCreator`) role bound *to itself* in order to successfully run `blob.generate_signed_url` synchronously on its own identity natively.
- **Security Fallback**: If URL signing fails (e.g. absent IAM Token Creator permissions), the card architecture automatically falls back to rendering a direct deep link to the Google Cloud Console Storage Browser UI for the specific object. This guarantees delivery by allowing the user's native GCP console identity to authorize the download instead.

## Scaling & Performance

- **Lean Containers**: The [Dockerfile](Dockerfile) uses `python:3.10-slim` and a [dedicated requirements.txt](requirements.txt). This results in a **120MB image** (down from 600MB+) and sub-second cold starts on Cloud Run.
- **Async Execution**: The webhook handler uses FastAPI and `async_stream_query` to handle long-running AI inferences without blocking the HTTP response.

## Known Issues & Caveats

### 1. Token Serialization (The "Quote Stripping" Problem)
- **Issue**: Some `.env` loaders and `bash` exports wrap `AGENT_ENGINE_RESOURCE_NAME` or `AGENT_ENGINE_ID` in single or double quotes. If these quotes are signed into the HMAC token, the Reasoning Engine SDK will reject the ID as malformed.
- **Solution**: We implemented mandatory quote-stripping in `card_client.py` and `webhook_handler.py`. Developers must ensure that any new IDs passed to `generate_signed_token` are sanitized.

### 2. Session ID Continuity
- **Issue**: The current webhook handler creates a *new* request to the AI session. It does not "resume" the specific question the AI just asked (e.g., "Do you approve?"). Instead, it sends the confirmation (e.g., "Human confirmed action X") as a new message in the same session.
- **Impact**: The AI must have "context memory" of its previous question to understand the incoming confirmation message.

### 3. Playground Identity Lock
- **Issue**: Testing action buttons from a card sent *outside* the Google Cloud Console while trying to interact with a *Playground* session will fail if the `user_id` is missing.
- **Requirement**: The `vais-query-reasoning-engine` ID must be explicitly passed in the payload for Playground session interaction. This is handled automatically in the templates' manual test blocks.

### 4. Shared Secret Synchronization
- **Issue**: If the `CHRONICLE_CHATOPS_SECRET` in the `card_client` environment (where the template is run) does not **EXACTLY** match the secret in the `webhook_handler` environment (Cloud Run), the verification will fail with "Invalid signature."
- **Debugging**: If you hit signature errors after a re-deployment, verify that the `uuidgen` secret was updated in both the root `.env` and the Cloud Run environment variables.

---

## Future Works

### 1. Unified Action Payload
Move from `openLink` (which opens a browser tab) to a registered **Google Chat App**. This will enable `onClick: { action: { ... } }` which executes in the background without leaving the chat interface.

### 2. Multi-Button Input Capture
Expand the `textInput` support to allow the AI to receive multiple fields at once (e.g., "Justify this access" + "End Date" + "Manager Name").

### 3. Real-time Status Card Updates
Implement a "Pending -> Complete" state update. After a button is clicked, the webhook should update the original card message to show a checkmark or the AI's final confirmation text.

### 4. Enterprise Identity Mapping
Create a mapping between Google Chat user IDs and Chronicle/IAM identities. This will allow the AI to say *"I've applied this block on behalf of John Smith"* with full audit logs.
