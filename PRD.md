# Product Requirements Document (PRD): ChatOps Context Integration with Agent Engine

## 1. Overview
The **ChatOps Context Integration** is designed to enable true "Human-in-the-loop" workflows by routing Google Chat capability actions (button clicks) back into the Google Vertex AI Agent Engine. By relaying the end-user's action via a signed payload, the system will execute `AgentEngine.query(session_id, user_action)` to seamlessly fuse the user's decision into the AI's contextual session memory.

## 2. Objectives
* **Context Preservation**: Ensure the AI agent is explicitly aware when an action (e.g., blocking an IP, resetting a password) has been approved and executed by a user.
* **Security & Non-repudiation**: Prevent unauthorized triggering or spoofing of approval clicks by implementing cryptographic URL validation.
* **Reliable UX**: Guarantee proper handling of long-running LLM inferences without violating chat platform latency requirements.

## 3. High-Level Architecture

The solution will introduce a new lightweight API integration layer bridging the Chat Interface and Vertex AI Agent Engine.

### 3.1 Components
1. **Card Generation Enhancements (`card_client.py`)**: 
   * Update the card payload generator to embed structured URLs containing Base64 encoded JSON parameters: `session_id`, `agent_engine_id`, and `action_type`.
   * Implement HMAC-SHA256 or JWT signing to affix a signature to the query parameters.
2. **Action Webhook (Cloud Function or Cloud Run)**:
   * A stateless HTTP endpoint that catches the `openLink` or `action` payload from Google Chat.
   * Validates the cryptographic signature against the environment's shared secret.
   * Executes the `reasoning_engines.ReasoningEngine(agent_engine_id).query(session_id=..., input="User confirmed: <action_type>")`.
   * Forwards the Agent Engine's text response back to the Chat space.

### 3.2 Interaction Flow
1. **Trigger**: Agent determines an action is needed and calls a tool. The tool sends an interactive card to Chat.
2. **Action**: User clicks the "Approve / Block" button.
3. **Validation**: The Action Webhook receives the request, verifies the signature, and rejects tampered requests with an HTTP 403.
4. **Execution**: The webhook instantiates the Agent Engine via the Vertex AI SDK and appends the user's action to the session.
    * **CRITICAL**: The webhook must use the internal identity `vais-query-reasoning-engine` as the `user_id` when querying sessions created via the Google Cloud Console (Playground).
    * **SDK Pattern**: Use `vertexai.agent_engines.get(id).async_stream_query(...)` for optimal compatibility with ADK-managed agents.
5. **Resolution**: The Agent Engine provides a natural language confirmation, which the webhook posts back to the Chat topic.

## 4. UX & Interface Considerations

### 4.1 "Tab Open" Problem (Phase 1)
Currently, the system relies on Google Chat **Incoming Webhooks**, which only support `openLink` button actions.
* When clicked, a new browser tab will inevitably open.
* **Requirement**: The Action Webhook must return a clean, static HTML response (e.g., *"Action complete. You may close this tab."*) to ensure a graceful UX while asynchronously posting the update to Chat.

### 4.2 Native Chat App (Phase 2 - Recommended)
To prevent new tabs from opening, the project should migrate from using Incoming Webhooks to a registered **Google Chat App**.
* This enables the use of `onClick: { action: { function: 'executeAction' } }` payloads.
* **Requirement**: Resolves UX constraints by allowing background execution, where the AI's response is natively rendered as a new message dialog inside Chat.

## 5. Security Requirements
* **Payload Signing**: Never expose plaintext `Session ID` and `Agent Engine ID` without a signature. A symmetric secret key (stored in GCP Secret Manager or `.env`) must be used to sign and verify URLs.
* **Expiration (Optional but Recommended)**: The JWT or encrypted payload should include an `exp` claim (e.g., 1 hour) so that approval buttons naturally expire if acted upon too late.

## 6. Performance & Latency Requirements
* **API Timeouts**: Google Chat requires an initial response within 30 seconds for native Apps. Agent Engine `.query()` calls can occasionally exceed this depending on model latency and prompt size.
* **Decoupling Strategy**: The Action Webhook should immediately acknowledge receipt (HTTP 200) and publish the execution task to a background queue (e.g., Pub/Sub or Cloud Tasks). A worker pulls the task, queries the Agent Engine, and posts the final AI reply via an asynchronous webhook callback.

## 7. Implementation Plan

* **Step 1: Tokenization Utility (`soc_agent/tools/chatops/security.py`)**
  * Create functions for `generate_signed_action_url()` and `verify_signed_action_url()`.
* **Step 2: Card Refactoring (`soc_agent/tools/chatops/*.py`)**
  * Modify existing cards (like the Privilege Access Card and AI Brute Force Card) to correctly fetch the `agent_engine_id` and `session_id` from the context and generate signed URLs for all buttons.
* **Step 3: Webhook Endpoint Deployment**
  * Create a lightweight FastAPI application for Cloud Function deployment.
  * **Implementation Detail**: Handler must support `user_id` context to prevent "Session does not belong to user" errors.
* **Step 4: Integration Testing & Verification**
  * Verified that `vais-query-reasoning-engine` successfully impersonates the Playground user for human-in-the-loop actions.
  * Verified end-to-end security via HMAC-SHA256 signature verification.
