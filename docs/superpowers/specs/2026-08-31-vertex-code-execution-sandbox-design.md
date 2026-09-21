# Vertex AI Code Execution & Threat Hunter Sandbox Integration Design

## 1. Overview & Objectives

Integrate **Vertex AI Code Execution Sandbox** (`AgentEngineSandboxCodeExecutor` and `VertexAiCodeExecutor`) into the **Agentic SOC** platform. The goal is to provide isolated, high-performance computational Python execution capabilities for specialized SOC agents—starting with the **Threat Hunter** specialist (`agent_a2a_threat_hunter`).

### Key Benefits
- **Context Window Optimization:** Large telemetry sets (1,000+ Chronicle UDM logs) can be processed as files in the sandbox, preventing token bloat and eliminating gRPC buffer limits.
- **Statistical & Algorithmic Analysis:** Enable deterministic calculations such as Shannon entropy (DGA detection), inter-arrival time distributions (beaconing detection), and process tree parsing.
- **Single-Turn Autoregulation:** Agents write Python code, execute it within the sandbox, catch exceptions, and correct logic in a single turn without multiple client-agent roundtrips.

---

## 2. Architecture & Component Interfaces

### 2.1 Code Executor Factory (`code_executor_factory.py`)
To ensure portability between local development, unit tests, and production Vertex AI Agent Engine deployments, a unified factory provides:
- **`AgentEngineSandboxCodeExecutor`**: When running within Vertex AI Agent Engine or with a configured `AGENT_ENGINE_RESOURCE_NAME` / `SANDBOX_RESOURCE_NAME`.
- **`VertexAiCodeExecutor`**: Fallback to Vertex AI Code Interpreter Extension.
- **`BuiltInCodeExecutor`**: Gemini native API code execution for rapid testing.
- **`UnsafeLocalCodeExecutor`**: For hermetic offline unit tests only.

### 2.2 Threat Hunter Agent Architecture
The Threat Hunter (`agent_a2a_threat_hunter`) maintains access to:
1. **MCP Security Tools (`McpToolset`)**: Chronicle SIEM (`search_security_events`), Google Threat Intelligence (`gti-mcp`), SOAR cases, and Security Command Center (`scc-mcp`).
2. **Code Executor (`code_executor`)**: Sandboxed Python execution for statistical analysis and log aggregation.
3. **Pre-configured Hunting Analytics Helpers**: Standardized calculation recipes injected into system instructions (entropy, beaconing jitter, timeline alignment).

---

## 3. Threat Hunter Hunting Scenarios & Workflows

### Scenario 1: Domain Generation Algorithm (DGA) / DNS Tunneling Detection
1. Threat Hunter queries Chronicle SIEM for `DNS_QUERY` events.
2. Threat Hunter executes a sandboxed Python script to compute Shannon entropy on queried domains:
   $$H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
3. Domains with $H(X) > 3.8$ are flagged as anomalous and cross-checked against GTI.

### Scenario 2: C2 Beaconing Periodic Analysis
1. Threat Hunter pulls network connection timestamps for a suspicious remote IP.
2. In the sandbox, pandas calculates delta intervals ($\Delta t = t_{i} - t_{i-1}$) and coefficient of variation ($CV = \sigma / \mu$).
3. Low variance indicates automated beaconing activity.
