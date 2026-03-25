<div align="center">

# AgentGate

**The Zero-Trust Firewall and Protocol Bridge for the Model Context Protocol (MCP)**

[![Go Report Card](https://goreportcard.com/badge/github.com/AgentStaqAI/agentgate)](https://goreportcard.com/report/github.com/AgentStaqAI/agentgate)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/AgentStaqAI/agentgate?style=social)](https://github.com/AgentStaqAI/agentgate/stargazers)

> A sub-millisecond, zero-dependency reverse proxy written in Go that airgaps your AI agents. Intercepts MCP tool calls, translates them across transport protocols, and wraps them in an impenetrable semantic firewall — with a built-in observability dashboard.

</div>

---

## The Problem: AI agents are inherently unsafe

As LLMs evolve into autonomous agents, they are being granted direct, raw access to filesystems, databases, and production APIs via MCP. Relying on system prompts for security is a guaranteed way to get your database dropped:

- Hallucinate destructive commands (`DROP TABLE production_users;`)
- Enter infinite loops that drain your API budget overnight
- Execute sensitive mutations without any human oversight

## The Solution: Stop them at the network layer

```
[ LLM / Agent ] ──► (HTTP/SSE) ──► [ AgentGate :8083 ] ──► (stdio / HTTP) ──► [ MCP Tool ]
                                           │
                                  ┌────────┴────────────────┐
                                  │  OAuth 2.1 Auth         │
                                  │  Semantic RBAC          │
                                  │  Regex Parameter Rules  │
                                  │  Rate Limiting          │
                                  │  Human-in-the-Loop      │
                                  │  Panic Button           │
                                  │  Observability Dashboard│
                                  └─────────────────────────┘
```

---

## Core Features

### 1. Centralized OAuth 2.1 Resource Server
AgentGate validates JWTs, fetches JWKS keys (with background rotation), and bounces unauthenticated AI clients with `WWW-Authenticate` headers — completely decoupling auth from your MCP tool code.

### 2. Semantic RBAC & Parameter Sandbox
Allowlist exactly which tools an agent can call. Go deeper with **regex rules on the parameters themselves** — e.g., the agent can only read files matching `*.log`, or can only `SELECT` but never `DELETE`.

### 3. Human-in-the-Loop (HITL)
Automatically pause high-risk tool execution. AgentGate intercepts the request, pings your **Slack / Discord / webhook**, and physically holds the HTTP connection open until a human clicks **Approve** or **Deny**.

### 4. Runaway Loop Breaker (Rate Limiting)
Cap tool executions per minute globally or per MCP server. If an agent spams a function, it instantly receives `HTTP 429`.

### 5. The IPC Panic Button
Type `agentgate service pause` in your terminal to instantly sever all autonomous tool execution with a `503`, without exposing an admin endpoint to the network.

### 6. stdio ↔ HTTP Bridge
AgentGate translates local `exec:` stdio processes to standard **HTTP/SSE**, letting you run tools in isolated containers while the LLM client stays local. Supports all three MCP transports:

| Transport | Path | Use case |
|---|---|---|
| Streamable HTTP (MCP 2025) | `/server/mcp` | Go/TS SDK clients |
| Server-Sent Events (legacy) | `/server/sse` | Python SDK, Cursor, Claude |
| Synchronous JSON-RPC | `/server` | curl, custom HTTP clients |

### 7. Onboarding & Tool Discovery
AgentGate includes a built-in guided onboarding flow. Paste your existing `claude_desktop_config.json` or `mcp.json` and AgentGate performs a transient hit-and-run discovery strike to enumerate all available tools from each server. You then visually configure allowlists, regex sandboxes, and HITL settings per-tool inside the browser — no YAML editing required.

> **Screenshot placeholder** — Onboarding: Tool Discovery & Policy Builder  
> `docs/screenshots/onboarding.png`

### 8. Live Traffic Observability Dashboard
The embedded admin dashboard (`:8081`) streams real-time tool call events via Server-Sent Events. Each row in the **Live Traffic Firehose** is clickable and expands to reveal:
- **Input Payload** — the exact JSON-RPC request sent to the upstream MCP tool
- **Upstream Output Payload** — the raw JSON-RPC response returned from the tool, updated in real-time without a page refresh

> **Screenshot placeholder** — Live Traffic Firehose with expanded I/O payloads  
> `docs/screenshots/observability.png`

Additional dashboard views:
- **Policy Heatmap** — tool-by-tool allow/block rates for security auditing
- **Rules & Policies** — live view of the currently hot-loaded `agentgate.yaml`

---

## Quick Start

AgentGate is a single, zero-dependency Go binary.

**Option 1 — Build from Source**
```bash
git clone https://github.com/AgentStaqAI/agentgate.git
cd agentgate
go build -o agentgate .
./agentgate serve
```

**Option 2 — Homebrew (macOS/Linux)**
```bash
brew tap AgentStaqAI/agentgate
brew install agentgate
```

Open `http://127.0.0.1:8081` in your browser. If you have no `agentgate.yaml` yet, AgentGate will drop you directly into the **Onboarding** flow.

---

## 5-Minute Example

Define your MCP servers in `agentgate.yaml`:

```yaml
version: "1.0"
network:
  port: 8083
  admin_port: 8081
auth:
  require_bearer_token: "my-secret-token"
audit_log_path: "audit.log"

mcp_servers:
  filesystem:
    upstream: "exec:npx -y @modelcontextprotocol/server-filesystem /home/user/projects"
    policies:
      access_mode: "allowlist"
      allowed_tools: ["read_file", "list_directory"]
      rate_limit:
        max_requests: 60
        window_seconds: 60

  my_postgres:
    upstream: "http://localhost:9090"
    policies:
      allowed_tools: ["query"]
      human_approval:
        require_for_tools: ["query"]
        timeout_seconds: 300
        webhook:
          type: "slack"
          url: "https://hooks.slack.com/services/..."
```

Point your LLM client at `http://localhost:8083/<server-name>/mcp` (Streamable HTTP) or `http://localhost:8083/<server-name>/sse` (SSE legacy).

---

## Usage

**1. Configure your Firewall**

Create an `agentgate.yaml`. See the **[Configuration Guide](configuration.md)** for the full YAML schema. Ready-made templates for popular MCP servers are in **[`config_templates/`](config_templates/README.md)**.

**2. Install & Start the Daemon**
```bash
./agentgate service install -c /path/to/agentgate.yaml
./agentgate service start
```

**3. Monitor the Dashboard**

Open `http://127.0.0.1:8081` to access real-time traffic, policy heatmap, and config management.

**4. Panic Button**
```bash
agentgate service pause    # Instantly suspend all autonomous actions
agentgate service resume   # Resume
```

**5. Hot-Reload Config**

Edit `agentgate.yaml`. Use `Generate & Apply` from the Onboarding UI to apply changes without restarting the server. Or send `SIGHUP` to the process.

---

## Documentation

| Document | Description |
|---|---|
| [Configuration Guide](configuration.md) | Full `agentgate.yaml` schema — auth, RBAC, regex rules, HITL, rate limits |
| [API & Endpoints](api_docs.md) | Streamable HTTP, SSE, sync JSON-RPC, HITL callback endpoints |
| [Config Templates](config_templates/README.md) | Drop-in configs for Filesystem, GitHub, Postgres, Slack, and more |

---

## Contributing

PRs are welcome! Feel free to open issues for new protocols, bugs, or enhanced HITL integrations.

If you find this useful, please ⭐ the repo to help others discover secure agent infrastructure.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).