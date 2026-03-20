<div align="center">

# 🚪 AgentGate

**The Zero-Trust Firewall and Protocol Bridge for the Model Context Protocol (MCP)**

[![Go Report Card](https://goreportcard.com/badge/github.com/AgentStaqAI/agentgate)](https://goreportcard.com/report/github.com/AgentStaqAI/agentgate)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/AgentStaqAI/agentgate?style=social)](https://github.com/AgentStaqAI/agentgate/stargazers)

> A sub-millisecond, zero-dependency reverse proxy written in Go that airgaps your AI agents. It intercepts MCP commands, translates them to HTTP/SSE, and wraps them in an impenetrable semantic firewall.

</div>

![AgentGate HITL Demo](docs/demo.gif)

---

## 🛑 The Problem: AI is inherently unsafe

As LLMs evolve into autonomous agents, they are being granted direct, raw `stdio` access to local filesystems, databases, and production APIs via MCP.

Relying on "system prompts" for security is a guaranteed way to get your database dropped. Without a network-layer firewall, an agent can:
- Hallucinate destructive commands (`rm -rf /`, `DROP TABLE`)
- Enter infinite loops that drain your API budget overnight
- Execute sensitive mutations without any human oversight

## ⚡ The Solution: Stop them at the network layer

```json
// What the Agent attempts:
{"method": "execute_sql", "params": {"query": "DROP TABLE production_users;"}}

// What AgentGate instantly returns:
{"error": {"code": -32000, "message": "AgentGate: BLOCKED. 'DROP' operations require Human-in-the-Loop approval."}}
```

```
[ LLM / LangChain ] ──► (HTTP/SSE) ──► [ AgentGate ] ──► (stdio) ──► [ MCP Tools / DB ]
                                                │
                                       ┌────────┴────────┐
                                       │  Policy Engine  │
                                       │  Slack HITL     │
                                       │  Rate Limiter   │
                                       └─────────────────┘
```

---

## 🔥 Core Features

### 1. Semantic RBAC & Parameter Sandbox 🔒
Whitelist exactly which tools an agent can use. Go deeper with **regex rules on the parameters themselves** — e.g., the agent can only read files ending in `.log`, or can only `SELECT` but never `DELETE`.

### 2. Human-in-the-Loop (HITL) ⏸️
Automatically pause high-risk tool execution. AgentGate intercepts the request, pings your **Slack** or a CLI webhook, and physically holds the HTTP connection open until a human clicks **Approve** or **Deny**.

### 3. Runaway Loop Breaker (Rate Limiting) ⏱️
Defeat hallucination loops. Cap tool executions per minute globally or **per MCP server**. If an agent spams a function, it instantly receives `HTTP 429`.

### 4. The IPC Panic Button 🛑
If an agent goes completely rogue, type `agentgate service pause` in your terminal. This uses an isolated Unix Domain Socket to **instantly sever all autonomous tool execution** with a `503`, without exposing an admin endpoint to the network.

### 5. stdio → HTTP Bridge 🌉
MCP natively uses local `stdio`. AgentGate translates this to standard **HTTP/SSE**, letting you run tools in an isolated container or VPC while the LLM client stays local.

---

## 🚀 Quick Start

AgentGate is a single, zero-dependency Go binary.

**Option 1 — Homebrew (macOS/Linux)**
```bash
brew tap AgentStaqAI/agentgate
brew install agentgate
```

**Option 2 — Build from Source**
```bash
git clone https://github.com/AgentStaqAI/agentgate.git
cd agentgate
go build -o agentgate .
```

---

## 5-Minute Example

Define your MCP servers in `agentgate.yaml`:

```yaml
version: "1.0"
network:
  port: 8083
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
    upstream: "http://localhost:9090"   # An already-running MCP HTTP server
    policies:
      allowed_tools: ["query"]
      human_approval:
        require_for_tools: ["query"]
        webhook:
          type: "slack"
          url: "https://hooks.slack.com/services/..."
```

Start AgentGate, then point your LLM client at it using the protocol your MCP server speaks:

| Protocol | Your MCP server speaks | URL to give your LLM client |
|---|---|---|
| **Streamable HTTP** (MCP spec 2025) | Native MCP / Go & TS SDKs | `http://localhost:8083/filesystem/mcp` |
| **Server-Sent Events** (SSE legacy) | Python SDK, FastMCP | `http://localhost:8083/filesystem/sse` |
| **Synchronous JSON-RPC** (plain HTTP) | Custom HTTP servers, curl | `http://localhost:8083/filesystem/` |

All three paths go through the **same firewall** — auth, RBAC, regex sandbox, rate limiting, and HITL checks apply equally regardless of the transport protocol.

> See the **[API & Endpoints guide](api_docs.md)** for a detailed breakdown of how each protocol works.

---

## ⚙️ Usage

**1. Configure your Firewall**

Create an `agentgate.yaml`. See the **[Configuration Guide](configuration.md)** for the full YAML schema including RBAC rules, regex sandboxes, HITL webhooks, and per-server rate limits.

Ready-made templates for popular MCP servers (Filesystem, GitHub, Postgres, Slack, etc.) are in the **[`config_templates/`](config_templates/README.md)** directory.

**2. Install & Start the Daemon**
```bash
# No sudo required — installs to ~/Library/LaunchAgents/ on macOS
./agentgate service install -c /path/to/agentgate.yaml
./agentgate service start
```

**3. Monitor the Audit Log**
```bash
tail -f audit.log
```

**4. Panic Button**
```bash
agentgate service pause    # Instantly suspend all autonomous actions
agentgate service resume   # Resume
```

---

## 📖 Documentation

| Document | Description |
|---|---|
| [Configuration Guide](configuration.md) | Full `agentgate.yaml` schema — RBAC, regex rules, HITL, rate limits |
| [API & Endpoints](api_docs.md) | `/mcp` Streamable HTTP, `/sse` legacy transport, HITL webhook endpoints |
| [Config Templates](config_templates/README.md) | Drop-in configs for Filesystem, GitHub, Postgres, Slack, and more |

---

## 🤝 Contributing

PRs are welcome! Feel free to open issues for new protocols, bugs, or enhanced HITL integrations.

If you find this useful, please ⭐ the repo to help others discover secure agent infrastructure.

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
