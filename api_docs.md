# AgentGate API & Endpoints

AgentGate exposes two separate HTTP servers: the **main proxy** (default `:56123`, configured via `proxy_port`) and the **admin dashboard** (default `:57123`, configured via `admin_port`).

---

## Main Proxy Endpoints (`:56123`)

All paths are namespaced by `/<server-name>` as defined in `agentgate.yaml`.

### MCP Transport Endpoints

| Method | Path | Transport | Use case |
|--------|------|-----------|----------|
| `GET` | `/<server>/sse` | SSE (legacy) | Cursor, Claude Desktop, Python SDK |
| `POST` | `/<server>/message?sessionId=<id>` | SSE (legacy) | Message delivery after SSE handshake |
| `POST/GET` | `/<server>/mcp` | Streamable HTTP (MCP 2025) | Go/TS SDK, modern clients |
| `POST` | `/<server>` | Sync JSON-RPC | curl, custom HTTP clients |

**Example — Sync POST:**
```bash
curl -X POST \
  -H "Authorization: Bearer ag_secret_12345" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}' \
  "http://localhost:56123/filesystem"
```

### OAuth 2.0 Protected Resource Metadata

| Path | Description |
|------|-------------|
| `GET /.well-known/oauth-protected-resource` | Returns PRM JSON (`resource`, `authorization_servers`, `scopes_supported`) |
| `GET /<server>/.well-known/oauth-protected-resource` | Per-server PRM discovery |

### HITL Callback Endpoints

These are called by Slack/Discord webhooks when a human approves or denies a tool execution. They do **not** require authentication.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/_agentgate/hitl/approve` | Approve a pending tool execution |
| `POST` | `/_agentgate/hitl/deny` | Deny a pending tool execution |
| `POST` | `/_agentgate/hitl/slack-interactive` | Slack interactive component payload handler |

---

## Admin Dashboard Endpoints (`:57123`)

All admin endpoints are bound to `127.0.0.1` only and never exposed to the network.

### Analytics & Metrics

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/stats` | Aggregate request counts and average latency |
| `GET` | `/api/heatmap` | Per-tool allow/block rate heatmap |
| `GET` | `/api/history` | Last 50 request records (includes input/output payloads) |
| `GET` | `/api/stream` | Server-Sent Events stream of real-time request events |

**`/api/history` response shape:**
```json
[
  {
    "id": 42,
    "timestamp": "2026-03-24T12:00:00Z",
    "status": "allowed",
    "server_name": "filesystem",
    "agent_id": "sub-from-jwt",
    "tool_name": "read_file",
    "arguments": {"path": "/home/user/config.yaml"},
    "reason": "Passed Semantic Firewall",
    "latency_ms": 12,
    "jsonrpc_id": "1",
    "input_payload": "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",...}",
    "output_payload": "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[...]}}"
  }
]
```

**`/api/stream` event types:**

| `type` field | Description |
|---|---|
| *(absent)* | New `RequestRecord` — prepend to firehose |
| `output_patch` | In-place update: patches `output_payload` on the matching row by `jsonrpc_id` |

### Configuration

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/config` | Returns the currently active `agentgate.yaml` as JSON |
| `POST` | `/api/config/save` | Saves a new configuration and triggers a hot-reload |

**`POST /api/config/save` request body (MCP JSON format):**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"],
      "policies": {
        "access_mode": "allowlist",
        "allowed_tools": ["read_file"],
        "human_approval": {
          "tools": ["read_file"],
          "timeout": 300,
          "webhook": { "type": "slack", "url": "https://hooks.slack.com/..." }
        }
      }
    }
  }
}
```

### Tool Discovery

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/discover` | Performs a transient tool discovery against one or more MCP servers |

**`POST /api/discover` request body:**
```json
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/mydb"]
    }
  }
}
```

**Response:**
```json
{
  "tools": {
    "postgres": [
      { "name": "execute_query", "description": "Run a SQL query", "inputSchema": { ... } }
    ]
  },
  "errors": {
    "broken-server": "context deadline exceeded. Last Stderr: image not found"
  }
}
```

---

## IPC Panic Button

AgentGate listens on a Unix domain socket at `/tmp/agentgate.sock` for out-of-band control signals that bypass all network paths:

```bash
agentgate service pause    # Immediately return 503 for all tool calls
agentgate service resume   # Restore normal operation
```
