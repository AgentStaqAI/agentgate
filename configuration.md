# Configuration Guide (`agentgate.yaml`)

AgentGate relies on a single `agentgate.yaml` file to define routing namespaces, network bindings, authentication, and fine-grained security policies per MCP server.

---

## Full Reference Example

```yaml
version: "1.0"

# ── Network ───────────────────────────────────────────────────────────────────
network:
  proxy_port: 56123    # Main proxy port (where your LLM clients connect)
  admin_port: 57123    # Embedded dashboard & admin API
  public_url: "https://your-ngrok-url.ngrok-free.dev"  # Required for HITL callback URLs

# ── Authentication ─────────────────────────────────────────────────────────────
# Option A: Simple static bearer token
auth:
  require_bearer_token: "my-secret-token"

# Option B: Full OAuth 2.1 Resource Server (comment out Option A to use this)
oauth2:
  enabled: true
  issuer: "https://auth.example.com"
  scopes_supported: ["mcp-tools"]
  resource: "http://localhost:56123"
  jwks_url: "https://auth.example.com/.well-known/jwks.json"
  inject_user_header: true   # Injects X-AgentGate-User and X-AgentGate-Scopes upstream

# ── Global Limits ──────────────────────────────────────────────────────────────
agent_limits:
  max_requests_per_minute: 120    # Global rate limit across all tools

audit_log_path: "audit.log"      # Structured audit output path

# ── MCP Servers ────────────────────────────────────────────────────────────────
mcp_servers:

  # --- Stdio Bridge (exec:) ---
  filesystem:
    upstream: "exec:npx -y @modelcontextprotocol/server-filesystem /home/user/projects"
    env:
      SOME_ENV_VAR: "value"       # Injected into the child process environment
    policies:
      access_mode: "allowlist"   # "allowlist" (deny-by-default) or "blocklist" (allow-by-default)
      allowed_tools:
        - read_file
        - list_directory
      tool_policies:
        read_file:
          - action: block
            condition: args.path.contains(".ssh") || args.path.contains("/etc/shadow")
            error_msg: "Security Block: Access to sensitive paths is denied."
        max_requests: 60
        window_seconds: 60

  # --- HTTP Reverse Proxy ---
  my_postgres:
    upstream: "http://localhost:9090"
    policies:
      access_mode: "allowlist"
      allowed_tools:
        - execute_query
      human_approval:
        tools:
          - execute_query
        timeout: 300              # Default: 300 seconds. Agent request is held open until approval.
        webhook:
          type: "slack"           # Options: "slack", "discord", "terminal", "generic"
          url: "https://hooks.slack.com/services/T.../B.../..."

  # --- Docker Container (also exec:) ---
  google-maps:
    upstream: "exec: docker run -i --rm -e GOOGLE_MAPS_API_KEY mcp/google-maps"
    env:
      GOOGLE_MAPS_API_KEY: "your-api-key-here"
    policies:
      access_mode: "allowlist"
      allowed_tools:
        - maps_directions
        - maps_search_places
```

---

## Key Configuration Fields

### 1. `network`
- `proxy_port` — The main proxy port. Your AI client connects here.
- `admin_port` — The embedded observability dashboard and admin API.
- `public_url` — Publicly reachable base URL. Required so AgentGate can build correct HITL callback URLs for Slack/Discord buttons to reach back.

### 2. Authentication: `auth` vs `oauth2`
Use `auth.require_bearer_token` for simple static token auth (good for local development). Switch to `oauth2` for production to get spec-compliant JWT validation with background JWKS key rotation.
- `inject_user_header: true` strips the JWT and injects `X-AgentGate-User` and `X-AgentGate-Scopes` into upstream requests so your MCP tools know who is calling without implementing OAuth themselves.

### 3. `mcp_servers` — Upstream Types
- **`exec:<command>`** → AgentGate spawns the command as a child process and bridges its `stdin`/`stdout` to HTTP. Works with `npx`, `uvx`, `docker run`, or any local binary.
- **`http://` / `https://`** → AgentGate acts as a reverse proxy to an already-running HTTP MCP server.

The `env` block injects key-value pairs into the child process environment (required if your MCP server reads from environment variables, e.g. `GOOGLE_MAPS_API_KEY`).

### 4. `policies.access_mode`
- `allowlist` — Deny all tools by default; only `allowed_tools` pass through. Recommended for production.
- `blocklist` — Allow all tools by default; only `blocked_tools` are denied.

### 5. `policies.tool_policies` (CEL Rules)
Inspect the JSON *arguments* of a tool call or the *JWT claims* using Google's Common Expression Language (CEL). You can map an action (`block`, `allow`, `hitl`) to a specific condition:

```yaml
tool_policies:
  execute_query:
    - action: block
      condition: args.query.contains("DROP") || args.query.contains("DELETE")
      error_msg: "Security Block: Destructive SQL operations are not permitted."
    - action: hitl
      condition: jwt.claims.role == "developer" && args.query.contains("UPDATE")
      error_msg: "Updates require Human-in-the-Loop authorization."
```

### 6. `policies.human_approval` (HITL)
Pause execution for high-risk tools and wait for a human decision:
- `tools` — List of tool names that require approval natively.
- `timeout` — How long the agent request is held open waiting for a decision. Defaults to 300 seconds.
- `webhook.type` — `slack`, `discord`, `terminal`, or `generic`.
- `webhook.url` — The incoming webhook URL for Slack/Discord notifications. Leave empty for `terminal` mode.

### 7. `policies.rate_limit`
Per-server sliding-window rate limiting:
- `max_requests` — Maximum calls allowed in the window.
- `window_seconds` — Length of the sliding window.

The global `agent_limits.max_requests_per_minute` applies across all servers as a blanket ceiling.

---

## Onboarding Flow (No YAML Required)

If you have an existing `claude_desktop_config.json` or `mcp.json` from Claude or Cursor, open `http://127.0.0.1:8081` and paste it into the **Onboarding** tab. AgentGate will:
1. Perform a transient discovery call to enumerate all tools from each server
2. Let you configure allowlists, regex parameter rules, and HITL settings per-tool via the UI
3. Generate and hot-reload the `agentgate.yaml` without restarting the server
