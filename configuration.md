# Configuration Guide (`agentgate.yaml`)

AgentGate relies on an overarching `agentgate.yaml` file to define routing namespaces, strict network port allocations, and fine-grained Agent security policies.

## Example Structure

```yaml
# ── Authentication ────────────────────────────────────────────────────────────
# Option A: Simple Static Token
# auth:
#   require_bearer_token: "secret_admin_token_123"

# Option B: Full OAuth 2.1 Resource Server
oauth2:
  enabled: true
  issuer: "https://auth.example.com"
  audience: "agentgate-production"
  jwks_url: "https://auth.example.com/.well-known/jwks.json"
  resource_metadata: "https://auth.example.com/.well-known/oauth-authorization-server"
  refresh_interval_seconds: 3600
  inject_user_header: true

# ── Global Limits & Telemetry ─────────────────────────────────────────────────
agent_limits:
  max_requests_per_minute: 120    # Global infinite loop limit across all tools

audit_log_path: "audit.log"       # Telemetry output for parsing tools executing

mcp_servers:
  local_mcp_namespace:
    upstream: "exec:/opt/homebrew/bin/npx -y @modelcontextprotocol/server-filesystem /Users/myuser/dev"
    policies:
      access_mode: "allowlist"    # Fail-secure default: Deny all tools natively unless explicit
      allowed_tools:
        - "read_file"
      
      parameter_rules:
        # Prevent the LLM from reading sensitive ssh and system keys
        "read_file":
          argument_key: "path"
          not_match_regex: "\\.ssh/|/etc/shadow"
          error_msg: "Security Block: Regex Sandbox prevented access to secure SSH/System architecture keys."

  database_postgres:
    # Notice this maps to an actual running network proxy! 
    upstream: "http://localhost:9099"
    policies:
      access_mode: "allowlist"
      allowed_tools:
        - "read_query"
        - "execute_query"
      
      # Stop the execution and wait for a human to type /approve in Slack!
      human_approval:
        require_for_tools:
          - "execute_query"
        timeout_seconds: 300
        webhook:
          type: "slack"
          url: "https://hooks.slack.com/services/T..."

      rate_limit:
        max_requests: 10
        window_seconds: 60
```

## Key Configuration Fields

### 1. Centralized OAuth 2.1 (`oauth2`)
Ditch the `auth.require_bearer_token` static secret and turn AgentGate into a spec-compliant OAuth 2.1 Resource Server. By setting `oauth2.enabled: true`, AgentGate will automatically:
- Intercept unauthenticated AI clients and bounce them with `WWW-Authenticate` headers pointing to your `resource_metadata` IdP exactly per the MCP spec.
- Fetch and cache your IdP's public keys from `jwks_url` (with background rotation every `refresh_interval_seconds`).
- Cryptographically validate RS256/ES256 JWT signatures entirely in-memory using zero external dependencies.
- (Optional) Cleanly strip the JWT and inject `X-AgentGate-User` / `X-AgentGate-Scopes` upstream so your underlying MCP tools know *who* made the request, without ever having to write OAuth validation logic inside your tool code!

### 2. The Matrix Map (`mcp_servers`)
Think of `mcp_servers` as a dictionary mapping arbitrary *names* (`local_mcp_namespace`) to raw endpoints or executables (`upstream`). The key acts as your connection namespace!
- The LLM Agent dials: `http://localhost:8083/local_mcp_namespace/mcp`.
- AgentGate natively connects the resulting JSON-RPC stream to the local file system `npx` target.

### 3. Supported `upstream` Types
- `exec:...` → AgentGate becomes a `StdioBridge`, safely spawning underlying child processes, piping networking directly into STDIN buffers.
- `http://` / `https://` → AgentGate becomes a generic Reverse Proxy, seamlessly flushing your MCP payload against other persistent internet-connected APIs.

### 4. Rate Limiting (`agent_limits` and `policies.rate_limit`)
If an AI agent gets stuck inside an infinite tool-calling loop, AgentGate implements sliding-window lock logic in memory.
- **Global `agent_limits`**: Setting `max_requests_per_minute` at the file root enforces a blanket ceiling.
- **Per-Server `rate_limit`**: Granularly override the global limit for sensitive APIs (e.g. allowing only 10 executions every 60 seconds).
Any requests breaking these thresholds are returned a polite HTTP `429` effectively telling the LLM to halt and retry natively.

### 5. Semantic Rules (`parameter_rules`)
You don't just ban tools; you can parse the JSON parameters inside those tools! 
If an LLM has access to `read_file`, it generally can read ANY file on the system. By mapping an `argument_key` to a `not_match_regex`, AgentGate intercepts the JSON payload, grabs the `path` string, confirms it against the regex, and blocks it out-right before it reaches the MCP tool natively!
