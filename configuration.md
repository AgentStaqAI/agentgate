# Configuration Guide (`agentgate.yaml`)

AgentGate relies on an overarching `agentgate.yaml` file to define routing namespaces, strict network port allocations, and fine-grained Agent security policies.

## Example Structure

```yaml
auth:
  require_bearer_token: "secret_admin_token_123"

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

### 1. The Matrix Map (`mcp_servers`)
Think of `mcp_servers` as a dictionary mapping arbitrary *names* (`local_mcp_namespace`) to raw endpoints or executables (`upstream`). The key acts as your connection namespace!
- The LLM Agent dials: `http://localhost:8083/local_mcp_namespace/mcp`.
- AgentGate natively connects the resulting JSON-RPC stream to the local file system `npx` target.

### 2. Supported `upstream` Types
- `exec:...` → AgentGate becomes a `StdioBridge`, safely spawning underlying child processes, piping networking directly into STDIN buffers.
- `http://` / `https://` → AgentGate becomes a generic Reverse Proxy, seamlessly flushing your MCP payload against other persistent internet-connected APIs.

### 3. Rate Limiting (`agent_limits` and `policies.rate_limit`)
If an AI agent gets stuck inside an infinite tool-calling loop, AgentGate implements sliding-window lock logic in memory.
- **Global `agent_limits`**: Setting `max_requests_per_minute` at the file root enforces a blanket ceiling.
- **Per-Server `rate_limit`**: Granularly override the global limit for sensitive APIs (e.g. allowing only 10 executions every 60 seconds).
Any requests breaking these thresholds are returned a polite HTTP `429` effectively telling the LLM to halt and retry natively.

### 4. Semantic Rules (`parameter_rules`)
You don't just ban tools; you can parse the JSON parameters inside those tools! 
If an LLM has access to `read_file`, it generally can read ANY file on the system. By mapping an `argument_key` to a `not_match_regex`, AgentGate intercepts the JSON payload, grabs the `path` string, confirms it against the regex, and blocks it out-right before it reaches the MCP tool natively!
