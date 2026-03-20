# AgentGate Configuration Templates

Drop-in `agentgate.yaml` templates for popular MCP servers. Each file is fully functional—just replace placeholder values (marked with `<YOUR_...>`) and start AgentGate!

## Template Index

| Template | MCP Server | Use Case |
|---|---|---|
| [filesystem.yaml](filesystem.yaml) | `@modelcontextprotocol/server-filesystem` | Read/write local files with path sandboxing |
| [git.yaml](git.yaml) | `@modelcontextprotocol/server-git` | Read git repos, block destructive commands |
| [fetch.yaml](fetch.yaml) | `@modelcontextprotocol/server-fetch` | Web fetching with URL allowlist sandboxing |
| [memory.yaml](memory.yaml) | `@modelcontextprotocol/server-memory` | Persistent knowledge graph sidecar |
| [sqlite.yaml](sqlite.yaml) | `@modelcontextprotocol/server-sqlite` | Local SQLite with read-only enforcement |
| [postgres.yaml](postgres.yaml) | `@modelcontextprotocol/server-postgres` | Postgres with HITL on mutations |
| [github.yaml](github.yaml) | `@modelcontextprotocol/server-github` | GitHub API access with branch protection |
| [slack.yaml](slack.yaml) | `@modelcontextprotocol/server-slack` | Slack messaging with message approval |
| [brave-search.yaml](brave-search.yaml) | `@modelcontextprotocol/server-brave-search` | Web search with rate limiting |
| [devops-pipeline.yaml](devops-pipeline.yaml) | Multi-server | Complex template: CI/CD DevOps agent |
| [data-analyst.yaml](data-analyst.yaml) | Multi-server | Complex template: Data analyst agent |
