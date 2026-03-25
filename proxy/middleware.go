package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agentgate/agentgate/analytics"
	"github.com/agentgate/agentgate/auth"
	"github.com/agentgate/agentgate/config"
	"github.com/agentgate/agentgate/logger"
)

type rpcEnvelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

type callToolBody struct {
	Params mcp.CallToolParams `json:"params"`
}

// SemanticMiddleware is the AgentGate semantic firewall. It intercepts every
// request, enforces Bearer auth, then — for tools/call requests — applies RBAC
// and regex sandboxing. Blocked requests get spec-compliant JSON-RPC 2.0 errors.
func SemanticMiddleware(cfg *config.Config, serverName string, serverConfig config.MCPServer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// ── Step 1: Auth ──────────────────────────────────────────────────────
		// When OAuth2 is enabled, JWTAuthMiddleware (outer layer) already validated
		// the JWT and enriched the context. Skip the static token check entirely.
		if !cfg.OAuth2.Enabled {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				log.Printf("[Middleware] [ERROR] Missing or malformed Authorization header")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token != cfg.Auth.RequireBearerToken {
				log.Printf("[Middleware] [ERROR] Invalid bearer token")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		// Non-POST requests pass through directly (SSE GET, health checks, etc.).
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// ── Step 2: Capture body bytes ───────────────────────────────────────
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[Middleware] [ERROR] Failed to read body: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(bodyBytes) == 0 {
			http.Error(w, "Bad Request: Empty Body", http.StatusBadRequest)
			return
		}

		// ── Step 3: Parse JSON-RPC envelope ─────────────────────────────────
		var envelope rpcEnvelope
		if err := json.Unmarshal(bodyBytes, &envelope); err != nil {
			log.Printf("[Middleware] [ERROR] Invalid JSON-RPC envelope: %v", err)
			http.Error(w, "Bad Request: Invalid JSON", http.StatusBadRequest)
			return
		}

		// Only tools/call payloads require firewall inspection.
		if envelope.Method != "tools/call" {
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			next.ServeHTTP(w, r)
			return
		}

		var callReq callToolBody
		if err := json.Unmarshal(bodyBytes, &callReq); err != nil {
			log.Printf("[Middleware] [ERROR] Failed to parse CallToolParams: %v", err)
			writeJSONRPCError(w, envelope.ID, jsonrpc.CodeInvalidRequest, "Invalid tools/call params")
			return
		}

		toolName := callReq.Params.Name

		// ── Step 4: Global Panic Button ──────────────────────────────────────
		if IsPaused.Load() {
			log.Printf("[Middleware] [WARN] AgentGate is PAUSED. Rejecting tool call: %q", toolName)
			go logger.LogAuditAction(logger.AuditOptions{
				LogPath:    cfg.AuditLogPath,
				ServerName: serverName,
				ToolName:   toolName,
				Action:     "BLOCKED",
				Reason:     "Global Panic Switch Engaged",
				ClientIP:   r.RemoteAddr,
				DurationMs: time.Since(start).Milliseconds(),
			})
			argsMap, _ := callReq.Params.Arguments.(map[string]any)
			analytics.RecordRequest(serverName, "blocked_panic_button", auth.SubFromContext(r.Context()), string(envelope.ID), string(bodyBytes), toolName, argsMap, "Global Panic Switch Engaged", time.Since(start).Milliseconds())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error": "AgentGate is PAUSED. All autonomous actions are suspended."}`))
			return
		}

		// ── Step 5: Rate Limiting ────────────────────────────────────────────
		// Per-server rate_limit takes precedence over the global agent_limits.
		maxReqs := cfg.AgentLimits.MaxRequestsPerMinute
		window := time.Minute
		if serverConfig.Policies.RateLimit != nil && serverConfig.Policies.RateLimit.MaxRequests > 0 {
			maxReqs = serverConfig.Policies.RateLimit.MaxRequests
			if serverConfig.Policies.RateLimit.WindowSeconds > 0 {
				window = time.Duration(serverConfig.Policies.RateLimit.WindowSeconds) * time.Second
			}
		}
		if maxReqs > 0 {
			if !Allow(serverName, toolName, maxReqs, window) {
				log.Printf("[Middleware] [WARN] Rate limit exceeded for %s/%s", serverName, toolName)
				reason := "Rate Limit Exceeded (Infinite Loop Protection)"
				go logger.LogAuditAction(logger.AuditOptions{
					LogPath:    cfg.AuditLogPath,
					ServerName: serverName,
					ToolName:   toolName,
					Action:     "BLOCKED",
					Reason:     reason,
					ClientIP:   r.RemoteAddr,
					RequestID:  string(envelope.ID),
					Arguments:  callReq.Params.Arguments,
					DurationMs: time.Since(start).Milliseconds(),
				})
				analytics.RecordRequest(serverName, "blocked_rate_limit", auth.SubFromContext(r.Context()), string(envelope.ID), string(bodyBytes), toolName, callReq.Params.Arguments.(map[string]any), reason, time.Since(start).Milliseconds())

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error": "Rate limit exceeded. Infinite loop protection engaged."}`))
				return
			}
		}

		// ── Step 6: RBAC — allowed/blocked tools check ───────────────────────
		accessMode := serverConfig.Policies.AccessMode
		if accessMode == "" {
			accessMode = "allowlist" // Fail-secure default
		}

		if accessMode == "blocklist" {
			toolBlocked := false
			for _, blocked := range serverConfig.Policies.BlockedTools {
				if toolName == blocked {
					toolBlocked = true
					break
				}
			}
			if toolBlocked {
				msg := fmt.Sprintf("Security Block: Tool explicitly blocked by AgentGate blocklist: %q", toolName)
				log.Printf("[Middleware] [ERROR] RBAC block: %s", msg)
				go logger.LogAuditAction(logger.AuditOptions{
					LogPath: cfg.AuditLogPath, ServerName: serverName, ToolName: toolName,
					Action: "BLOCKED", Reason: "explicit blocklist", ClientIP: r.RemoteAddr,
					RequestID: string(envelope.ID), Arguments: callReq.Params.Arguments,
					DurationMs: time.Since(start).Milliseconds(),
				})
				argsMap, _ := callReq.Params.Arguments.(map[string]any)
				analytics.RecordRequest(serverName, "blocked_rbac", auth.SubFromContext(r.Context()), string(envelope.ID), string(bodyBytes), toolName, argsMap, "Explicit blocklist", time.Since(start).Milliseconds())
				writeJSONRPCError(w, envelope.ID, jsonrpc.CodeMethodNotFound, msg)
				return
			}
		} else {
			toolAllowed := false
			for _, allowed := range serverConfig.Policies.AllowedTools {
				if toolName == allowed {
					toolAllowed = true
					break
				}
			}
			if !toolAllowed {
				msg := "Security Block: Tool not explicitly allowed by AgentGate allowlist."
				log.Printf("[Middleware] [ERROR] RBAC block (%q not in allowlist)", toolName)
				go logger.LogAuditAction(logger.AuditOptions{
					LogPath: cfg.AuditLogPath, ServerName: serverName, ToolName: toolName,
					Action: "BLOCKED", Reason: "missing from allowlist", ClientIP: r.RemoteAddr,
					RequestID: string(envelope.ID), Arguments: callReq.Params.Arguments,
					DurationMs: time.Since(start).Milliseconds(),
				})
				argsMap, _ := callReq.Params.Arguments.(map[string]any)
				analytics.RecordRequest(serverName, "blocked_rbac", auth.SubFromContext(r.Context()), string(envelope.ID), string(bodyBytes), toolName, argsMap, "Missing from allowlist", time.Since(start).Milliseconds())
				writeJSONRPCError(w, envelope.ID, jsonrpc.CodeMethodNotFound, msg)
				return
			}
		}

		// ── Step 7: Regex Sandbox — parameter_rules check ───────────────────
		if rules, exists := serverConfig.Policies.ParameterRules[toolName]; exists {
			args, ok := callReq.Params.Arguments.(map[string]any)
			if !ok {
				if rawArgs, err := json.Marshal(callReq.Params.Arguments); err == nil {
					json.Unmarshal(rawArgs, &args)
				}
			}

			for _, rule := range rules {
				if rule.CompiledRegex == nil {
					continue
				}
				if argVal, hasArg := args[rule.Argument]; hasArg {
					argStr := fmt.Sprintf("%v", argVal)
					if rule.CompiledRegex.MatchString(argStr) {
						errMsg := rule.ErrorMsg
						if errMsg == "" {
							errMsg = fmt.Sprintf("Security Block: Argument %q violates regex policy.", rule.Argument)
						}
						log.Printf("[Middleware] [ERROR] Regex sandbox triggered for argument %q: %s", rule.Argument, errMsg)
						go logger.LogAuditAction(logger.AuditOptions{
							LogPath: cfg.AuditLogPath, ServerName: serverName, ToolName: toolName,
							Action: "BLOCKED", Reason: "regex sandbox match", ClientIP: r.RemoteAddr,
							RequestID: string(envelope.ID), Arguments: callReq.Params.Arguments,
							DurationMs: time.Since(start).Milliseconds(),
						})
						analytics.RecordRequest(serverName, "blocked_regex", auth.SubFromContext(r.Context()), string(envelope.ID), string(bodyBytes), toolName, args, errMsg, time.Since(start).Milliseconds())
						writeJSONRPCError(w, envelope.ID, jsonrpc.CodeInvalidParams, errMsg)
						return
					}
				}
			}
		}

		// ── Step 8: Pass-through ─────────────────────────────────────────────
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		go logger.LogAuditAction(logger.AuditOptions{
			LogPath: cfg.AuditLogPath, ServerName: serverName, ToolName: toolName,
			Action: "ALLOWED", Reason: "passed semantic firewall", ClientIP: r.RemoteAddr,
			RequestID: string(envelope.ID), Arguments: callReq.Params.Arguments,
			DurationMs: time.Since(start).Milliseconds(),
		})
		argsMap, _ := callReq.Params.Arguments.(map[string]any)
		analytics.RecordRequest(serverName, "allowed", auth.SubFromContext(r.Context()), string(envelope.ID), string(bodyBytes), toolName, argsMap, "Passed Semantic Firewall", time.Since(start).Milliseconds())
		next.ServeHTTP(w, r)
	})
}
