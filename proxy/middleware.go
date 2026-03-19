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

	"github.com/agentgate/agentgate/config"
	"github.com/agentgate/agentgate/logger"
)

// rpcEnvelope is a minimal struct to extract the method and id from any
// JSON-RPC 2.0 message without importing internal SDK packages.
type rpcEnvelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

// callToolBody is a thin wrapper to reach Params using the SDK's canonical
// mcp.CallToolParams type — giving us type-safe access to Name and Arguments.
type callToolBody struct {
	Params mcp.CallToolParams `json:"params"`
}

// SemanticMiddleware is the AgentGate semantic firewall.
// It intercepts every request, enforces Bearer auth, then — for tools/call
// requests — applies RBAC (allowed_tools) and regex sandboxing (parameter_rules).
// Blocked requests receive spec-compliant JSON-RPC 2.0 error responses (HTTP 200).
// All other requests pass through to the upstream handler unmodified.
func SemanticMiddleware(cfg *config.Config, serverName string, serverConfig config.MCPServer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		if IsPaused.Load() {
			log.Printf("[Middleware] [WARN] AgentGate is PAUSED. Rejecting autonomous request.")
			go logger.LogAuditAction(logger.AuditOptions{
				LogPath:    cfg.AuditLogPath,
				ServerName: serverName,
				ToolName:   "N/A",
				Action:     "BLOCKED",
				Reason:     "Global Panic Switch Engaged",
				ClientIP:   r.RemoteAddr,
				DurationMs: time.Since(start).Milliseconds(),
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error": "AgentGate is PAUSED. All autonomous actions are suspended."}`))
			return
		}

		log.Printf("[Middleware] ▶ %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// ── Step 1: Bearer token auth ─────────────────────────────────────────
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
		log.Printf("[Middleware] ✓ Auth OK")

		// Non-POST requests are passed through directly (e.g. health checks).
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// ── Step 2: Capture body bytes ────────────────────────────────────────
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("[Middleware] ✗ Failed to read body: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(bodyBytes) == 0 {
			log.Printf("[Middleware] ✗ Empty body")
			http.Error(w, "Bad Request: Empty Body", http.StatusBadRequest)
			return
		}
		log.Printf("[Middleware] Body (%d bytes): %s", len(bodyBytes), string(bodyBytes))

		// ── Step 3: SDK-typed parsing ─────────────────────────────────────────
		// First pass: extract method and id from any JSON-RPC message.
		var envelope rpcEnvelope
		if err := json.Unmarshal(bodyBytes, &envelope); err != nil {
			log.Printf("[Middleware] ✗ Invalid JSON-RPC envelope: %v", err)
			http.Error(w, "Bad Request: Invalid JSON", http.StatusBadRequest)
			return
		}
		log.Printf("[Middleware] JSON-RPC method=%q id=%s", envelope.Method, envelope.ID)

		// Only tools/call payloads require firewall inspection.
		// Other MCP methods (initialize, tools/list, ping, etc.) pass through.
		if envelope.Method != "tools/call" {
			log.Printf("[Middleware] Method %q is not tools/call — passing through", envelope.Method)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			next.ServeHTTP(w, r)
			return
		}

		// Second pass: use the official mcp.CallToolParams for type-safe field access.
		var callReq callToolBody
		if err := json.Unmarshal(bodyBytes, &callReq); err != nil {
			log.Printf("[Middleware] ✗ Failed to parse CallToolParams: %v", err)
			writeJSONRPCError(w, envelope.ID, jsonrpc.CodeInvalidRequest, "Invalid tools/call params")
			return
		}

		toolName := callReq.Params.Name

		if cfg.AgentLimits.MaxRequestsPerMinute > 0 {
			if !Allow(serverName, toolName, cfg.AgentLimits.MaxRequestsPerMinute, time.Minute) {
				log.Printf("[Middleware] [WARN] Rate limit exceeded for %s/%s", serverName, toolName)
				go logger.LogAuditAction(logger.AuditOptions{
					LogPath:    cfg.AuditLogPath,
					ServerName: serverName,
					ToolName:   toolName,
					Action:     "BLOCKED",
					Reason:     "Rate Limit Exceeded (Infinite Loop Protection)",
					ClientIP:   r.RemoteAddr,
					RequestID:  string(envelope.ID),
					Arguments:  callReq.Params.Arguments,
					DurationMs: time.Since(start).Milliseconds(),
				})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error": "Rate limit exceeded. Infinite loop protection engaged."}`))
				return
			}
		}

		// ── Step 4a: RBAC — allowed tools check ──────────────────────────────
		accessMode := serverConfig.Policies.AccessMode
		if accessMode == "" {
			accessMode = "allowlist" // Fail-secure default
		}

		if accessMode == "blocklist" {
			// In blocklist mode, we check if the tool is explicitly forbidden.
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
					LogPath:    cfg.AuditLogPath,
					ServerName: serverName,
					ToolName:   toolName,
					Action:     "BLOCKED",
					Reason:     "explicit blocklist",
					ClientIP:   r.RemoteAddr,
					RequestID:  string(envelope.ID),
					Arguments:  callReq.Params.Arguments,
					DurationMs: time.Since(start).Milliseconds(),
				})
				writeJSONRPCError(w, envelope.ID, jsonrpc.CodeMethodNotFound, msg)
				return
			}
			log.Printf("[Middleware] ✓ RBAC: tool %q implicitly allowed (not in blocklist)", toolName)
		} else {
			// Default allowlist mode: we check if the tool is explicitly permitted.
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
					LogPath:    cfg.AuditLogPath,
					ServerName: serverName,
					ToolName:   toolName,
					Action:     "BLOCKED",
					Reason:     "missing from allowlist",
					ClientIP:   r.RemoteAddr,
					RequestID:  string(envelope.ID),
					Arguments:  callReq.Params.Arguments,
					DurationMs: time.Since(start).Milliseconds(),
				})
				writeJSONRPCError(w, envelope.ID, jsonrpc.CodeMethodNotFound, msg)
				return
			}
			log.Printf("[Middleware] ✓ RBAC: tool %q is allowed", toolName)
		}

		// ── Step 4b: Regex sandbox — parameter_rules check ───────────────────
		if rule, exists := serverConfig.Policies.ParameterRules[toolName]; exists && rule.CompiledRegex != nil {
			// Arguments is typed as `any` in the SDK — it unmarshals as map[string]any.
			args, ok := callReq.Params.Arguments.(map[string]any)
			if !ok {
				// Try re-unmarshaling from raw JSON if the type assertion fails.
				if rawArgs, err := json.Marshal(callReq.Params.Arguments); err == nil {
					json.Unmarshal(rawArgs, &args)
				}
			}

			if argVal, hasArg := args[rule.Argument]; hasArg {
				argStr := fmt.Sprintf("%v", argVal)
				if rule.CompiledRegex.MatchString(argStr) {
					log.Printf("[Middleware] [ERROR] Regex sandbox triggered: %s", rule.ErrorMsg)
					go logger.LogAuditAction(logger.AuditOptions{
						LogPath:    cfg.AuditLogPath,
						ServerName: serverName,
						ToolName:   toolName,
						Action:     "BLOCKED",
						Reason:     "regex sandbox match",
						ClientIP:   r.RemoteAddr,
						RequestID:  string(envelope.ID),
						Arguments:  callReq.Params.Arguments,
						DurationMs: time.Since(start).Milliseconds(),
					})
					writeJSONRPCError(w, envelope.ID, jsonrpc.CodeInvalidParams, rule.ErrorMsg)
					return
				}
				log.Printf("[Middleware] ✓ Param passed regex check")
			}
		}

		// ── Step 5: Pass-through ──────────────────────────────────────────────
		// Restore body so the downstream handler (StdioBridge or ReverseProxy) can read it.
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		go logger.LogAuditAction(logger.AuditOptions{
			LogPath:    cfg.AuditLogPath,
			ServerName: serverName,
			ToolName:   toolName,
			Action:     "ALLOWED",
			Reason:     "passed semantic firewall",
			ClientIP:   r.RemoteAddr,
			RequestID:  string(envelope.ID),
			Arguments:  callReq.Params.Arguments,
			DurationMs: time.Since(start).Milliseconds(),
		})
		next.ServeHTTP(w, r)
	})
}
