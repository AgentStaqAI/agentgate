package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/agentgate/agentgate/analytics"
	"github.com/agentgate/agentgate/auth"
	"github.com/agentgate/agentgate/config"
	"github.com/agentgate/agentgate/hitl"
)

// sseModifier intercepts and rewrites outbound SSE data payloads to include the namespace.
type sseModifier struct {
	http.ResponseWriter
	serverName string
}

func (m *sseModifier) Write(b []byte) (int, error) {
	// Intercept the JSON-RPC Output payload returning to Agent
	var env struct {
		ID json.RawMessage `json:"id"`
	}
	// Extract the trailing payload following `data: `
	dataPrefix := []byte("data: ")
	if idx := bytes.Index(b, dataPrefix); idx != -1 {
		lineStart := idx + len(dataPrefix)
		lineEnd := bytes.IndexByte(b[lineStart:], '\n')
		var jsonLine []byte
		if lineEnd == -1 {
			jsonLine = b[lineStart:]
		} else {
			jsonLine = b[lineStart : lineStart+lineEnd]
		}
		if err := json.Unmarshal(jsonLine, &env); err == nil && len(env.ID) > 0 {
			analytics.RecordOutput(m.serverName, string(env.ID), string(jsonLine))
		}
	} else {
		// Fallback for non-SSE JSON bodies
		if err := json.Unmarshal(b, &env); err == nil && len(env.ID) > 0 {
			analytics.RecordOutput(m.serverName, string(env.ID), string(b))
		}
	}

	// Fast path: dynamic SSE endpoint notification intercept
	// Handles both standard `data: /message?sessionId=` and absolute nested `data: /mcp/message?sessionId=`
	if bytes.Contains(b, []byte("data: /")) && bytes.Contains(b, []byte("?sessionId=")) {
		newB := bytes.Replace(b, []byte("data: /"), []byte(fmt.Sprintf("data: /%s/", m.serverName)), 1)
		return m.ResponseWriter.Write(newB)
	}
	return m.ResponseWriter.Write(b)
}

// SetupRouter creates the top-level HTTP mux.
//
// Route priority:
//  1. /_agentgate/hitl/*  — internal HITL callbacks (no auth, no middleware)
//  2. /{server-name}      — MCP server routes (JWTAuth → SemanticMiddleware → HITL → Upstream)
func SetupRouter(ctx context.Context, cfg *config.Config, jwksCache *auth.JWKSCache) (http.Handler, []func()) {
	mux := http.NewServeMux()
	var cleanups []func()

	// ── Internal HITL callback routes ─────────────────────────────────────────
	// These bypass all auth middleware — a human clicking a Slack/Discord button
	// doesn't have the Bearer token.
	mux.HandleFunc("/_agentgate/hitl/approve", hitl.GetCallbackHandler(true))
	mux.HandleFunc("/_agentgate/hitl/deny", hitl.GetCallbackHandler(false))
	mux.HandleFunc("/_agentgate/hitl/slack-interactive", hitl.SlackInteractiveHandler())
	log.Println("[Router] Registered HITL callback routes")

	// ── MCP Authorization Discovery (PRM) ─────────────────────────────────────
	if cfg.OAuth2.Enabled {
		prmHandler := func(w http.ResponseWriter, r *http.Request) {
			prm := map[string]interface{}{
				"resource":              cfg.OAuth2.Resource,
				"authorization_servers": []string{cfg.OAuth2.Issuer},
				"scopes_supported":      cfg.OAuth2.ScopesSupported,
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(prm)
		}

		mux.HandleFunc("/.well-known/oauth-protected-resource", prmHandler)
		// Register for each server path as well
		for name := range cfg.MCPServers {
			mux.HandleFunc(fmt.Sprintf("/%s/.well-known/oauth-protected-resource", name), prmHandler)
		}
		log.Println("[Router] Registered MCP Authorization PRM endpoints")
	}

	// ── MCP server routes ─────────────────────────────────────────────────────
	for name, srvConfig := range cfg.MCPServers {
		var baseHandler http.Handler

		if strings.HasPrefix(srvConfig.Upstream, "exec:") {
			cmdString := strings.TrimSpace(strings.TrimPrefix(srvConfig.Upstream, "exec:"))
			bridge, err := NewStdioBridge(ctx, name, cmdString, srvConfig.Env)
			if err != nil {
				log.Printf("[Router] Warning: Failed to start StdioBridge for %s: %v. Continuing without component...", name, err)
				continue
			}
			cleanups = append(cleanups, func() {
				if err := bridge.Close(); err != nil {
					log.Printf("[Router] Warning: StdioBridge cleanup failed for %s: %v", name, err)
				}
			})
			baseHandler = bridge
		} else {
			targetURL, err := url.Parse(srvConfig.Upstream)
			if err != nil {
				log.Printf("[Router] Warning: Invalid upstream URL for %s: %v. Continuing without component...", name, err)
				continue
			}
			proxy := httputil.NewSingleHostReverseProxy(targetURL)

			// Override Director to handle duplicated proxy target paths.
			// The UI generates strict snippet queries (/math/mcp) targeting absolute Upstreams (/mcp).
			// StripPrefix cleans it to /mcp which httputil blindly joins into /mcp/mcp.
			originalDirector := proxy.Director
			proxy.Director = func(req *http.Request) {
				originalDirector(req)
				if targetURL.Path != "" && targetURL.Path != "/" {
					duplicatedPath := targetURL.Path + targetURL.Path
					if strings.HasPrefix(req.URL.Path, duplicatedPath) {
						req.URL.Path = strings.Replace(req.URL.Path, duplicatedPath, targetURL.Path, 1)
					}
				}
			}

			proxy.FlushInterval = time.Millisecond * 10

			// Wrap the proxy to inject our SSE namespace rewriter
			srvName := name
			baseHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				modWriter := &sseModifier{ResponseWriter: w, serverName: srvName}
				proxy.ServeHTTP(modWriter, r)
			})
		}

		// Middleware chain (innermost → outermost):
		//   Upstream ← HITLMiddleware ← SemanticMiddleware ← JWTAuthMiddleware
		handler := auth.JWTAuthMiddleware(
			cfg,
			jwksCache,
			SemanticMiddleware(cfg, name, srvConfig,
				HITLMiddleware(cfg, name, srvConfig, baseHandler),
			),
		)

		path := "/" + name
		mux.Handle(path, http.StripPrefix(path, handler))
		mux.Handle(path+"/", http.StripPrefix(path, handler))
		log.Printf("[Router] Registered %q → %s", name, srvConfig.Upstream)
	}

	return mux, cleanups
}
