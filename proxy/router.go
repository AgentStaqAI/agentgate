package proxy

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
	"encoding/json"

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
	line := b
	if bytes.HasPrefix(b, []byte("data: ")) {
		line = bytes.TrimPrefix(b, []byte("data: "))
	}
	if err := json.Unmarshal(line, &env); err == nil && len(env.ID) > 0 {
		analytics.RecordOutput(m.serverName, string(env.ID), string(line))
	}

	// Fast path: check if this looks like our SSE endpoint notification
	// "data: /message?sessionId="
	if bytes.Contains(b, []byte("data: /message?sessionId=")) {
		newB := bytes.Replace(b, []byte("data: /message"), []byte(fmt.Sprintf("data: /%s/message", m.serverName)), 1)
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

	// ── OAuth 2.1 Discovery ───────────────────────────────────────────────────
	// Proactive IdP discovery for MCP clients. We redirect them directly to the IdP.
	if cfg.OAuth2.Enabled && cfg.OAuth2.ResourceMetadata != "" {
		discoveryHandler := func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, cfg.OAuth2.ResourceMetadata, http.StatusFound)
		}
		mux.HandleFunc("/.well-known/oauth-authorization-server", discoveryHandler)
		// Register for each server path in case clients assume the tool path is the base URL
		for name := range cfg.MCPServers {
			mux.HandleFunc(fmt.Sprintf("/%s/.well-known/oauth-authorization-server", name), discoveryHandler)
		}
		log.Println("[Router] Registered OAuth 2.1 discovery endpoints")
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
		hitlEnabled := srvConfig.Policies.HumanApproval != nil && len(srvConfig.Policies.HumanApproval.RequireForTools) > 0
		log.Printf("[Router] Registered %q → %s (HITL: %v)", name, srvConfig.Upstream, hitlEnabled)
	}

	return mux, cleanups
}
