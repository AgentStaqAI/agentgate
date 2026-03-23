package auth

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/agentgate/agentgate/config"
)

// JWTAuthMiddleware is the OAuth 2.1 Resource Server interceptor.
//
// Behavior:
//   - If oauth2.enabled = false: passes through immediately (backward compatible).
//   - No/invalid Authorization header: HTTP 401 + WWW-Authenticate challenge.
//   - Valid JWT: enriches context with sub+scopes, strips Authorization header,
//     optionally injects X-AgentGate-User header for the upstream MCP server.
//   - Passes to next handler.
func JWTAuthMiddleware(cfg *config.Config, cache *JWKSCache, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fast path: OAuth2 not enabled — skip this entire layer.
		if !cfg.OAuth2.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// ── Extract Bearer token ──────────────────────────────────────────────
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			writeWWWAuthenticate(w, cfg.OAuth2.ResourceMetadata, "missing_token", "Authorization: Bearer <token> is required")
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// ── Validate JWT ──────────────────────────────────────────────────────
		sub, scopes, err := ValidateJWT(tokenString, cache, cfg.OAuth2.Issuer, cfg.OAuth2.Audience)
		if err != nil {
			log.Printf("[JWTAuth] [ERROR] Token validation failed from %s: %v", r.RemoteAddr, err)
			errCode := classifyError(err)
			writeWWWAuthenticate(w, cfg.OAuth2.ResourceMetadata, errCode, err.Error())
			return
		}

		log.Printf("[JWTAuth] Token valid — sub=%q scopes=%v from %s", sub, scopes, r.RemoteAddr)

		// ── Enrich context with claims ────────────────────────────────────────
		ctx := ContextWithClaims(r.Context(), sub, scopes)
		r = r.WithContext(ctx)

		// ── Strip upstream Authorization header (don't leak the JWT) ─────────
		// We replace the original header with a custom user identity header
		// so the upstream MCP server knows who made the request without having
		// access to the raw credential.
		r.Header.Del("Authorization")
		if cfg.OAuth2.InjectUserHeader {
			r.Header.Set("X-AgentGate-User", sub)
			if len(scopes) > 0 {
				r.Header.Set("X-AgentGate-Scopes", strings.Join(scopes, " "))
			}
		}

		next.ServeHTTP(w, r)
	})
}

// writeWWWAuthenticate sends an RFC 6750-compliant 401 response.
//
// Format per MCP spec:
//
//	WWW-Authenticate: Bearer realm="mcp", resource_metadata="<url>",
//	                          error="<code>", error_description="<msg>"
func writeWWWAuthenticate(w http.ResponseWriter, resourceMetadata, errCode, errDesc string) {
	challenge := fmt.Sprintf(
		`Bearer realm="mcp", resource_metadata="%s", error="%s", error_description="%s"`,
		resourceMetadata, errCode, errDesc,
	)
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"unauthorized","error_description":"` + errDesc + `"}`))
}

// classifyError maps a validation error to an RFC 6750 error code string.
func classifyError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "expired") {
		return "invalid_token"
	}
	if strings.Contains(msg, "signature") {
		return "invalid_token"
	}
	if strings.Contains(msg, "issuer") || strings.Contains(msg, "audience") {
		return "invalid_token"
	}
	if strings.Contains(msg, "malformed") || strings.Contains(msg, "algorithm") {
		return "invalid_token"
	}
	return "invalid_token"
}
