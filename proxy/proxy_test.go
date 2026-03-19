package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/agentgate/agentgate/config"
)

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func TestSemanticMiddleware(t *testing.T) {
	// Mock upstream server
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Echo back the body to verify it was passed unchanged
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})

	upstreamServer := httptest.NewServer(upstreamHandler)
	defer upstreamServer.Close()

	// Setup Config
	cfg := &config.Config{
		Auth: config.AuthConfig{
			RequireBearerToken: "secret_token",
		},
		MCPServers: map[string]config.MCPServer{
			"test_server": {
				Upstream: upstreamServer.URL,
				Policies: config.SecurityPolicy{
					AllowedTools: []string{"safe_tool", "data_tool"},
					ParameterRules: map[string]config.ParameterRule{
						"safe_tool": {
							Argument:      "query",
							NotMatchRegex: "(?i)(DROP|DELETE)",
							ErrorMsg:      "Blocked Query",
							CompiledRegex: regexp.MustCompile("(?i)(DROP|DELETE)"),
						},
					},
				},
			},
		},
	}

	// Setup Router
	router := SetupRouter(context.Background(), cfg)
	proxyServer := httptest.NewServer(router)
	defer proxyServer.Close()

	tests := []struct {
		name           string
		token          string
		method         string
		params         map[string]interface{}
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid request allowed",
			token:          "secret_token",
			method:         "safe_tool",
			params:         map[string]interface{}{"query": "SELECT * FROM users"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid token blocked",
			token:          "wrong",
			method:         "safe_tool",
			params:         map[string]interface{}{"query": "SELECT * FROM users"},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Tool not allowed blocked",
			token:          "secret_token",
			method:         "unauthorized_tool",
			params:         map[string]interface{}{},
			expectedStatus: http.StatusOK,
			expectedBody:   "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Security Block: Tool not explicitly allowed by AgentGate allowlist.\"}}\n",
		},
		{
			name:           "Regex match blocked",
			token:          "secret_token",
			method:         "safe_tool",
			params:         map[string]interface{}{"query": "DROP TABLE users"},
			expectedStatus: http.StatusOK,
			expectedBody:   "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"Blocked Query\"}}\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody := JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "tools/call",
			}
			callParams := map[string]interface{}{
				"name": tt.method,
			}
			if tt.params != nil {
				callParams["arguments"] = tt.params
			}
			paramBytes, _ := json.Marshal(callParams)
			reqBody.Params = paramBytes

			reqBytes, _ := json.Marshal(reqBody)
			req, _ := http.NewRequest("POST", proxyServer.URL+"/test_server", bytes.NewBuffer(reqBytes))
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			if tt.expectedBody != "" {
				body, _ := io.ReadAll(resp.Body)
				if string(body) != tt.expectedBody {
					t.Errorf("Expected body %q, got %q", tt.expectedBody, string(body))
				}
			}
		})
	}
}
