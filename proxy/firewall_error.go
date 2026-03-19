package proxy

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// writeJSONRPCError writes a spec-compliant JSON-RPC 2.0 error response.
// Per the MCP specification, errors are always returned with HTTP 200 OK —
// the error is conveyed in the JSON payload, not in the HTTP status code.
func writeJSONRPCError(w http.ResponseWriter, rawID json.RawMessage, code int, message string) {
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   jsonrpc.Error   `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      rawID,
		Error: jsonrpc.Error{
			Code:    int64(code),
			Message: message,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[Firewall] Failed to write JSON-RPC error response: %v", err)
	}
}
