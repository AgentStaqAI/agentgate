package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// MCPClient wraps a ClientTransport to orchestrate the strict MCP connection handshake
// and tolerate dirty streams or non-compliant formatters.
type MCPClient struct {
	transport ClientTransport
	SessionID string
}

func NewMCPClient(t ClientTransport) *MCPClient {
	return &MCPClient{transport: t}
}

func (c *MCPClient) Discover(ctx context.Context) ([]MCPTool, error) {
	defer c.transport.Close()

	if err := c.transport.Connect(ctx); err != nil {
		return nil, fmt.Errorf("transport connect failed: %w", err)
	}

	c.SessionID = ""

	// STEP 1: Initialize
	initReq := []byte(`{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "AgentGate", "version": "1.0.0"}}}`)
	if err := c.transport.Send(initReq); err != nil {
		return nil, fmt.Errorf("initialize send failed: %w", err)
	}

	// Wait for initialize response
	initSuccess := false
	var lastErr error
	for i := 0; i < 10; i++ { // Try reading up to 10 messages safely without hanging
		raw, err := c.transport.Receive(ctx)

		if err != nil {
			lastErr = err
			break
		}

		resp, err := parseTolerantResponse(raw)
		if err != nil {
			continue // Ignore garbage preamble prints
		}

		if resp.ID != nil {
			idVal := fmt.Sprintf("%v", resp.ID)
			if idVal == "1" || idVal == "1.0" {
				// STEP 2: Session Extraction
				if sess, ok := resp.Result["mcp-session-id"].(string); ok {
					c.SessionID = sess
				} else if sess, ok := resp.Result["x-session-id"].(string); ok {
					c.SessionID = sess
				} else if sess, ok := resp.Result["sessionId"].(string); ok {
					c.SessionID = sess
				}

				// Ensure HTTP transport picks it up for subsequent stateful loops
				if httpT, ok := c.transport.(*HTTPTransport); ok {
					if httpT.SessionID == "" {
						httpT.SessionID = c.SessionID
					}
				}
				initSuccess = true
				break
			}
		}
	}

	if !initSuccess {
		if lastErr != nil {
			return nil, fmt.Errorf("failed to complete handshake: %w", lastErr)
		}
		return nil, fmt.Errorf("failed to complete handshake: no initialize response")
	}

	// STEP 3: Initialized Notification
	notifyReq := []byte(`{"jsonrpc": "2.0", "method": "notifications/initialized"}`)
	if err := c.transport.Send(notifyReq); err != nil {
		// Just a notification broadcast, ignore send errors natively
	}

	// STEP 4: Fallback Discovery Loop
	// We increment the ID iteratively so that if an earlier variant times out and responds later, we only match the actual variant block checking it!
	variants := []struct {
		ID  int
		Req string
	}{
		{ID: 2, Req: `{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}`},
		{ID: 3, Req: `{"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}`},
		{ID: 4, Req: `{"jsonrpc": "2.0", "id": 4, "method": "tool/list"}`},
		{ID: 5, Req: `{"jsonrpc": "2.0", "id": 5, "method": "tool/list", "params": {}}`},
		{ID: 6, Req: `{"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": null}`},
	}

	var toolsFound []MCPTool

	for _, v := range variants {
		if err := c.transport.Send([]byte(v.Req)); err != nil {
			continue
		}

		var innerBreak bool
		var matchedVariant bool

		for j := 0; j < 5; j++ {
			receiveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			raw, err := c.transport.Receive(receiveCtx)
			cancel()

			if err != nil {
				innerBreak = true
				break
			}

			resp, err := parseTolerantResponse(raw)
			if err != nil {
				continue
			}

			if resp.ID != nil {
				idVal := fmt.Sprintf("%v", resp.ID)
				expectedID := fmt.Sprintf("%d", v.ID)

				if idVal == expectedID || idVal == expectedID+".0" {
					matchedVariant = true
					if len(resp.Result) > 0 {
						if rawTools, ok := resp.Result["tools"]; ok {
							b, _ := json.Marshal(rawTools)
							json.Unmarshal(b, &toolsFound) //nolint:errcheck
							return toolsFound, nil
						}
					}
					// If we get an error response for this exact ID, or a missing tools array, we break natively to skip to next variant.
					innerBreak = true
					break
				}
			}
		}

		if matchedVariant || innerBreak {
			continue
		}
	}

	return nil, fmt.Errorf("failed to discover tools across all fallback variants")
}
