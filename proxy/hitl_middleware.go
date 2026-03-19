package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/agentgate/agentgate/config"
	"github.com/agentgate/agentgate/hitl"
	"github.com/agentgate/agentgate/logger"
)

// HITLMiddleware intercepts tools/call requests that require human approval.
// It blocks the HTTP goroutine, fires the dispatcher (terminal/slack/discord/generic),
// then either forwards to next or returns a JSON-RPC error on deny/timeout.
func HITLMiddleware(cfg *config.Config, serverName string, serverConfig config.MCPServer, next http.Handler) http.Handler {
	ha := serverConfig.Policies.HumanApproval

	// Fast-path: if no tools require approval, bypass entirely.
	if len(ha.RequireForTools) == 0 {
		return next
	}

	requireSet := make(map[string]struct{}, len(ha.RequireForTools))
	for _, t := range ha.RequireForTools {
		requireSet[t] = struct{}{}
	}

	timeoutSecs := ha.TimeoutSeconds
	if timeoutSecs <= 0 {
		timeoutSecs = 60
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// ── Read & buffer body ────────────────────────────────────────────────
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// ── Parse envelope — fast-path non tools/call ─────────────────────────
		var envelope rpcEnvelope // defined in middleware.go
		if err := json.Unmarshal(bodyBytes, &envelope); err != nil || envelope.Method != "tools/call" {
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			next.ServeHTTP(w, r)
			return
		}

		// ── Extract tool name via SDK type ────────────────────────────────────
		var callReq callToolBody // defined in middleware.go
		if err := json.Unmarshal(bodyBytes, &callReq); err != nil {
			writeJSONRPCError(w, envelope.ID, jsonrpc.CodeInvalidRequest, "Invalid tools/call params")
			return
		}
		toolName := callReq.Params.Name

		// ── Check approval requirement ────────────────────────────────────────
		if _, needsApproval := requireSet[toolName]; !needsApproval {
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			next.ServeHTTP(w, r)
			return
		}

		// ── Coerce arguments to map[string]any ───────────────────────────────
		args, _ := callReq.Params.Arguments.(map[string]any)
		if args == nil {
			if raw, err := json.Marshal(callReq.Params.Arguments); err == nil {
				json.Unmarshal(raw, &args) //nolint:errcheck
			}
		}

		log.Printf("[HITL] [INFO] Tool %q requires human approval — blocking (timeout: %ds)", toolName, timeoutSecs)
		go logger.LogAuditAction(logger.AuditOptions{
			LogPath:    cfg.AuditLogPath,
			ServerName: serverName,
			ToolName:   toolName,
			Action:     "PAUSED",
			Reason:     "Waiting for HITL Approval",
			ClientIP:   r.RemoteAddr,
			RequestID:  string(envelope.ID),
			Arguments:  args,
			DurationMs: time.Since(start).Milliseconds(),
		})

		// ── Create in-memory state ────────────────────────────────────────────
		reqID, token, decisionChan, err := hitl.NewPendingApproval(serverName, toolName, args)
		if err != nil {
			log.Printf("[HITL] State allocation error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		log.Printf("[HITL] Pending approval created reqID=%s type=%s", reqID, ha.Webhook.Type)

		// ── Fire dispatcher (always in goroutine) ─────────────────────────────
		// terminal mode: the goroutine blocks on stdin and sends into decisionChan
		// all other modes: fires HTTP POST and returns immediately
		go hitl.Dispatch(ha.Webhook, cfg.Network.PublicURL, serverName, toolName, args, reqID, token, decisionChan)

		// ── Block: wait for decision or timeout ───────────────────────────────
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutSecs)*time.Second)
		defer cancel()

		select {
		case decision := <-decisionChan:
			if decision.Approved {
				log.Printf("[HITL] [INFO] reqID=%s APPROVED — forwarding to upstream", reqID)
				go logger.LogAuditAction(logger.AuditOptions{
					LogPath:    cfg.AuditLogPath,
					ServerName: serverName,
					ToolName:   toolName,
					Action:     "APPROVED",
					Reason:     "HITL Approved",
					ClientIP:   r.RemoteAddr,
					RequestID:  string(envelope.ID),
					Arguments:  args,
					Approver:   decision.Approver,
					DurationMs: time.Since(start).Milliseconds(),
				})
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				next.ServeHTTP(w, r)
			} else {
				log.Printf("[HITL] [ERROR] reqID=%s DENIED", reqID)
				go logger.LogAuditAction(logger.AuditOptions{
					LogPath:    cfg.AuditLogPath,
					ServerName: serverName,
					ToolName:   toolName,
					Action:     "BLOCKED",
					Reason:     "HITL Denied",
					ClientIP:   r.RemoteAddr,
					RequestID:  string(envelope.ID),
					Arguments:  args,
					Approver:   decision.Approver,
					DurationMs: time.Since(start).Milliseconds(),
				})
				writeJSONRPCError(w, envelope.ID, jsonrpc.CodeInternalError,
					fmt.Sprintf("Human denied execution of tool %q", toolName))
			}

		case <-ctx.Done():
			hitl.Delete(reqID) // aggressively clean up; no-op if already burned
			log.Printf("[HITL] [WARN] reqID=%s TIMED OUT after %ds", reqID, timeoutSecs)
			go logger.LogAuditAction(logger.AuditOptions{
				LogPath:    cfg.AuditLogPath,
				ServerName: serverName,
				ToolName:   toolName,
				Action:     "BLOCKED",
				Reason:     "HITL Timeout",
				ClientIP:   r.RemoteAddr,
				RequestID:  string(envelope.ID),
				Arguments:  args,
				DurationMs: time.Since(start).Milliseconds(),
			})
			writeJSONRPCError(w, envelope.ID, jsonrpc.CodeInternalError,
				fmt.Sprintf("Human approval timed out after %d seconds for tool %q", timeoutSecs, toolName))
		}
	})
}
