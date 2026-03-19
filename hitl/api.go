package hitl

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// GetCallbackHandler handles GET /_agentgate/hitl/approve and /deny.
// Used by Discord Embed links and Generic JSON callbacks.
func GetCallbackHandler(approved bool) http.HandlerFunc {
	action := "APPROVED"
	emoji := "✅"
	if !approved {
		action = "DENIED"
		emoji = "❌"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		reqID := r.URL.Query().Get("req")
		token := r.URL.Query().Get("token")

		if reqID == "" || token == "" {
			http.Error(w, "Missing req or token parameter", http.StatusBadRequest)
			return
		}

		decisionChan, ok := LookupAndBurn(reqID, token)
		if !ok {
			log.Printf("[HITL Callback] Invalid or expired token reqID=%s", reqID)
			http.Error(w, "401 Unauthorized: Invalid or expired approval token", http.StatusUnauthorized)
			return
		}

		// Non-blocking send: decisionChan is buffered(1).
		// If the context already timed out, this is a no-op — no goroutine leak.
		decisionChan <- HitlDecision{Approved: approved, Approver: "Discord/Generic Webhook"}
		log.Printf("[HITL Callback] GET %s reqID=%s", action, reqID)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, callbackHTML(emoji, action))
	}
}

// SlackInteractiveHandler handles POST /_agentgate/hitl/slack-interactive.
// Slack sends a x-www-form-urlencoded body with a 'payload' field containing JSON.
// The button value is formatted as "requestID|actionToken".
func SlackInteractiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			log.Printf("[HITL Slack] Failed to parse form: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		payloadStr := r.FormValue("payload")
		if payloadStr == "" {
			http.Error(w, "Missing payload", http.StatusBadRequest)
			return
		}

		// Slack sends the payload as a URL-encoded JSON string
		var slackPayload struct {
			Actions []struct {
				ActionID string `json:"action_id"`
				Value    string `json:"value"`
			} `json:"actions"`
		}
		if err := json.Unmarshal([]byte(payloadStr), &slackPayload); err != nil {
			log.Printf("[HITL Slack] Failed to parse payload JSON: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if len(slackPayload.Actions) == 0 {
			http.Error(w, "No actions in payload", http.StatusBadRequest)
			return
		}

		action := slackPayload.Actions[0]
		approved := action.ActionID == "ag_approve"

		// value is formatted as "requestID|actionToken"
		parts := strings.SplitN(action.Value, "|", 2)
		if len(parts) != 2 {
			log.Printf("[HITL Slack] Malformed action value: %q", action.Value)
			http.Error(w, "Bad Request: malformed action value", http.StatusBadRequest)
			return
		}
		reqID, token := parts[0], parts[1]

		decisionChan, ok := LookupAndBurn(reqID, token)
		if !ok {
			log.Printf("[HITL Slack] Invalid or expired token reqID=%s", reqID)
			// Slack requires HTTP 200 within 3 seconds — still return 200, but log the error
			w.WriteHeader(http.StatusOK)
			return
		}
		decisionChan <- HitlDecision{Approved: approved, Approver: "Slack (Interactive)"}
		actionStr := "DENIED"
		if approved {
			actionStr = "APPROVED"
		}
		log.Printf("[HITL Slack] Interactive %s reqID=%s", actionStr, reqID)

		// Slack requires HTTP 200 to stop retrying
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Optionally update the Slack message (replace buttons with result)
		fmt.Fprintf(w, `{"text":"Action %s by human."}`, actionStr)
	}
}

func callbackHTML(emoji, action string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>AgentGate — %s</title>
<style>
body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;
     height:100vh;margin:0;background:#f0f4f8;}
.card{text-align:center;padding:2rem 3rem;border-radius:12px;background:white;
      box-shadow:0 4px 24px rgba(0,0,0,.1);}
h1{font-size:2.5rem;margin-bottom:.5rem;}
p{color:#666;}
</style>
</head>
<body>
  <div class="card">
    <h1>%s Action %s</h1>
    <p>You can close this tab.</p>
  </div>
</body>
</html>`, action, emoji, action)
}
