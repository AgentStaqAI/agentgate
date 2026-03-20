package hitl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/agentgate/agentgate/config"
)

// Dispatch fires the appropriate notification for the given webhook type and
// delivers the human decision into decisionChan.
// It is always called in a goroutine by the middleware — it must never block the HTTP goroutine.
func Dispatch(
	wcfg config.WebhookConfig,
	publicURL string,
	serverName string,
	toolName string,
	args map[string]any,
	reqID string,
	token string,
	decisionChan chan HitlDecision,
) {
	switch wcfg.Type {
	case "terminal":
		dispatchTerminal(serverName, toolName, args, decisionChan)
	case "slack":
		dispatchSlack(wcfg.URL, serverName, toolName, args, reqID, token)
	case "discord":
		approveURL, denyURL := callbackURLs(publicURL, reqID, token)
		dispatchDiscord(wcfg.URL, serverName, toolName, args, approveURL, denyURL)
	default: // "generic"
		approveURL, denyURL := callbackURLs(publicURL, reqID, token)
		dispatchGeneric(wcfg.URL, serverName, toolName, args, approveURL, denyURL)
	}
}

func dispatchSlack(webhookURL, serverName, toolName string, args map[string]any, reqID, token string) {
	argsJSON, _ := json.MarshalIndent(args, "", "  ")
	value := reqID + "|" + token // parsed by SlackInteractiveHandler

	payload := map[string]any{
		"blocks": []any{
			map[string]any{
				"type": "header",
				"text": map[string]any{"type": "plain_text", "text": "⚠️ AgentGate: Approval Required"},
			},
			map[string]any{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Server:* `%s`\n*Tool:* `%s`\n*Arguments:*\n```%s```", serverName, toolName, string(argsJSON)),
				},
			},
			map[string]any{
				"type": "actions",
				"elements": []any{
					map[string]any{
						"type":      "button",
						"style":     "primary",
						"action_id": "ag_approve",
						"value":     value,
						"text":      map[string]any{"type": "plain_text", "text": "✅ Approve"},
					},
					map[string]any{
						"type":      "button",
						"style":     "danger",
						"action_id": "ag_deny",
						"value":     value,
						"text":      map[string]any{"type": "plain_text", "text": "❌ Deny"},
					},
				},
			},
		},
	}
	postJSON(webhookURL, payload)
}

// ── Discord ───────────────────────────────────────────────────────────────────

func dispatchDiscord(webhookURL, serverName, toolName string, args map[string]any, approveURL, denyURL string) {
	argsJSON, _ := json.MarshalIndent(args, "", "  ")
	payload := map[string]any{
		"username": "AgentGate",
		"embeds": []any{
			map[string]any{
				"title":       "⚠️ Human Approval Required",
				"color":       0xF4A236,
				"description": fmt.Sprintf("**Server:** `%s`\n**Tool:** `%s`\n**Arguments:**\n```json\n%s\n```", serverName, toolName, string(argsJSON)),
				"fields": []any{
					map[string]any{"name": "✅ Approve", "value": fmt.Sprintf("[Click here](%s)", approveURL), "inline": true},
					map[string]any{"name": "❌ Deny", "value": fmt.Sprintf("[Click here](%s)", denyURL), "inline": true},
				},
				"footer": map[string]any{"text": "AgentGate HITL Interceptor"},
			},
		},
	}
	postJSON(webhookURL, payload)
}

// ── Generic ───────────────────────────────────────────────────────────────────

func dispatchGeneric(webhookURL, serverName, toolName string, args map[string]any, approveURL, denyURL string) {
	payload := map[string]any{
		"server":      serverName,
		"tool":        toolName,
		"arguments":   args,
		"approve_url": approveURL,
		"deny_url":    denyURL,
	}
	postJSON(webhookURL, payload)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func callbackURLs(publicURL, reqID, token string) (approveURL, denyURL string) {
	base := fmt.Sprintf("%s/_agentgate/hitl", publicURL)
	approveURL = fmt.Sprintf("%s/approve?req=%s&token=%s", base, reqID, token)
	denyURL = fmt.Sprintf("%s/deny?req=%s&token=%s", base, reqID, token)
	return
}

func postJSON(url string, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[HITL Dispatcher] Marshal error: %v", err)
		return
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		log.Printf("[HITL Dispatcher] POST to %s failed: %v", url, err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[HITL Dispatcher] Webhook delivered to %s — HTTP %d", url, resp.StatusCode)
}
