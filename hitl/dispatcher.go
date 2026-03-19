package hitl

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/agentgate/agentgate/config"
	"github.com/kardianos/service"
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

// ── Terminal ──────────────────────────────────────────────────────────────────

func dispatchTerminal(serverName, toolName string, args map[string]any, decisionChan chan HitlDecision) {
	if !service.Interactive() {
		log.Printf("[HITL Terminal] ❌ Action requires terminal approval, but AgentGate is running as a background service. Denying by default.")
		decisionChan <- HitlDecision{Approved: false, Approver: "System (Headless)"}
		return
	}

	argsJSON, _ := json.MarshalIndent(args, "    ", "  ")

	// Open /dev/tty directly — always the controlling terminal of the process,
	// regardless of how stdin (fd 0) is redirected.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		log.Printf("[HITL Terminal] Cannot open /dev/tty: %v — denying by default", err)
		decisionChan <- HitlDecision{Approved: false, Approver: "System (No TTY)"}
		return
	}
	defer tty.Close()

	// ── Drain any stale input from the tty buffer ─────────────────────────────
	// When the agent sends an HTTP request via curl/SDK and hits Enter, that \n
	// keypresses sits in the terminal input buffer. Without draining, ReadString
	// consumes it immediately and "denies" before the user even sees the prompt.
	// Fix: briefly set O_NONBLOCK, read until EAGAIN, then restore blocking mode.
	fd := int(tty.Fd())
	if err := syscall.SetNonblock(fd, true); err == nil {
		drain := make([]byte, 256)
		for {
			_, rerr := tty.Read(drain)
			if rerr != nil {
				break // EAGAIN / EWOULDBLOCK — buffer empty, done draining
			}
		}
		syscall.SetNonblock(fd, false) //nolint:errcheck — restoring blocking; ignore error
	}
	// ─────────────────────────────────────────────────────────────────────────

	fmt.Fprintf(tty, "\n\033[33m╔══════════════════════════════════════════════════╗\033[0m\n")
	fmt.Fprintf(tty, "\033[33m║  ⚠️  AgentGate: Human Approval Required          ║\033[0m\n")
	fmt.Fprintf(tty, "\033[33m╚══════════════════════════════════════════════════╝\033[0m\n")
	fmt.Fprintf(tty, "  Server:    \033[1m%s\033[0m\n", serverName)
	fmt.Fprintf(tty, "  Tool:      \033[1m%s\033[0m\n", toolName)
	fmt.Fprintf(tty, "  Arguments:\n    %s\n\n", string(argsJSON))
	fmt.Fprintf(tty, "Allow execution? [\033[32my\033[0m/\033[31mN\033[0m]: ")

	reader := bufio.NewReader(tty)
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[HITL Terminal] Failed to read from /dev/tty: %v — denying by default", err)
		decisionChan <- HitlDecision{Approved: false, Approver: "System (Read Error)"}
		return
	}

	input := strings.TrimSpace(strings.ToLower(line))
	approved := input == "y" || input == "yes"
	decisionChan <- HitlDecision{Approved: approved, Approver: "Terminal Controller"}
}

// ── Slack ─────────────────────────────────────────────────────────────────────

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
