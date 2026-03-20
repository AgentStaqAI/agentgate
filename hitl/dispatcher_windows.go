//go:build windows

package hitl

import (
	"log"
)

// dispatchTerminal on Windows always denies — /dev/tty and syscall.SetNonblock
// are not available. Use the Slack or Discord webhook type instead when running on Windows.
func dispatchTerminal(serverName, toolName string, args map[string]any, decisionChan chan HitlDecision) {
	log.Printf("[HITL Terminal] Terminal approval is not supported on Windows (server=%s tool=%s). Denying by default. Use webhook type 'slack' or 'discord' instead.", serverName, toolName)
	decisionChan <- HitlDecision{Approved: false, Approver: "System (Windows — Terminal HITL Unavailable)"}
}
