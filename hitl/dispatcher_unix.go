//go:build !windows

package hitl

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/kardianos/service"
)

// dispatchTerminal prompts the operator at the controlling terminal on Unix/macOS.
func dispatchTerminal(serverName, toolName string, args map[string]any, decisionChan chan HitlDecision) {
	if !service.Interactive() {
		log.Printf("[HITL Terminal] Action requires terminal approval, but AgentGate is running as a background service. Denying by default.")
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

	// Drain stale input from the tty buffer using O_NONBLOCK.
	fd := int(tty.Fd())
	if err := syscall.SetNonblock(fd, true); err == nil {
		drain := make([]byte, 256)
		for {
			_, rerr := tty.Read(drain)
			if rerr != nil {
				break // EAGAIN / EWOULDBLOCK — buffer empty
			}
		}
		syscall.SetNonblock(fd, false) //nolint:errcheck
	}

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
