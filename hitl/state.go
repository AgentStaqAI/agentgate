package hitl

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

// HitlDecision combines the boolean approval with the Approver attribution.
type HitlDecision struct {
	Approved bool
	Approver string
}

// PendingApproval holds in-flight state for a single HITL request.
type PendingApproval struct {
	ActionToken  string
	DecisionChan chan HitlDecision // buffered(1): callback/terminal goroutine never blocks on timeout race
	ServerName   string
	ToolName     string
	Arguments    map[string]any
}

// pendingApprovals is the global in-memory store.
// Key: requestID (hex string). Value: *PendingApproval.
var pendingApprovals sync.Map

// NewPendingApproval generates crypto-secure IDs, stores the entry, and
// returns the requestID, actionToken, and the decision channel.
func NewPendingApproval(serverName, toolName string, args map[string]any) (reqID, token string, ch chan HitlDecision, err error) {
	reqID, err = randomHex(16)
	if err != nil {
		return "", "", nil, fmt.Errorf("generate requestID: %w", err)
	}
	token, err = randomHex(16)
	if err != nil {
		return "", "", nil, fmt.Errorf("generate actionToken: %w", err)
	}

	ch = make(chan HitlDecision, 1)
	pendingApprovals.Store(reqID, &PendingApproval{
		ActionToken:  token,
		DecisionChan: ch,
		ServerName:   serverName,
		ToolName:     toolName,
		Arguments:    args,
	})
	return reqID, token, ch, nil
}

// LookupAndBurn atomically retrieves and deletes a PendingApproval.
// Returns (decisionChan, true) only when reqID exists AND token matches.
// Any mismatch or replay returns (nil, false).
func LookupAndBurn(reqID, token string) (chan HitlDecision, bool) {
	v, loaded := pendingApprovals.LoadAndDelete(reqID)
	if !loaded {
		return nil, false
	}
	pa := v.(*PendingApproval)
	if pa.ActionToken != token {
		// Bad token — put entry back so the legitimate actor can still use it.
		pendingApprovals.Store(reqID, pa)
		return nil, false
	}
	return pa.DecisionChan, true
}

// Delete removes a pending approval entry (used for timeout cleanup).
func Delete(reqID string) {
	pendingApprovals.Delete(reqID)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
