package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

type AuditEvent struct {
	Timestamp string      `json:"timestamp"`
	Server    string      `json:"server"`
	Tool      string      `json:"tool"`
	Action    string      `json:"action"`
	Reason    string      `json:"reason"`
	Client    string      `json:"client"`
	RequestID string      `json:"request_id,omitempty"`
	Arguments interface{} `json:"arguments,omitempty"`
	Duration  string      `json:"duration,omitempty"`
	Approver  string      `json:"approver,omitempty"`
}

type AuditOptions struct {
	LogPath    string
	ServerName string
	ToolName   string
	Action     string
	Reason     string
	ClientIP   string
	RequestID  string
	Arguments  interface{}
	DurationMs int64
	Approver   string
}

// LogAuditAction writes the structured decision metadata atomically to disk.
func LogAuditAction(opts AuditOptions) {
	if opts.LogPath == "" {
		return
	}

	event := AuditEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Server:    opts.ServerName,
		Tool:      opts.ToolName,
		Action:    opts.Action,
		Reason:    opts.Reason,
		Client:    opts.ClientIP,
		RequestID: opts.RequestID,
		Arguments: opts.Arguments,
		Approver:  opts.Approver,
	}

	if opts.DurationMs > 0 {
		event.Duration = fmt.Sprintf("%dms", opts.DurationMs)
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[AuditLogger] Failed to serialize event: %v", err)
		return
	}

	data = append(data, '\n')

	f, err := os.OpenFile(opts.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[AuditLogger] Failed to open audit log: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		log.Printf("[AuditLogger] Failed to write event to audit log: %v", err)
	}
}
