package analytics

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

var db *sql.DB

// InitDB opens the local sqlite database and ensures the schema exists.
func InitDB(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return fmt.Errorf("open sqlite db: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		status TEXT,
		server_name TEXT,
		agent_id TEXT,
		tool_name TEXT,
		arguments TEXT,
		reason TEXT,
		latency_ms INTEGER,
		jsonrpc_id TEXT,
		input_payload TEXT,
		output_payload TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
	`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	log.Printf("[Analytics] Local datastore initialized at %s", dbPath)
	return nil
}

// RequestRecord represents a single proxy execution event.
type RequestRecord struct {
	ID            int64          `json:"id"`
	Timestamp     string         `json:"timestamp"`
	Status        string         `json:"status"` // "allowed", "blocked_regex", "blocked_rate_limit", "pending_hitl"
	ServerName    string         `json:"server_name"`
	AgentID       string         `json:"agent_id"`
	ToolName      string         `json:"tool_name"`
	Arguments     map[string]any `json:"arguments,omitempty"`
	Reason        string         `json:"reason"`
	LatencyMs     int64          `json:"latency_ms"`
	JSONRPCID     string         `json:"jsonrpc_id"`
	InputPayload  string         `json:"input_payload"`
	OutputPayload string         `json:"output_payload"`
}

// RecordRequest writes an event to the DB and broadcasts it via SSE.
// Execute this entirely asynchronously so it never blocks the proxy path.
func RecordRequest(serverName, status, agentID, jsonrpcID, inputPayload, toolName string, args map[string]any, reason string, latencyMs int64) {
	if db == nil {
		return // not initialized
	}

	go func() {
		argsBytes, _ := json.Marshal(args)
		argsStr := string(argsBytes)

		query := `
		INSERT INTO requests (server_name, status, agent_id, jsonrpc_id, input_payload, tool_name, arguments, reason, latency_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
		res, err := db.Exec(query, serverName, status, agentID, jsonrpcID, inputPayload, toolName, argsStr, reason, latencyMs)
		if err != nil {
			log.Printf("[Analytics] db.Exec error: %v", err)
			return
		}

		id, _ := res.LastInsertId()

		record := RequestRecord{
			ID:           id,
			Timestamp:    time.Now().UTC().Format(time.RFC3339),
			Status:       status,
			ServerName:   serverName,
			AgentID:      agentID,
			ToolName:     toolName,
			Arguments:    args,
			Reason:       reason,
			LatencyMs:    latencyMs,
			JSONRPCID:    jsonrpcID,
			InputPayload: inputPayload,
		}

		// Push to the in-memory SSE channels
		Broadcast(record)
	}()
}

// RecordOutput updates an existing request with the final JSON-RPC output payload returning from the upstream server.
// It maps securely by serverName and jsonrpcID for matching the most recent invoke.
func RecordOutput(serverName string, jsonrpcID string, outputPayload string) {
	if db == nil || jsonrpcID == "" {
		return
	}

	go func() {
		subQuery := `
		UPDATE requests 
		SET output_payload = ? 
		WHERE id = (SELECT id FROM requests WHERE server_name = ? AND jsonrpc_id = ? ORDER BY id DESC LIMIT 1)
		`
		_, err := db.Exec(subQuery, outputPayload, serverName, jsonrpcID)
		if err != nil {
			log.Printf("[Analytics] RecordOutput error: %v", err)
			return
		}
		// Push real-time patch to all connected SSE dashboard clients
		BroadcastOutputPatch(serverName, jsonrpcID, outputPayload)
	}()
}
