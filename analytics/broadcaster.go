package analytics

import (
	"encoding/json"
	"sync"
)

var (
	sseClients   = make(map[chan []byte]bool)
	sseClientsMu sync.Mutex
)

// Broadcast sends a JSON-marshaled RequestRecord to all active SSE streams.
func Broadcast(record RequestRecord) {
	data, err := json.Marshal(record)
	if err != nil {
		return
	}

	sseClientsMu.Lock()
	defer sseClientsMu.Unlock()

	for ch := range sseClients {
		select {
		case ch <- data:
		default:
			// Client's channel buffer is full (e.g., slow network) — drop event
			// rather than pausing the broadcast loop or leaking memory.
		}
	}
}

// OutputPatch is a lightweight SSE message used to update an existing firehose row's output in real-time.
type OutputPatch struct {
	Type          string `json:"type"`
	ServerName    string `json:"server_name"`
	JSONRPCID     string `json:"jsonrpc_id"`
	OutputPayload string `json:"output_payload"`
}

// BroadcastOutputPatch sends a minimal patch event to all SSE clients so the
// frontend can update an existing firehose row's output_payload in-place.
func BroadcastOutputPatch(serverName, jsonrpcID, outputPayload string) {
	patch := OutputPatch{
		Type:          "output_patch",
		ServerName:    serverName,
		JSONRPCID:     jsonrpcID,
		OutputPayload: outputPayload,
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return
	}

	sseClientsMu.Lock()
	defer sseClientsMu.Unlock()

	for ch := range sseClients {
		select {
		case ch <- data:
		default:
		}
	}
}

// Subscribe opens a new stream for an SSE connection.
// Returns the channel to read from, and a cleanup function to close the subscription.
func Subscribe() (chan []byte, func()) {
	// Buffer allows handling spikes without instantly dropping events
	ch := make(chan []byte, 100)

	sseClientsMu.Lock()
	sseClients[ch] = true
	sseClientsMu.Unlock()

	cleanup := func() {
		sseClientsMu.Lock()
		delete(sseClients, ch)
		sseClientsMu.Unlock()
		close(ch)
	}

	return ch, cleanup
}
