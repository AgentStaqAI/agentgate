package proxy

import (
"bufio"
"bytes"
"context"
"crypto/rand"
"encoding/hex"
"encoding/json"
"fmt"
"io"
"log"
"net/http"
"os"
"os/exec"
"path/filepath"
"runtime"
"strings"
"sync"
"sync/atomic"
"time"
)

const stdioReadTimeout = 30 * time.Second

// StdioBridge provides an HTTP bridge to a local CLI process using standard I/O pipes.
// It implements http.Handler to simulate a reverse proxy.
type StdioBridge struct {
	cmd       *exec.Cmd
	cmdString string
	serverName string
	mu        sync.Mutex
	stdin     io.WriteCloser
	exited    atomic.Bool // true once the child process has exited

	sessionsMu  sync.RWMutex
	sseSessions map[string]chan []byte

	syncRequestsMu sync.Mutex
	syncRequests   map[string]chan []byte
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// NewStdioBridge creates and starts a new StdioBridge process.
func NewStdioBridge(ctx context.Context, serverName string, cmdString string) (*StdioBridge, error) {
	parts := strings.Fields(cmdString)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty command string")
	}

	var homeDir string
	var homeErr error

	for i, part := range parts {
		if strings.HasPrefix(part, "~/") {
			if homeDir == "" && homeErr == nil {
				homeDir, homeErr = os.UserHomeDir()
			}
			if homeErr != nil {
				return nil, fmt.Errorf("failed to resolve home directory to expand '~/' for %q: %w", part, homeErr)
			}
			parts[i] = filepath.Join(homeDir, part[2:])
		}
	}

	log.Printf("[StdioBridge] Launching child process: %v", parts)

	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)

	// Inject rich PATH for background compatibility so wrapper scripts like `npx` can find `node`.
	cmd.Env = os.Environ()
	pathFound := false
	pathIndex := -1

	for i, envVar := range cmd.Env {
		// Use ToUpper for Windows safety where Path vs PATH matters
		if strings.HasPrefix(strings.ToUpper(envVar), "PATH=") {
			pathFound = true
			pathIndex = i
			break
		}
	}

	var additions string
	if runtime.GOOS == "windows" {
		additions = `C:\Program Files\nodejs`
	} else {
		additions = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	}

	if pathFound {
		sep := string(os.PathListSeparator)
		cmd.Env[pathIndex] = cmd.Env[pathIndex] + sep + additions
	} else {
		cmd.Env = append(cmd.Env, "PATH="+additions)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}
	log.Printf("[StdioBridge] Child process started. PID: %d  cmd: %s", cmd.Process.Pid, cmdString)

	bridge := &StdioBridge{
		cmd:          cmd,
		cmdString:    cmdString,
		serverName:   serverName,
		stdin:        stdin,
		sseSessions:  make(map[string]chan []byte),
		syncRequests: make(map[string]chan []byte),
	}

	// Stream stdout
	go func() {
		scanner := bufio.NewScanner(stdout)
		
		// Increase buffer size to handle large JSON-RPC responses
		buf := make([]byte, 1024*1024) // 1MB initial buf
		scanner.Buffer(buf, 10*1024*1024) // 10MB max token size

		for scanner.Scan() {
			line := scanner.Bytes()
			
			// We MUST make a copy of the line because scanner.Bytes() reuses the underlying array.
			lineCopy := make([]byte, len(line))
			copy(lineCopy, line)
			
			// Broadcast to all SSE sessions
			bridge.sessionsMu.RLock()
			for _, ch := range bridge.sseSessions {
				select {
				case ch <- lineCopy:
				default:
					log.Printf("[StdioBridge] Warning: SSE channel full, dropping message")
				}
			}
			bridge.sessionsMu.RUnlock()

			// Check if it's a sync request response
var env rpcEnvelope
if err := json.Unmarshal(lineCopy, &env); err == nil && len(env.ID) > 0 {
idStr := string(env.ID)
bridge.syncRequestsMu.Lock()
if ch, ok := bridge.syncRequests[idStr]; ok {
ch <- lineCopy
delete(bridge.syncRequests, idStr)
}
bridge.syncRequestsMu.Unlock()
}
}
if scanErr := scanner.Err(); scanErr != nil {
log.Printf("[StdioBridge] stdout scanner error for %s: %v", cmdString, scanErr)
}
log.Printf("[StdioBridge] stdout scanner goroutine ending for: %s", cmdString)
}()

// Stream stderr line-by-line
go func() {
log.Printf("[StdioBridge] stderr reader goroutine started for: %s", cmdString)
scanner := bufio.NewScanner(stderr)
for scanner.Scan() {
log.Printf("[StdioBridge stderr | %s] %s", cmdString, scanner.Text())
}
if scanErr := scanner.Err(); scanErr != nil {
log.Printf("[StdioBridge] stderr scanner error for %s: %v", cmdString, scanErr)
}
log.Printf("[StdioBridge] stderr reader goroutine ending for: %s", cmdString)
}()

// Wait goroutine: marks bridge as exited and logs exit status.
go func() {
waitErr := cmd.Wait()
bridge.exited.Store(true)
if waitErr != nil {
log.Printf("[StdioBridge] Process '%s' (PID %d) exited with ERROR: %v", cmdString, cmd.Process.Pid, waitErr)
} else {
log.Printf("[StdioBridge] Process '%s' (PID %d) exited gracefully", cmdString, cmd.Process.Pid)
}
}()

return bridge, nil
}

// ServeHTTP writes the HTTP JSON request payload to the child process Stdin,
// and answers the HTTP request with the exact newline-delimited JSON response from Stdout.
func (s *StdioBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
log.Printf("[StdioBridge] ServeHTTP called: method=%s url=%s", r.Method, r.URL.String())

// Check if process has already crashed using the atomic flag (race-free)
if s.exited.Load() {
log.Printf("[StdioBridge] Process already exited — returning 502")
http.Error(w, "Bad Gateway: Child MCP process has crashed or exited", http.StatusBadGateway)
return
}

// Route A: Async GET /sse
// Route A1: Streamable HTTP Transport Unified Endpoint (/mcp endpoints)
if strings.HasSuffix(r.URL.Path, "mcp") {
s.handleStreamableHTTP(w, r)
return
}

if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "sse") {
s.handleSSE(w, r)
return
}

if r.Method != http.MethodPost {
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
return
}

// Route B: Async POST /message
sessionId := r.URL.Query().Get("sessionId")
if strings.HasSuffix(r.URL.Path, "message") && sessionId != "" {
s.handleAsyncMessage(w, r, sessionId)
return
}

// Route C: Sync POST legacy
s.handleSyncLegacy(w, r)
}

func (s *StdioBridge) handleSSE(w http.ResponseWriter, r *http.Request) {
flusher, ok := w.(http.Flusher)
if !ok {
http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
return
}

sessionID := generateSessionID()
ch := make(chan []byte, 100)

s.sessionsMu.Lock()
s.sseSessions[sessionID] = ch
s.sessionsMu.Unlock()

defer func() {
s.sessionsMu.Lock()
delete(s.sseSessions, sessionID)
s.sessionsMu.Unlock()
}()

w.Header().Set("Content-Type", "text/event-stream")
w.Header().Set("Cache-Control", "no-cache")
w.Header().Set("Connection", "keep-alive")

fmt.Fprintf(w, "event: endpoint\ndata: /message?sessionId=%s\n\n", sessionID)
flusher.Flush()

for {
select {
case msg := <-ch:
fmt.Fprintf(w, "data: %s\n\n", msg)
flusher.Flush()
case <-r.Context().Done():
return
}
}
}

func (s *StdioBridge) handleAsyncMessage(w http.ResponseWriter, r *http.Request, sessionID string) {
s.sessionsMu.RLock()
_, exists := s.sseSessions[sessionID]
s.sessionsMu.RUnlock()

if !exists {
http.Error(w, "Invalid session ID", http.StatusBadRequest)
return
}

body, err := io.ReadAll(r.Body)
if err != nil {
log.Printf("[StdioBridge] Failed to read HTTP request body: %v", err)
http.Error(w, "Failed to read request body", http.StatusInternalServerError)
return
}
defer r.Body.Close()

if len(body) == 0 {
http.Error(w, "Empty body", http.StatusBadRequest)
return
}

payload := string(body)
if !strings.HasSuffix(payload, "\n") {
payload += "\n"
}

s.mu.Lock()
_, err = s.stdin.Write([]byte(payload))
s.mu.Unlock()

if err != nil {
log.Printf("[StdioBridge] stdin write error: %v", err)
http.Error(w, "Bad Gateway: Failed to write to MCP process", http.StatusBadGateway)
return
}

w.WriteHeader(http.StatusAccepted)
w.Write([]byte("Accepted"))
}

func (s *StdioBridge) handleStreamableHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		sessionID := generateSessionID()
		ch := make(chan []byte, 100)

		s.sessionsMu.Lock()
		s.sseSessions[sessionID] = ch
		s.sessionsMu.Unlock()

		defer func() {
			s.sessionsMu.Lock()
			delete(s.sseSessions, sessionID)
			s.sessionsMu.Unlock()
		}()

		w.Header().Set("Mcp-Session-Id", sessionID)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		for {
			select {
			case msg := <-ch:
				fmt.Fprintf(w, "data: %s\n\n", msg)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}

	case http.MethodPost:
		sessionID := r.Header.Get("Mcp-Session-Id")
		if sessionID == "" {
			http.Error(w, "Missing Mcp-Session-Id header", http.StatusBadRequest)
			return
		}
		s.handleAsyncMessage(w, r, sessionID)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *StdioBridge) handleSyncLegacy(w http.ResponseWriter, r *http.Request) {
body, err := io.ReadAll(r.Body)
if err != nil {
log.Printf("[StdioBridge] Failed to read HTTP request body: %v", err)
http.Error(w, "Failed to read request body", http.StatusInternalServerError)
return
}
defer r.Body.Close()

if len(body) == 0 {
log.Printf("[StdioBridge] Received empty body — rejecting")
http.Error(w, "Empty body", http.StatusBadRequest)
return
}

log.Printf("[StdioBridge] Incoming sync payload (%d bytes)", len(body))

var env rpcEnvelope
if err := json.Unmarshal(body, &env); err != nil {
http.Error(w, "Invalid JSON-RPC", http.StatusBadRequest)
return
}

idStr := string(env.ID)
var ch chan []byte

if len(env.ID) > 0 {
ch = make(chan []byte, 1)
s.syncRequestsMu.Lock()
s.syncRequests[idStr] = ch
s.syncRequestsMu.Unlock()
}

payload := string(body)
if !strings.HasSuffix(payload, "\n") {
payload += "\n"
}

s.mu.Lock()
_, writeErr := s.stdin.Write([]byte(payload))
s.mu.Unlock()

if writeErr != nil {
log.Printf("[StdioBridge] stdin write error: %v", writeErr)
if ch != nil {
s.syncRequestsMu.Lock()
delete(s.syncRequests, idStr)
s.syncRequestsMu.Unlock()
}
http.Error(w, "Bad Gateway: Failed to write to MCP process", http.StatusBadGateway)
return
}

// If no ID (e.g. notification), do not wait for response
if ch == nil {
w.WriteHeader(http.StatusOK)
return
}

log.Printf("[StdioBridge] Payload written to stdin. Waiting for stdout response (timeout: %s)...", stdioReadTimeout)

select {
case res := <-ch:
log.Printf("[StdioBridge] Got response (%d bytes): %s", len(res), bytes.TrimSpace(res))
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(http.StatusOK)
w.Write(res)
w.Write([]byte("\n"))

case <-time.After(stdioReadTimeout):
log.Printf("[StdioBridge] TIMEOUT after %s waiting for response", stdioReadTimeout)
s.syncRequestsMu.Lock()
delete(s.syncRequests, idStr)
s.syncRequestsMu.Unlock()
http.Error(w, fmt.Sprintf("Gateway Timeout: MCP process did not respond within %s", stdioReadTimeout), http.StatusGatewayTimeout)
}
}
