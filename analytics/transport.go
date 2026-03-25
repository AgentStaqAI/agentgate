package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// MCPTool represents the structure of a tool discovered from an upstream MCP server
type MCPTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ClientTransport defines the stateful strategy for executing an MCP connection
type ClientTransport interface {
	Connect(ctx context.Context) error
	Send(req []byte) error
	Receive(ctx context.Context) ([]byte, error)
	Close() error
}

type JSONRPCResponse struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id"`
	Result  map[string]any `json:"result,omitempty"`
	Error   map[string]any `json:"error,omitempty"`
}

func parseTolerantResponse(raw []byte) (*JSONRPCResponse, error) {
	rawStr := strings.TrimSpace(string(raw))

	// Strip "data:" prefix if present (SSE format leaking into raw HTTP)
	if strings.HasPrefix(rawStr, "data:") {
		rawStr = strings.TrimPrefix(rawStr, "data:")
		rawStr = strings.TrimSpace(rawStr)
	}

	// Handle dirty preamble by finding the first '{'
	idx := strings.Index(rawStr, "{")
	if idx != -1 {
		rawStr = rawStr[idx:]
	} else {
		return nil, fmt.Errorf("no JSON object found in response")
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(rawStr), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

type ClaudeServerConfig struct {
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Transport string            `json:"transport,omitempty"` // Optional: default "stdio"
	URL       string            `json:"url,omitempty"`       // For HTTP transports
}

// ClaudeConfigRoot represents the top-level standard MCP JSON file structure
type ClaudeConfigRoot struct {
	MCPServers map[string]ClaudeServerConfig `json:"mcpServers"`
}

// ------------------------------------------------------------------------
// STDIO TRANSPORT
// ------------------------------------------------------------------------

// StdioTransport wraps a child process for Hit-and-Run tool extraction
type StdioTransport struct {
	Command string
	Args    []string
	Env     map[string]string

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	ctx    context.Context
	
	queue chan []byte
	errCh chan error
	stderrBuf *bytes.Buffer
	stderrMu  sync.Mutex
}

func (t *StdioTransport) Connect(ctx context.Context) error {
	t.ctx = ctx
	t.cmd = exec.CommandContext(ctx, t.Command, t.Args...)
	
	t.cmd.Env = os.Environ()
	for k, v := range t.Env {
		t.cmd.Env = append(t.cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	var err error
	t.stdin, err = t.cmd.StdinPipe()
	if err != nil {
		return err
	}

	t.stdout, err = t.cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderrPipe, err := t.cmd.StderrPipe()
	if err != nil {
		return err
	}

	log.Printf("[StdioTransport] Spawning discovery process: %s %v", t.Command, t.Args)

	if err := t.cmd.Start(); err != nil {
		log.Printf("[StdioTransport] Failed to spawn discovery process %s: %v", t.Command, err)
		return err
	}

	t.stderrBuf = &bytes.Buffer{}

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				log.Printf("[StdioTransport stderr | %s] %s", t.Command, string(bytes.TrimSpace(chunk)))
				t.stderrMu.Lock()
				if t.stderrBuf.Len() < 4096 {
					t.stderrBuf.Write(chunk)
				}
				t.stderrMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	t.queue = make(chan []byte, 100)
	t.errCh = make(chan error, 1)

	// Single dedicated reader goroutine preventing Decoder thread-races
	go func() {
		dec := json.NewDecoder(t.stdout)
		for {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				t.errCh <- err
				return
			}
			t.queue <- []byte(raw)
		}
	}()

	return nil
}

func (t *StdioTransport) Send(req []byte) error {
	_, err := t.stdin.Write(append(req, '\n'))
	return err
}

func (t *StdioTransport) getStderr() string {
	t.stderrMu.Lock()
	defer t.stderrMu.Unlock()
	if t.stderrBuf == nil {
		return ""
	}
	return strings.TrimSpace(t.stderrBuf.String())
}

func (t *StdioTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():    // Short-circuited scoped fallback context
		stderr := t.getStderr()
		if stderr != "" {
			return nil, fmt.Errorf("%w. Last Stderr: %s", ctx.Err(), stderr)
		}
		return nil, ctx.Err()
	case <-t.ctx.Done():  // Global connection died
		stderr := t.getStderr()
		if stderr != "" {
			return nil, fmt.Errorf("%w. Last Stderr: %s", t.ctx.Err(), stderr)
		}
		return nil, t.ctx.Err()
	case err := <-t.errCh:
		// Put error back if subsequent polls happen
		t.errCh <- err
		stderr := t.getStderr()
		if stderr != "" {
			return nil, fmt.Errorf("%w. Process Stderr: %s", err, stderr)
		}
		return nil, err
	case msg := <-t.queue:
		return msg, nil
	}
}

func (t *StdioTransport) Close() error {
	if t.cmd != nil && t.cmd.Process != nil {
		// Assassinate child process instantly to prevent zombies since we got what we came for
		return t.cmd.Process.Kill()
	}
	return nil
}

// ------------------------------------------------------------------------
// HTTP TRANSPORT
// ------------------------------------------------------------------------

// HTTPTransport wraps a remote HTTP URL for Hit-and-Run tool extraction
type HTTPTransport struct {
	URL       string
	SessionID string
	ctx       context.Context
	queue     chan []byte
}

func (t *HTTPTransport) Connect(ctx context.Context) error {
	t.ctx = ctx
	t.queue = make(chan []byte, 100)
	return nil
}

func (t *HTTPTransport) Send(req []byte) error {
	httpReq, err := http.NewRequestWithContext(t.ctx, http.MethodPost, t.URL, bytes.NewBuffer(req))
	if err != nil {
		return err
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	if t.SessionID != "" {
		httpReq.Header.Set("mcp-session-id", t.SessionID)
		httpReq.Header.Set("x-session-id", t.SessionID)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP Upstream failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP Error %d: %s", resp.StatusCode, string(bytes.TrimSpace(body)))
	}

	// Intercept session if propagated
	if sess := resp.Header.Get("mcp-session-id"); sess != "" {
		t.SessionID = sess
	} else if sess := resp.Header.Get("x-session-id"); sess != "" {
		t.SessionID = sess
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) > 0 {
		t.queue <- body
	}

	return nil
}

func (t *HTTPTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.ctx.Done():
		return nil, t.ctx.Err()
	case msg := <-t.queue:
		return msg, nil
	}
}

func (t *HTTPTransport) Close() error {
	return nil
}
