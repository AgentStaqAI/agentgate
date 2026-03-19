package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStdioBridge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bridge, err := NewStdioBridge(ctx, "test_server", "cat")
	if err != nil {
		t.Fatalf("Failed to create StdioBridge: %v", err)
	}

	server := httptest.NewServer(bridge)
	defer server.Close()

	testPayload := `{"jsonrpc":"2.0","id":1,"method":"test_method"}`

	req, err := http.NewRequest("POST", server.URL, bytes.NewBuffer([]byte(testPayload)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	expectedBody := testPayload + "\n"
	if string(respBody) != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, string(respBody))
	}
}

func TestStdioBridge_InvalidMethod(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	bridge, err := NewStdioBridge(ctx, "test_server", "cat")
	if err != nil {
		t.Fatalf("Failed to create StdioBridge: %v", err)
	}

	req, _ := http.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	bridge.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}
