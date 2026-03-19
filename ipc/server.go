package ipc

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agentgate/agentgate/proxy"
)

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func GetUnixSocketPath() string {
	return "/tmp/agentgate.sock"
}

func GetWindowsTokenPath() string {
	return filepath.Join(os.TempDir(), "agentgate.ipc_token")
}

// StartServer launches the background listener natively during agentgate serve.
func StartServer() {
	if runtime.GOOS == "windows" {
		startWindowsServer()
	} else {
		startUnixServer()
	}
}

func startUnixServer() {
	sockPath := GetUnixSocketPath()
	os.Remove(sockPath) // cleanly burn stale sockets

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Printf("[IPC] Failed to start Unix socket: %v", err)
		return
	}

	// Lock permissions strictly to executor
	os.Chmod(sockPath, 0600)

	log.Printf("[IPC] Listening for CLI commands on Unix socket %s", sockPath)
	go acceptLoop(listener, "")
}

func startWindowsServer() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Printf("[IPC] Failed to start TCP fallback: %v", err)
		return
	}

	port := listener.Addr().(*net.TCPAddr).Port
	token := generateToken()

	tokenPath := GetWindowsTokenPath()
	data := fmt.Sprintf("%d\n%s", port, token)
	if err := os.WriteFile(tokenPath, []byte(data), 0600); err != nil {
		log.Printf("[IPC] Failed to write token file: %v", err)
		return
	}

	log.Printf("[IPC] Listening for CLI commands on 127.0.0.1:%d", port)
	go acceptLoop(listener, token)
}

func acceptLoop(listener net.Listener, requiredToken string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[IPC] Accept error: %v", err)
			continue
		}
		go handleConn(conn, requiredToken)
	}
}

func handleConn(conn net.Conn, requiredToken string) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)

	if requiredToken != "" {
		if !scanner.Scan() {
			return
		}
		if scanner.Text() != requiredToken {
			fmt.Fprintf(conn, "ERROR: Invalid Auth Token\n")
			return
		}
	}

	for scanner.Scan() {
		cmd := strings.TrimSpace(scanner.Text())
		switch cmd {
		case "PAUSE":
			proxy.IsPaused.Store(true)
			log.Println("[IPC] [WARN] AgentGate globally PAUSED via CLI")
			fmt.Fprintf(conn, "SUCCESS: AgentGate Paused\n")
		case "RESUME":
			proxy.IsPaused.Store(false)
			log.Println("[IPC] [INFO] AgentGate globally RESUMED via CLI")
			fmt.Fprintf(conn, "SUCCESS: AgentGate Resumed\n")
		default:
			fmt.Fprintf(conn, "ERROR: Unknown Command\n")
		}
	}
}

// DialCmd sends a payload to the running AgentGate agent via IPC
func DialCmd(command string) error {
	var conn net.Conn
	var err error

	if runtime.GOOS == "windows" {
		tokenPath := GetWindowsTokenPath()
		data, readErr := os.ReadFile(tokenPath)
		if readErr != nil {
			return fmt.Errorf("agentgate does not appear to be running (cannot find token): %v", readErr)
		}
		parts := strings.SplitN(string(data), "\n", 2)
		if len(parts) != 2 {
			return fmt.Errorf("corrupt IPC token file")
		}
		port, token := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

		conn, err = net.Dial("tcp", "127.0.0.1:"+port)
		if err != nil {
			return fmt.Errorf("agentgate does not appear to be running: %v", err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "%s\n", token)
	} else {
		conn, err = net.Dial("unix", GetUnixSocketPath())
		if err != nil {
			return fmt.Errorf("agentgate does not appear to be running on unix socket: %v", err)
		}
		defer conn.Close()
	}

	fmt.Fprintf(conn, "%s\n", command)

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		response := scanner.Text()
		if strings.HasPrefix(response, "SUCCESS") {
			return nil
		}
		return fmt.Errorf("server error: %s", response)
	}
	return fmt.Errorf("no response from server")
}
