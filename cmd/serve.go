package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/agentgate/agentgate/analytics"
	"github.com/agentgate/agentgate/auth"
	"github.com/agentgate/agentgate/config"
	"github.com/agentgate/agentgate/ipc"
	"github.com/agentgate/agentgate/proxy"
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// defaultConfigContent is the auto-generated agentgate.yaml written on first run.
// Uses distinct default ports (56123/57123) to avoid conflicts with other services.
const defaultConfigContent = `version: "1.0"

network:
  port: 56123         # Main proxy — point your LLM client here
  admin_port: 57123   # Dashboard — open http://localhost:57123

auth:
  require_bearer_token: "%s"  # Replace this token with a strong secret before exposing externally

audit_log_path: "agentgate_audit.log"

# No MCP servers configured yet.
# Open http://localhost:57123 to use the Onboarding UI, or edit this file directly.

`

// generateSecureToken creates a 16-byte (32 hex chars) cryptographically secure token
func generateSecureToken() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// bootstrapConfig resolves the config file path, creating a default one if none exists.
// Priority: explicit -c flag → <cwd>/agentgate.yaml → <binary-dir>/agentgate.yaml → /tmp/agentgate.yaml
func bootstrapConfig(explicit string, flagChanged bool) string {
	// User explicitly passed -c — respect it unconditionally
	if flagChanged {
		return explicit
	}

	// Candidate locations to check / create in order of preference
	var candidates []string

	// 1. Current working directory
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "agentgate.yaml"))
	}

	// 2. Directory containing the agentgate binary (works for brew installs)
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "agentgate.yaml"))
	}

	// 3. /tmp fallback — guaranteed writable on every platform
	candidates = append(candidates, filepath.Join(os.TempDir(), "agentgate.yaml"))

	// Deduplicate candidates while preserving order
	seen := map[string]bool{}
	var unique []string
	for _, p := range candidates {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}

	// Return the first one that already exists
	for _, path := range unique {
		if _, err := os.Stat(path); err == nil {
			log.Printf("[Bootstrap] Found existing config: %s", path)
			return path
		}
	}

	// None found — write the default to the first writable candidate
	for _, path := range unique {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			continue
		}

		token, err := generateSecureToken()
		if err != nil {
			log.Printf("[Bootstrap] Failed to generate secure token: %v", err)
			continue
		}

		// Replace %s in defaultConfigContent with the generated token
		content := fmt.Sprintf(defaultConfigContent, token)

		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			log.Printf("[Bootstrap] Could not write default config to %s: %v", path, err)
			continue
		}
		log.Printf("[Bootstrap] No config found. Created default config at: %s", path)
		log.Printf("[Bootstrap] Open http://localhost:57123 to configure AgentGate via the Onboarding UI.")
		return path
	}

	// Last resort: return whatever the flag default was
	return explicit
}

type program struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc
	srv    *http.Server
}

// DynamicRouter allows for hot-reloading the underlying HTTP multiplexer locklessly.
type DynamicRouter struct {
	mu      sync.RWMutex
	handler http.Handler
}

func (r *DynamicRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	h := r.handler
	r.mu.RUnlock()
	h.ServeHTTP(w, req)
}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) run() {
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// ── OAuth 2.1 JWKS cache ─────────────────────────────────────────────────
	var jwksCache *auth.JWKSCache
	if p.cfg.OAuth2.Enabled {
		refreshInterval := time.Duration(p.cfg.OAuth2.RefreshIntervalSeconds) * time.Second
		if refreshInterval <= 0 {
			refreshInterval = time.Hour
		}
		var err error
		jwksCache, err = auth.NewJWKSCache(p.cfg.OAuth2.JWKSURL, refreshInterval)
		if err != nil {
			log.Fatalf("[OAuth2] Failed to initialize JWKS cache: %v", err)
		}
		log.Printf("[OAuth2] Resource Server mode enabled (issuer=%s, audience=%s)", p.cfg.OAuth2.Issuer, p.cfg.OAuth2.Audience)
	}

	// ── Hot-Reload architecture ──────────────────────────────────────────────
	initHandler, initCleanups := proxy.SetupRouter(p.ctx, p.cfg, jwksCache)
	var activeCleanups = initCleanups

	dynRouter := &DynamicRouter{handler: initHandler}

	reloadFunc := func() error {
		log.Println("[GitOps] Triggering hot-reload of AgentGate policies...")
		newCfg, err := config.LoadConfig(configPath)
		if err != nil {
			return err
		}
		newHandler, newCleanups := proxy.SetupRouter(p.ctx, newCfg, jwksCache)

		dynRouter.mu.Lock()
		p.cfg = newCfg
		dynRouter.handler = newHandler
		dynRouter.mu.Unlock()

		for _, cleanup := range activeCleanups {
			cleanup()
		}
		activeCleanups = newCleanups

		log.Println("[GitOps] Hot-reload successfully multiplexed active router.")
		return nil
	}

	if err := analytics.InitDB("agentgate.db"); err != nil {
		log.Printf("[Warning] Failed to initialize analytics DB: %v (Dashboard disabled)", err)
	} else {
		getConfig := func() *config.Config {
			dynRouter.mu.RLock()
			defer dynRouter.mu.RUnlock()
			return p.cfg
		}
		go analytics.StartAdminServer(p.ctx, getConfig, configPath, reloadFunc)
	}

	addr := fmt.Sprintf(":%d", p.cfg.Network.Port)

	ipc.StartServer()

	// If no MCP servers are configured, auto-open the Onboarding UI in the browser
	if len(p.cfg.MCPServers) == 0 {
		log.Println("[Init] No MCP servers configured. Opening Onboarding UI in browser...")
		go func() {
			time.Sleep(1 * time.Second)
			dashboardURL := fmt.Sprintf("http://127.0.0.1:%d", p.cfg.Network.AdminPort)
			var openCmd *exec.Cmd
			switch runtime.GOOS {
			case "linux":
				openCmd = exec.Command("xdg-open", dashboardURL)
			case "windows":
				openCmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", dashboardURL)
			case "darwin":
				openCmd = exec.Command("open", dashboardURL)
			}
			if openCmd != nil {
				openCmd.Start()
			}
		}()
	}

	p.srv = &http.Server{
		Addr:    addr,
		Handler: dynRouter,
	}

	log.Printf("AgentGate listening on %s", addr)
	if err := p.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

func (p *program) Stop(s service.Service) error {
	log.Println("\nShutting down server gracefully...")
	if p.cancel != nil {
		p.cancel()
	}
	if p.srv != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := p.srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Server forced to shutdown: %v", err)
		}
	}
	log.Println("Server exited")
	return nil
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Starts the AgentGate semantic firewall reverse proxy server",
	Run: func(cmd *cobra.Command, args []string) {
		// Auto-bootstrap: resolve or auto-create config for zero-YAML first-run.
		flagChanged := cmd.Flags().Changed("config")
		configPath = bootstrapConfig(configPath, flagChanged)

		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load config from %s: %v", configPath, err)
		}

		if !service.Interactive() {
			for name, srv := range cfg.MCPServers {
				if srv.Policies.HumanApproval != nil && srv.Policies.HumanApproval.Webhook != nil && srv.Policies.HumanApproval.Webhook.Type == "terminal" {
					log.Printf("WARNING: 'terminal' HITL mode is configured for %s, but AgentGate is running as a background service. Terminal approvals will be automatically rejected.", name)
				}
			}
		}

		svcConfig := &service.Config{
			Name:        "agentgate",
			DisplayName: "AgentGate Semantic Firewall",
			Description: "AgentGate MCP firewall and reverse proxy.",
		}

		prg := &program{cfg: cfg}
		s, err := service.New(prg, svcConfig)
		if err != nil {
			log.Fatalf("Failed to initialize service: %v", err)
		}

		if err := s.Run(); err != nil {
			log.Fatalf("Service failed: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVarP(&configPath, "config", "c", "agentgate.yaml", "Path to the configuration file")
}
