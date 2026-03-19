package cmd

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/agentgate/agentgate/config"
	"github.com/agentgate/agentgate/ipc"
	"github.com/agentgate/agentgate/proxy"
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

type program struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc
	srv    *http.Server
}

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}

func (p *program) run() {
	p.ctx, p.cancel = context.WithCancel(context.Background())
	handler := proxy.SetupRouter(p.ctx, p.cfg)
	addr := fmt.Sprintf(":%d", p.cfg.Network.Port)

	// Spin up the background Unix domain socket (or TCP fallback) for IPC Panic commands
	ipc.StartServer()
	
	p.srv = &http.Server{
		Addr:    addr,
		Handler: handler,
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
		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load config from %s: %v", configPath, err)
		}

		if !service.Interactive() {
			for name, srv := range cfg.MCPServers {
				if srv.Policies.HumanApproval.Webhook.Type == "terminal" {
					log.Printf("⚠️ WARNING: 'terminal' HITL mode is configured for %s, but AgentGate is running as a background service. Terminal approvals will be automatically rejected.", name)
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
