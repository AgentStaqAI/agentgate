package cmd

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/agentgate/agentgate/ipc"
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// We define an empty program struct just to satisfy kardianos/service
// for the control commands (install, start, etc.).
// The actual service logic is executed by the 'serve' command.
type emptyProgram struct{}

func (p *emptyProgram) Start(s service.Service) error { return nil }
func (p *emptyProgram) Stop(s service.Service) error  { return nil }

var serviceCmd = &cobra.Command{
	Use:   "service [install|uninstall|start|stop|restart|status|pause|resume]",
	Short: "Manage the AgentGate background OS service",
	Long:  "Allows installing, uninstalling, and controlling AgentGate as a system daemon (systemd, launchd, windows service).",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		action := args[0]
		
		absPath, err := filepath.Abs(configPath)
		if err != nil {
			log.Fatalf("Failed to resolve absolute config path: %v", err)
		}

		svcConfig := &service.Config{
			Name:        "agentgate",
			DisplayName: "AgentGate Semantic Firewall",
			Description: "AgentGate MCP firewall and reverse proxy.",
			Arguments:   []string{"serve", "--config", absPath},
		}

		prg := &emptyProgram{}
		s, err := service.New(prg, svcConfig)
		if err != nil {
			log.Fatalf("Failed to initialize service manager: %v", err)
		}

		switch action {
		case "install":
			err = s.Install()
			if err != nil {
				log.Fatalf("Failed to install service: %v", err)
			}
			fmt.Printf("Service installed successfully. It will run 'agentgate serve --config %s'.\n", absPath)
		case "uninstall":
			err = s.Uninstall()
			if err != nil {
				log.Fatalf("Failed to uninstall service: %v", err)
			}
			fmt.Println("Service uninstalled successfully.")
		case "start":
			err = s.Start()
			if err != nil {
				log.Fatalf("Failed to start service: %v", err)
			}
			fmt.Println("Service started.")
		case "stop":
			err = s.Stop()
			if err != nil {
				log.Fatalf("Failed to stop service: %v", err)
			}
			fmt.Println("Service stopped.")
		case "restart":
			err = s.Restart()
			if err != nil {
				log.Fatalf("Failed to restart service: %v", err)
			}
			fmt.Println("Service restarted.")
		case "status":
			status, err := s.Status()
			if err != nil {
				log.Fatalf("Failed to get service status: %v", err)
			}
			statusStr := "Unknown"
			switch status {
			case service.StatusRunning:
				statusStr = "Running"
			case service.StatusStopped:
				statusStr = "Stopped"
			}
			fmt.Printf("Service status: %s\n", statusStr)
		case "pause":
			if err := ipc.DialCmd("PAUSE"); err != nil {
				log.Fatalf("Failed to pause AgentGate: %v", err)
			}
			fmt.Println("AgentGate successfully PAUSED. All autonomous actions suspended.")
		case "resume":
			if err := ipc.DialCmd("RESUME"); err != nil {
				log.Fatalf("Failed to resume AgentGate: %v", err)
			}
			fmt.Println("AgentGate successfully RESUMED.")
		default:
			log.Fatalf("Unknown command: %s (valid commands: install, uninstall, start, stop, restart, status, pause, resume)", action)
		}
	},
}

func init() {
	rootCmd.AddCommand(serviceCmd)
}
