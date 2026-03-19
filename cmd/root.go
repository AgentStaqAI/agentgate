package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var configPath string

var rootCmd = &cobra.Command{
	Use:   "agentgate",
	Short: "AgentGate is a lightweight, single-binary semantic firewall and reverse proxy for AI agents.",
	Long:  "Protects underlying local MCP servers from malicious LLM prompts, directory traversal, and infinite loops via deterministic deterministic rules.",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "agentgate.yaml", "Path to the configuration file")
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
