package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Creates a default agentgate.yaml at the specified --config path",
	Run: func(cmd *cobra.Command, args []string) {
		if _, err := os.Stat(configPath); err == nil {
			log.Fatalf("Config file already exists at %s", configPath)
		}

		defaultConfig := []byte(`network:
  port: 8083
  public_url: https://your-domain.ngrok-free.app

auth:
  require_bearer_token: ag_secret_12345

mcp_servers:
  local_database:
    upstream: exec:npx -y @pollinations/mcp-server-sqlite ./data.db
    policies:
      allowed_tools:
        - execute_query
      parameter_rules:
        execute_query:
          argument: query
          not_match_regex: (?i)(DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT)
          error_message: "Write operations are forbidden. Only SELECT queries are allowed."
      human_approval:
        require_for_tools:
          - execute_query
        timeout_seconds: 60
        webhook:
          type: terminal
          url: ""
`)

		if err := os.WriteFile(configPath, defaultConfig, 0644); err != nil {
			log.Fatalf("Failed to write default config to %s: %v", configPath, err)
		}

		fmt.Printf("Successfully created default configuration file at %s\n", configPath)
		fmt.Println("You can now run 'agentgate serve'")
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
