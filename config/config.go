package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Config represents the root configuration structure
type Config struct {
	Version      string               `yaml:"version"`
	Network      NetworkConfig        `yaml:"network"`
	Auth         AuthConfig           `yaml:"auth"`
	AgentLimits  AgentLimits          `yaml:"agent_limits"`
	AuditLogPath string               `yaml:"audit_log_path"`
	MCPServers   map[string]MCPServer `yaml:"mcp_servers"`
}

type NetworkConfig struct {
	Port      int    `yaml:"port"`
	PublicURL string `yaml:"public_url"`
}

type AuthConfig struct {
	RequireBearerToken string `yaml:"require_bearer_token"`
}

type AgentLimits struct {
	MaxRequestsPerMinute int `yaml:"max_requests_per_minute"`
}

type MCPServer struct {
	Upstream string         `yaml:"upstream"`
	Policies SecurityPolicy `yaml:"policies"`
}

type SecurityPolicy struct {
	AccessMode     string                   `yaml:"access_mode"`
	AllowedTools   []string                 `yaml:"allowed_tools"`
	BlockedTools   []string                 `yaml:"blocked_tools"`
	ParameterRules map[string]ParameterRule `yaml:"parameter_rules"`
	HumanApproval  HumanApproval            `yaml:"human_approval"`
	RateLimit      RateLimitConfig          `yaml:"rate_limit"`
}

// RateLimitConfig defines granular infinite loop protection timelines.
type RateLimitConfig struct {
	MaxRequests   int `yaml:"max_requests"`
	WindowSeconds int `yaml:"window_seconds"`
}

// HumanApproval defines which tools require human sign-off before execution.
type HumanApproval struct {
	RequireForTools []string      `yaml:"require_for_tools"`
	TimeoutSeconds  int           `yaml:"timeout_seconds"`
	Webhook         WebhookConfig `yaml:"webhook"`
}

// WebhookConfig describes the notification target for HITL approval requests.
type WebhookConfig struct {
	Type string `yaml:"type"` // "slack" | "discord" | "generic"
	URL  string `yaml:"url"`
}

type ParameterRule struct {
	Argument      string `yaml:"argument"`
	NotMatchRegex string `yaml:"not_match_regex"`
	ErrorMsg      string `yaml:"error_msg"`

	// CompiledRegex is for internal use and set during LoadConfig
	CompiledRegex *regexp.Regexp `yaml:"-"`
}

// LoadConfig reads, parses and validates the AgentGate configuration
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	if err := validateAndCompile(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func validateAndCompile(cfg *Config) error {
	for srvName, srv := range cfg.MCPServers {
		for toolName, rule := range srv.Policies.ParameterRules {
			if rule.NotMatchRegex != "" {
				compiled, err := regexp.Compile(rule.NotMatchRegex)
				if err != nil {
					return fmt.Errorf("invalid regex in mcp_servers.%s.policies.parameter_rules.%s.not_match_regex: %w", srvName, toolName, err)
				}
				rule.CompiledRegex = compiled
				// Reassign back to the map since it's passed by value
				srv.Policies.ParameterRules[toolName] = rule
			}
		}
	}
	return nil
}
