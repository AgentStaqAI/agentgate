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
	OAuth2       OAuth2Config         `yaml:"oauth2"`
	AgentLimits  AgentLimits          `yaml:"agent_limits"`
	AuditLogPath string               `yaml:"audit_log_path"`
	MCPServers   map[string]MCPServer `yaml:"mcp_servers,omitempty"`
}

type NetworkConfig struct {
	Port      int    `yaml:"port,omitempty"`
	AdminPort int    `yaml:"admin_port,omitempty"` // Default 8081
	PublicURL string `yaml:"public_url,omitempty"`
}

type AuthConfig struct {
	RequireBearerToken string `yaml:"require_bearer_token,omitempty"`
}

// OAuth2Config configures AgentGate as an OAuth 2.1 Resource Server.
// When Enabled is true, incoming requests must carry a valid RS256 JWT.
// The static require_bearer_token check is automatically bypassed.
type OAuth2Config struct {
	// Enabled activates JWT validation. Default: false (static token mode).
	Enabled bool `yaml:"enabled,omitempty"`

	// Issuer is the expected "iss" claim in the JWT (e.g. "https://auth.example.com").
	Issuer string `yaml:"issuer,omitempty"`

	// Audience is the expected "aud" claim — typically the AgentGate resource identifier.
	Audience string `yaml:"audience,omitempty"`

	// JWKSURL is the Authorization Server's public key endpoint.
	// e.g. "https://auth.example.com/.well-known/jwks.json"
	JWKSURL string `yaml:"jwks_url,omitempty"`

	// ResourceMetadata is the URL advertised in WWW-Authenticate challenges
	// so AI clients can discover the Authorization Server.
	// e.g. "https://auth.example.com/.well-known/oauth-authorization-server"
	ResourceMetadata string `yaml:"resource_metadata,omitempty"`

	// RefreshIntervalSeconds controls how often JWKS keys are re-fetched for rotation.
	// Default: 3600 (1 hour).
	RefreshIntervalSeconds int `yaml:"refresh_interval_seconds,omitempty"`

	// InjectUserHeader, when true, adds X-AgentGate-User: <sub> and
	// X-AgentGate-Scopes: <scope> to upstream requests.
	InjectUserHeader bool `yaml:"inject_user_header,omitempty"`
}

type AgentLimits struct {
	MaxRequestsPerMinute int `yaml:"max_requests_per_minute,omitempty"`
}

type MCPServer struct {
	Upstream string            `yaml:"upstream"`
	Env      map[string]string `yaml:"env,omitempty"`
	Policies SecurityPolicy    `yaml:"policies,omitempty"`
}

type SecurityPolicy struct {
	AccessMode     string                     `yaml:"access_mode,omitempty" json:"access_mode,omitempty"`
	AllowedTools   []string                   `yaml:"allowed_tools,omitempty" json:"allowed_tools,omitempty"`
	BlockedTools   []string                   `yaml:"blocked_tools,omitempty" json:"blocked_tools,omitempty"`
	ParameterRules map[string][]ParameterRule `yaml:"parameter_rules,omitempty" json:"parameter_rules,omitempty"`
	HumanApproval  *HumanApproval             `yaml:"human_approval,omitempty" json:"human_approval,omitempty"`
	RateLimit      *RateLimitConfig           `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
}

// RateLimitConfig defines granular infinite loop protection timelines.
type RateLimitConfig struct {
	MaxRequests   int `yaml:"max_requests,omitempty"`
	WindowSeconds int `yaml:"window_seconds,omitempty"`
}

// HumanApproval defines which tools require human sign-off before execution.
type HumanApproval struct {
	RequireForTools []string       `yaml:"require_for_tools,omitempty"`
	TimeoutSeconds  int            `yaml:"timeout_seconds,omitempty"`
	Webhook         *WebhookConfig `yaml:"webhook,omitempty"`
}

// WebhookConfig describes the notification target for HITL approval requests.
type WebhookConfig struct {
	Type string `yaml:"type,omitempty"` // "slack" | "discord" | "generic"
	URL  string `yaml:"url,omitempty"`
}

type ParameterRule struct {
	Argument      string `yaml:"argument,omitempty" json:"argument,omitempty"`
	NotMatchRegex string `yaml:"not_match_regex,omitempty" json:"not_match_regex,omitempty"`
	ErrorMsg      string `yaml:"error_msg,omitempty" json:"error_msg,omitempty"`

	// CompiledRegex is for internal use and set during LoadConfig
	CompiledRegex *regexp.Regexp `yaml:"-" json:"-"`
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
		for toolName, rules := range srv.Policies.ParameterRules {
			for i, rule := range rules {
				if rule.NotMatchRegex != "" {
					compiled, err := regexp.Compile(rule.NotMatchRegex)
					if err != nil {
						return fmt.Errorf("invalid regex in mcp_servers.%s.policies.parameter_rules.%s[%d].not_match_regex: %w", srvName, toolName, i, err)
					}
					rule.CompiledRegex = compiled
					// Reassign back to the slice since Structs copy by value natively
					srv.Policies.ParameterRules[toolName][i] = rule
				}
			}
		}
	}
	return nil
}
