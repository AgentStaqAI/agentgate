package config

import (
	"fmt"
	"os"
	"regexp"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
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
	ProxyPort int    `yaml:"proxy_port,omitempty"`
	AdminPort int    `yaml:"admin_port,omitempty"`
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

	// Resource is the identifier for this AgentGate instance (e.g., https://agentgate.local/mcp).
	// Advertised inside the PRM JSON.
	Resource string `yaml:"resource,omitempty"`

	// ScopesSupported are the strictly required scopes for this AgentGate Resource Server
	// (e.g., ["mcp:tools", "mcp:resources"]). Tokens must encapsulate all required scopes.
	ScopesSupported []string `yaml:"scopes_supported,omitempty"`

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
	ToolPolicies   map[string][]ToolPolicy    `yaml:"tool_policies,omitempty" json:"tool_policies,omitempty"`
	HumanApproval  *HumanApproval             `yaml:"human_approval,omitempty" json:"human_approval,omitempty"`
	RateLimit      *RateLimitConfig           `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
}

type ToolPolicy struct {
	Action    string `yaml:"action" json:"action"`       // "block", "allow", "hitl"
	Condition string `yaml:"condition" json:"condition"` // CEL string
	ErrorMsg  string `yaml:"error_msg,omitempty" json:"error_msg,omitempty"`

	// Compiled CEL program
	Program cel.Program `yaml:"-" json:"-"`
}

// RateLimitConfig defines granular infinite loop protection timelines.
type RateLimitConfig struct {
	MaxRequests   int `yaml:"max_requests,omitempty"`
	WindowSeconds int `yaml:"window_seconds,omitempty"`
}

// HumanApproval defines which tools require human sign-off before execution.
type HumanApproval struct {
	Tools   []string       `yaml:"tools,omitempty" json:"tools,omitempty"`
	Timeout int            `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Webhook *WebhookConfig `yaml:"webhook,omitempty" json:"webhook,omitempty"`
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

	if err := ValidateAndCompile(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func ValidateAndCompile(cfg *Config) error {
	// Setup CEL environment
	env, err := cel.NewEnv(
		cel.OptionalTypes(),
		ext.Strings(),
		cel.Variable("args", cel.MapType(cel.StringType, cel.AnyType)),
		cel.Variable("jwt", cel.MapType(cel.StringType, cel.AnyType)),
	)
	if err != nil {
		return fmt.Errorf("failed to create CEL env: %w", err)
	}

	for srvName, srv := range cfg.MCPServers {
		if srv.Policies.ToolPolicies == nil && len(srv.Policies.ParameterRules) > 0 {
			srv.Policies.ToolPolicies = make(map[string][]ToolPolicy)
		}

		// For backward compatibility, keep the old regex compile to ensure no syntax errors and
		// proactively auto-migrate the legacy parameter rules into CEL ToolPolicies.
		for toolName, rules := range srv.Policies.ParameterRules {
			for i, rule := range rules {
				if rule.NotMatchRegex != "" {
					compiled, err := regexp.Compile(rule.NotMatchRegex)
					if err != nil {
						return fmt.Errorf("invalid regex in mcp_servers.%s.policies.parameter_rules.%s[%d].not_match_regex: %w", srvName, toolName, i, err)
					}
					rule.CompiledRegex = compiled
					srv.Policies.ParameterRules[toolName][i] = rule

					// Auto-migrate to CEL and append.
					// Using string literal escape logic: we assume rule.NotMatchRegex is safe or we just use it
					// with raw string literals for CEL (e.g. `r'...'` or backslash escaping).
					// Or to be simpler, since it's an regex pattern, we can use CEL matches().
					// Note: type() check prevents evaluating matches() on non-strings.
					celCondition := fmt.Sprintf("has(args['%s']) && type(args['%s']) == string && !args['%s'].matches('%s')",
						rule.Argument, rule.Argument, rule.Argument, rule.NotMatchRegex)

					srv.Policies.ToolPolicies[toolName] = append(srv.Policies.ToolPolicies[toolName], ToolPolicy{
						Action:    "block",
						Condition: celCondition,
						ErrorMsg:  rule.ErrorMsg,
					})
				}
			}
		}

		// Compile CEL conditions into Programs
		for toolName, policies := range srv.Policies.ToolPolicies {
			for i, policy := range policies {
				if policy.Condition == "" {
					continue
				}
				ast, issues := env.Compile(policy.Condition)
				if issues != nil && issues.Err() != nil {
					return fmt.Errorf("invalid CEL condition in mcp_servers.%s.policies.tool_policies.%s[%d].condition: %w", srvName, toolName, i, issues.Err())
				}
				prg, err := env.Program(ast)
				if err != nil {
					return fmt.Errorf("failed to create CEL program for mcp_servers.%s.policies.tool_policies.%s[%d].condition: %w", srvName, toolName, i, err)
				}
				policy.Program = prg
				srv.Policies.ToolPolicies[toolName][i] = policy
			}
		}

		cfg.MCPServers[srvName] = srv
	}
	return nil
}
