package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type Capabilities struct {
	Telemetry      bool     `yaml:"telemetry"`
	ConfigureLDAP  bool     `yaml:"configure_ldap"`
	Reboot         bool     `yaml:"reboot"`
	ServiceControl []string `yaml:"service_control"`
	ArbitraryBash  bool     `yaml:"arbitrary_bash"`
	LdapTunnel     bool     `yaml:"ldap_tunnel"`
	Secrets        bool     `yaml:"secrets"`
	IAM            bool     `yaml:"iam"`
}

// SecretTarget maps a local template to a rendered target file and an optional
// post-render reload command (DESIGN.md §5).
type SecretTarget struct {
	Template string `yaml:"template"`
	Target   string `yaml:"target"`
	Reload   string `yaml:"reload"`
}

// WireGuardConfig holds the mesh client settings (DESIGN-WINDOWS.md §5).
type WireGuardConfig struct {
	// TunnelName is the Windows WireGuard tunnel/service name.
	TunnelName string `yaml:"tunnel_name"`
	// Conf is where the pushed peer config is persisted on disk.
	Conf string `yaml:"conf"`
}

type Config struct {
	ServerURL string `yaml:"server_url"`
	AuthToken string `yaml:"auth_token"`
	// A join key is the one credential an operator hands out. On first connect
	// the server exchanges it for a per-agent AuthToken (written back to this
	// file), so it is a bootstrap value, not a long-term credential. Used only
	// when AuthToken is empty.
	JoinKey      string         `yaml:"join_key"`
	Location     string         `yaml:"location"`
	PublicKey    string         `yaml:"public_key"`     // Ed25519 public key for signed commands
	LdapSocket   string         `yaml:"ldap_socket"`    // local LDAP tunnel socket (DESIGN.md §4)
	Secrets      []SecretTarget `yaml:"secrets"`        // secret templates to render (DESIGN.md §5)
	Capabilities Capabilities   `yaml:"capabilities"`

	// Windows-specific (DESIGN-WINDOWS.md §11).
	ServiceName string           `yaml:"service_name"` // Windows service name
	DesktopHelper string         `yaml:"desktop_helper"` // theta-agent-helper.exe path
	PublicIPDetect *bool         `yaml:"public_ip_detect"` // false disables external lookups (air-gap)
	WireGuard     WireGuardConfig `yaml:"wireguard"`
}

// DetectPublicIP reports whether the agent may perform external public-IP
// lookups. Defaults to true; an air-gapped host sets public_ip_detect: false so
// the agent never tries to reach ipify/icanhazip/etc.
func (c *Config) DetectPublicIP() bool {
	if c.PublicIPDetect == nil {
		return true
	}
	return *c.PublicIPDetect
}

// ServiceNameOrDefault returns the Windows service name, defaulting to
// theta-agent when unset.
func (c *Config) ServiceNameOrDefault() string {
	if c.ServiceName != "" {
		return c.ServiceName
	}
	return "theta-agent"
}

// Credential returns the value to present when connecting: our own token once
// enrolled, otherwise the join key.
func (c *Config) Credential() string {
	if c.AuthToken != "" {
		return c.AuthToken
	}
	return c.JoinKey
}

// ConfigManager handles thread-safe access and reloading of the agent configuration.
type ConfigManager struct {
	mu         sync.RWMutex
	current    *Config
	configPath string
}

func NewConfigManager(path string) (*ConfigManager, error) {
	cfg, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	return &ConfigManager{
		current:    cfg,
		configPath: path,
	}, nil
}

// Get returns a copy of the current configuration.
func (cm *ConfigManager) Get() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.current
}

// Reload re-reads the configuration from disk and updates the active config.
func (cm *ConfigManager) Reload() error {
	cfg, err := LoadConfig(cm.configPath)
	if err != nil {
		return fmt.Errorf("reload failed: %w", err)
	}
	cm.mu.Lock()
	cm.current = cfg
	cm.mu.Unlock()
	return nil
}

// PersistEnrollment writes the credentials the server issued during join-key
// enrollment back into agent.yml, then reloads. Only the auth_token and
// public_key lines are rewritten (added if absent); every other line, including
// operator comments and the capability matrix, is preserved -- this file is
// hand-edited, so a naive marshal-and-write would destroy it.
//
// The join key is blanked once we hold our own token: leaving a fleet-wide
// credential on every host after it has stopped being needed is exactly the
// blast radius the per-agent token exists to avoid.
func (cm *ConfigManager) PersistEnrollment(token, publicKey string) error {
	if token == "" {
		return fmt.Errorf("server reported enrollment but sent no token")
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	raw, err := os.ReadFile(cm.configPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cm.configPath, err)
	}

	out := setYamlScalar(string(raw), "auth_token", token)
	if publicKey != "" {
		out = setYamlScalar(out, "public_key", publicKey)
	}
	out = setYamlScalar(out, "join_key", "")

	// Same permissions the installer sets: this file now holds a credential.
	if err := os.WriteFile(cm.configPath, []byte(out), 0600); err != nil {
		return fmt.Errorf("write %s: %w", cm.configPath, err)
	}

	cfg, err := LoadConfig(cm.configPath)
	if err != nil {
		return fmt.Errorf("reload after enrollment: %w", err)
	}
	cm.current = cfg
	return nil
}

// setYamlScalar replaces the value of a top-level `key: "..."` line, or appends
// the key when it is absent. Deliberately line-based rather than a YAML
// round-trip so comments and formatting survive.
func setYamlScalar(doc, key, value string) string {
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*:.*$`)
	line := fmt.Sprintf("%s: %q", key, value)
	if re.MatchString(doc) {
		return re.ReplaceAllString(doc, line)
	}
	if !strings.HasSuffix(doc, "\n") {
		doc += "\n"
	}
	return doc + line + "\n"
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var cfg Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode YAML config: %w", err)
	}

	if cfg.Capabilities.ConfigureLDAP {
		cfg.Capabilities.LdapTunnel = true
	}

	return &cfg, nil
}

// CanManageService checks if a specific service is permitted to be restarted/stopped
func (c *Capabilities) CanManageService(serviceName string) bool {
	for _, allowed := range c.ServiceControl {
		if allowed == serviceName {
			return true
		}
	}
	return false
}
