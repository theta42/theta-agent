package main

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

type Capabilities struct {
	Telemetry      bool     `yaml:"telemetry"`
	ConfigureLDAP  bool     `yaml:"configure_ldap"`
	Reboot         bool     `yaml:"reboot"`
	ServiceControl []string `yaml:"service_control"`
	ArbitraryBash  bool     `yaml:"arbitrary_bash"`
}

type Config struct {
	ServerURL    string       `yaml:"server_url"`
	AuthToken    string       `yaml:"auth_token"`
	Location     string       `yaml:"location"`
	PublicKey    string       `yaml:"public_key"` // Ed25519 public key for signed commands
	Capabilities Capabilities `yaml:"capabilities"`
}

// ConfigManager handles thread-safe access and reloading of the agent configuration.
type ConfigManager struct {
	mu       sync.RWMutex
	current  *Config
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
