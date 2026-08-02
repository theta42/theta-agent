package main

import (
	"fmt"
	"os"

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
	Capabilities Capabilities `yaml:"capabilities"`
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
