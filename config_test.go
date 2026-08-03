package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary directory for config files
	tmpDir, err := os.MkdirTemp("", "agent-config-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name        string
		yamlContent string
		filename    string
		expectErr   bool
	}{
		{
			name: "valid config",
			yamlContent: `
server_url: "http://sso.local"
auth_token: "secret-token"
location: "datacenter-1"
capabilities:
  telemetry: true
  configure_ldap: true
  reboot: false
  service_control: ["nginx", "gitea"]
  arbitrary_bash: false
`,
			filename:  "valid.yml",
			expectErr: false,
		},
		{
			name:        "invalid yaml",
			yamlContent: "invalid: [yaml: content",
			filename:    "invalid.yml",
			expectErr:   true,
		},
		{
			name:        "missing file",
			yamlContent: "",
			filename:    "nonexistent.yml",
			expectErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(tmpDir, tc.filename)
			if tc.yamlContent != "" {
				err := os.WriteFile(path, []byte(tc.yamlContent), 0644)
				if err != nil {
					t.Fatalf("failed to write temp file: %v", err)
				}
			}

			cfg, err := LoadConfig(path)
			if (err != nil) != tc.expectErr {
				t.Errorf("LoadConfig() error = %v, expectErr %v", err, tc.expectErr)
				return
			}

			if !tc.expectErr && cfg == nil {
				t.Error("LoadConfig() returned nil config without error")
			}
		})
	}
}

func TestCanManageService(t *testing.T) {
	caps := Capabilities{
		ServiceControl: []string{"nginx", "gitea"},
	}

	tests := []struct {
		service  string
		expected bool
	}{
		{"nginx", true},
		{"gitea", true},
		{"ssh", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.service, func(t *testing.T) {
			if got := caps.CanManageService(tc.service); got != tc.expected {
				t.Errorf("CanManageService(%q) = %v, want %v", tc.service, got, tc.expected)
			}
		})
	}
}
