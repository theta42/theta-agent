package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

// PersistEnrollment rewrites a hand-edited file, so it must replace exactly the
// credential lines and leave everything else -- comments, capabilities,
// formatting -- untouched.
func TestPersistEnrollmentPreservesFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/agent.yml"
	original := `# theta-agent configuration file
server_url: "https://sso.example.com"

# Bootstrap credential, exchanged on first connect.
join_key: "tjk_abc123"
public_key: ""
location: "rack-4"

capabilities:
  telemetry: true
  # keep this comment
  reboot: false
  service_control: ["nginx"]
`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := cm.PersistEnrollment("issued-token-xyz", "PUBKEYBASE64"); err != nil {
		t.Fatalf("PersistEnrollment: %v", err)
	}

	out, _ := os.ReadFile(path)
	got := string(out)

	for _, want := range []string{
		`auth_token: "issued-token-xyz"`,
		`public_key: "PUBKEYBASE64"`,
		`join_key: ""`, // blanked: a fleet-wide key must not linger once unneeded
		"# theta-agent configuration file",
		"# keep this comment",
		`location: "rack-4"`,
		`service_control: ["nginx"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in rewritten config, got:\n%s", want, got)
		}
	}

	// and the in-memory config is live without a restart
	if cm.Get().AuthToken != "issued-token-xyz" {
		t.Errorf("config not reloaded: AuthToken = %q", cm.Get().AuthToken)
	}
	if cm.Get().Credential() != "issued-token-xyz" {
		t.Errorf("Credential() should prefer the issued token, got %q", cm.Get().Credential())
	}

	// file must stay 0600 -- it now holds a credential. POSIX-only: Windows has
	// no mode bits (0666 is reported regardless) and relies on ACLs instead.
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0600 {
			t.Errorf("expected mode 0600, got %o", fi.Mode().Perm())
		}
	}
}

func TestPersistEnrollmentAddsMissingKeys(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/agent.yml"
	// No auth_token or public_key lines at all.
	if err := os.WriteFile(path, []byte("server_url: \"https://sso.example.com\"\njoin_key: \"tjk_x\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cm.PersistEnrollment("tok", "pk"); err != nil {
		t.Fatalf("PersistEnrollment: %v", err)
	}
	if cm.Get().AuthToken != "tok" || cm.Get().PublicKey != "pk" {
		out, _ := os.ReadFile(path)
		t.Errorf("keys not appended; file:\n%s", out)
	}
}

func TestCredentialPrefersAuthToken(t *testing.T) {
	c := &Config{JoinKey: "tjk_x"}
	if c.Credential() != "tjk_x" {
		t.Errorf("unenrolled agent should present the join key, got %q", c.Credential())
	}
	c.AuthToken = "own-token"
	if c.Credential() != "own-token" {
		t.Errorf("enrolled agent must present its own token, not the join key, got %q", c.Credential())
	}
}

func TestPersistEnrollmentRejectsEmptyToken(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/agent.yml"
	os.WriteFile(path, []byte("server_url: \"x\"\n"), 0600)
	cm, _ := NewConfigManager(path)
	if err := cm.PersistEnrollment("", "pk"); err == nil {
		t.Error("expected an error when the server sends no token")
	}
}

// TestPersistAutoVPN writes the tray preference into the file and reloads it.
func TestPersistAutoVPN(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/agent.yml"
	os.WriteFile(path, []byte("server_url: \"https://sso.example.com\"\njoin_key: \"tjk_abc123\"\n"), 0600)
	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := cm.PersistAutoVPN(true); err != nil {
		t.Fatalf("PersistAutoVPN: %v", err)
	}
	if !cm.Get().AutoVPN {
		t.Errorf("AutoVPN should be true after persist")
	}
	out, _ := os.ReadFile(path)
	if !strings.Contains(string(out), "auto_vpn: true") {
		t.Errorf("expected auto_vpn: true in file, got:\n%s", out)
	}

	if err := cm.PersistAutoVPN(false); err != nil {
		t.Fatalf("PersistAutoVPN(false): %v", err)
	}
	if cm.Get().AutoVPN {
		t.Errorf("AutoVPN should be false after persist")
	}
}

// TestClearEnrollment blanks credentials so the agent re-enrolls.
func TestClearEnrollment(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/agent.yml"
	os.WriteFile(path, []byte("server_url: \"https://sso.example.com\"\nauth_token: \"tok-abc\"\npublic_key: \"PK\"\njoin_key: \"tjk_keep\"\n"), 0600)
	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := cm.ClearEnrollment(); err != nil {
		t.Fatalf("ClearEnrollment: %v", err)
	}
	cfg := cm.Get()
	if cfg.AuthToken != "" || cfg.PublicKey != "" {
		t.Errorf("expected cleared credentials, got token=%q pub=%q", cfg.AuthToken, cfg.PublicKey)
	}
	out, _ := os.ReadFile(path)
	if strings.Contains(string(out), "tok-abc") {
		t.Errorf("old token should be gone from file, got:\n%s", out)
	}
}

// TestReloadIfChangedPicksUpAnotherProcessesEdit is the regression for a
// just-registered service never appearing in telemetry.
//
// `theta-agent register` writes agent.yml from its OWN process and tells the
// Directory over a one-shot socket. The daemon held its config in memory, so
// `services:` on the wire stayed as it was at startup: the Directory created
// the service resource from the registration and then never got a status
// sample for it.
func TestReloadIfChangedPicksUpAnotherProcessesEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yml")
	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}
	write("server_url: \"wss://sso\"\nauth_token: \"t\"\nservices: []\n")

	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatalf("NewConfigManager: %v", err)
	}

	// The first call only establishes the baseline; it must not claim a change.
	if changed, err := cm.ReloadIfChanged(); err != nil || changed {
		t.Fatalf("first ReloadIfChanged = (%v, %v), want (false, nil)", changed, err)
	}
	// And an unchanged file stays unchanged.
	if changed, err := cm.ReloadIfChanged(); err != nil || changed {
		t.Fatalf("unchanged ReloadIfChanged = (%v, %v), want (false, nil)", changed, err)
	}

	// Another process registers a service.
	write("server_url: \"wss://sso\"\nauth_token: \"t\"\nservices:\n  - name: emby-server\n    subtype: systemd\n")
	// Same-second writes would compare equal on a filesystem with coarse mtime.
	os.Chtimes(path, time.Now().Add(2*time.Second), time.Now().Add(2*time.Second))

	changed, err := cm.ReloadIfChanged()
	if err != nil {
		t.Fatalf("ReloadIfChanged after edit: %v", err)
	}
	if !changed {
		t.Fatal("an edit by another process was not noticed")
	}
	got := cm.Get().Services
	if len(got) != 1 || got[0].Name != "emby-server" {
		t.Fatalf("Services = %+v, want the newly registered emby-server", got)
	}
}

// A half-written or briefly invalid file must not take the running agent's
// configuration away from it.
func TestReloadIfChangedKeepsTheLastGoodConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yml")
	if err := os.WriteFile(path, []byte("server_url: \"wss://sso\"\nauth_token: \"good\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = cm.ReloadIfChanged()

	if err := os.WriteFile(path, []byte("server_url: \"wss://sso\"\n  auth_token: [oops\n"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, time.Now().Add(2*time.Second), time.Now().Add(2*time.Second))

	changed, rerr := cm.ReloadIfChanged()
	if rerr == nil {
		t.Fatal("expected an error for an unparseable config")
	}
	if changed {
		t.Error("a failed reload must not report a change")
	}
	if got := cm.Get().AuthToken; got != "good" {
		t.Errorf("auth_token = %q; the last good config must survive a bad write", got)
	}
}
