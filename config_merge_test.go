package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.yml")
	if err := os.WriteFile(p, []byte(body), 0640); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	return p
}

// The bug: sed -i "s|^key:.*|...|" only substitutes an EXISTING line, so a key
// the config never had was silently dropped and the operator had to delete
// agent.yml for the setting to take effect.
func TestApplyConfigValuesAddsMissingKey(t *testing.T) {
	p := writeTempConfig(t, "server_url: \"https://old.example.com\"\nauth_token: \"\"\n")

	if err := ApplyConfigValues(p, map[string]string{"join_key": "jk-abc123"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), `join_key: "jk-abc123"`) {
		t.Fatalf("missing key was not added:\n%s", got)
	}
}

func TestApplyConfigValuesReplacesExistingKey(t *testing.T) {
	p := writeTempConfig(t, "server_url: \"https://old.example.com\"\njoin_key: \"stale\"\n")

	if err := ApplyConfigValues(p, map[string]string{
		"server_url": "https://new.example.com",
		"join_key":   "fresh",
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := string(mustRead(t, p))
	if !strings.Contains(got, `server_url: "https://new.example.com"`) {
		t.Fatalf("server_url not replaced:\n%s", got)
	}
	if strings.Contains(got, "old.example.com") || strings.Contains(got, "stale") {
		t.Fatalf("old values survived:\n%s", got)
	}
}

// Everything the operator wrote -- comments, nested blocks, capabilities --
// has to survive a merge untouched. This is the whole reason not to rewrite
// the file from a parsed struct.
func TestApplyConfigValuesPreservesCommentsAndNesting(t *testing.T) {
	original := `# theta-agent configuration file
server_url: "https://old.example.com"

# The one credential you need to add a host.
join_key: ""

location: "default" # Location identifier

wireguard:
  tunnel_name: "theta-mesh"
  conf: ""

capabilities:
  telemetry: true
  reboot: false
  service_control: []
`
	p := writeTempConfig(t, original)
	if err := ApplyConfigValues(p, map[string]string{"join_key": "jk-xyz"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := string(mustRead(t, p))

	for _, want := range []string{
		"# theta-agent configuration file",
		"# The one credential you need to add a host.",
		`  tunnel_name: "theta-mesh"`,
		"  telemetry: true",
		"  service_control: []",
		`location: "default"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("merge lost %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, `join_key: "jk-xyz"`) {
		t.Fatalf("join_key not set:\n%s", got)
	}
}

// A nested key must not be hijacked by a top-level set of the same name --
// `conf` lives under wireguard here.
func TestApplyConfigValuesStillParsesAfterMerge(t *testing.T) {
	p := writeTempConfig(t, "server_url: \"https://a\"\ncapabilities:\n  telemetry: true\n")
	if err := ApplyConfigValues(p, map[string]string{
		"auth_token": "tok",
		"public_key": "cHVia2V5",
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("result does not load: %v", err)
	}
	if cfg.AuthToken != "tok" {
		t.Fatalf("auth_token = %q, want tok", cfg.AuthToken)
	}
	if !cfg.Capabilities.Telemetry {
		t.Fatalf("telemetry capability lost in merge")
	}
}

// Booleans must not be written as quoted strings or YAML decodes them wrong.
func TestApplyConfigValuesKeepsBoolsUnquoted(t *testing.T) {
	p := writeTempConfig(t, "server_url: \"https://a\"\nauto_vpn: false\n")
	if err := ApplyConfigValues(p, map[string]string{"auto_vpn": "true"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := string(mustRead(t, p))
	if !strings.Contains(got, "auto_vpn: true") {
		t.Fatalf("bool was quoted:\n%s", got)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.AutoVPN {
		t.Fatalf("auto_vpn did not decode as true")
	}
}

// setYamlScalarValue's pattern also matches an INDENTED line and rewrites it
// flush-left, so `config-set reboot=true` would lift `reboot` out of the
// capabilities block -- silently dropping the capability while still producing
// valid YAML, which the parse check cannot catch. Refuse instead.
func TestApplyConfigValuesRefusesNestedKey(t *testing.T) {
	original := "server_url: \"https://a\"\ncapabilities:\n  telemetry: true\n  reboot: false\n"
	p := writeTempConfig(t, original)

	err := ApplyConfigValues(p, map[string]string{"reboot": "true"})
	if err == nil {
		t.Fatalf("expected a refusal for a nested-only key")
	}
	if !strings.Contains(err.Error(), "nested") {
		t.Fatalf("error should explain the nesting problem, got: %v", err)
	}
	if got := string(mustRead(t, p)); got != original {
		t.Fatalf("file was modified despite the refusal:\n%s", got)
	}
}

// A top-level key must still be settable even when a nested key shares its name.
func TestApplyConfigValuesTopLevelWinsOverNestedNamesake(t *testing.T) {
	p := writeTempConfig(t, "conf: \"top\"\nwireguard:\n  conf: \"nested\"\n")
	if err := ApplyConfigValues(p, map[string]string{"conf": "changed"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := string(mustRead(t, p))
	if !strings.Contains(got, `conf: "changed"`) {
		t.Fatalf("top-level conf not set:\n%s", got)
	}
	if !strings.Contains(got, `  conf: "nested"`) {
		t.Fatalf("nested conf was clobbered:\n%s", got)
	}
}

func TestApplyConfigValuesMissingFileErrors(t *testing.T) {
	if err := ApplyConfigValues(filepath.Join(t.TempDir(), "nope.yml"), map[string]string{"a": "b"}); err == nil {
		t.Fatalf("expected an error for a missing config")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return b
}
