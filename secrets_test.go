package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestRenderSecrets verifies the agent parses `{{ bao "path#key" }}` placeholders,
// fetches the secrets from the SSO, renders the template to its target
// atomically, and runs the reload.
func TestRenderSecrets(t *testing.T) {
	dir := t.TempDir()
	tpl := filepath.Join(dir, "db.env.tpl")
	target := filepath.Join(dir, "db.env")
	os.WriteFile(tpl, []byte("DB_USER=\"{{ bao \"secret/data/nodes/n1/db#username\" }}\"\nDB_PASS=\"{{ bao \"secret/data/nodes/n1/db#password\" }}\"\n"), 0600)

	// Fake SSO secrets endpoint.
	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/secrets" {
			w.WriteHeader(404)
			return
		}
		var req struct{ Paths []string `json:"paths"` }
		json.NewDecoder(r.Body).Decode(&req)
		gotPaths = req.Paths
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": map[string]interface{}{
				"secret/data/nodes/n1/db": map[string]interface{}{
					"username": "alice",
					"password": "s3cret",
				},
			},
		})
	}))
	defer srv.Close()

	cfg := &Config{
		ServerURL: srv.URL,
		AuthToken: "tok",
		Secrets: []SecretTarget{
			{Template: tpl, Target: target, Reload: ""},
		},
	}

	exec := &MockExecutor{}
	if err := renderSecrets(cfg, exec); err != nil {
		t.Fatalf("renderSecrets: %v", err)
	}

	// The requested path should be the one in the template.
	if len(gotPaths) != 1 || gotPaths[0] != "secret/data/nodes/n1/db" {
		t.Fatalf("expected to request secret/data/nodes/n1/db, got %v", gotPaths)
	}

	// The target should be rendered with the secret values.
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	expected := "DB_USER=\"alice\"\nDB_PASS=\"s3cret\"\n"
	if string(content) != expected {
		t.Fatalf("rendered content mismatch:\n got: %q\nwant: %q", content, expected)
	}

	// The target should be 0600 (holds secrets). Windows has no POSIX modes and
	// reports 0666 regardless; the intent there is covered by the ACLs the
	// installer sets on the target directory.
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(target)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600, got %o", info.Mode().Perm())
		}
	}
}

// TestRenderSecretsReload verifies the reload command runs after rendering.
func TestRenderSecretsReload(t *testing.T) {
	dir := t.TempDir()
	tpl := filepath.Join(dir, "app.tpl")
	target := filepath.Join(dir, "app.conf")
	os.WriteFile(tpl, []byte("KEY={{ bao \"secret/data/nodes/n1/app#key\" }}"), 0600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"secrets": map[string]interface{}{
				"secret/data/nodes/n1/app": map[string]interface{}{"key": "v"},
			},
		})
	}))
	defer srv.Close()

	cfg := &Config{
		ServerURL: srv.URL,
		AuthToken: "tok",
		Secrets: []SecretTarget{
			{Template: tpl, Target: target, Reload: "systemctl reload app"},
		},
	}
	exec := &MockExecutor{}
	if err := renderSecrets(cfg, exec); err != nil {
		t.Fatalf("renderSecrets: %v", err)
	}
	if len(exec.ExecutedCommands) != 1 {
		t.Fatalf("expected 1 reload command, got %v", exec.ExecutedCommands)
	}
	cmd := exec.ExecutedCommands[0]
	if len(cmd) != 3 || cmd[0] != "sh" || cmd[2] != "systemctl reload app" {
		t.Fatalf("expected reload 'sh -c systemctl reload app', got %v", cmd)
	}
}

const testCert = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIadOG0kUXwn9lyfXWJHU1TAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDpZ
6y1XCcvE5nX5WQyd8pQ8I8yv1L7v0uHm7z8pB6qFf4xlmz5Fq6R6c4a1BqfyzKxg
sZ2nZmKZTn0qrX7RJKajQjBAMA4GA1UdDwEB/wQEAwICpDAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBTn1UUw0N5gcjkFqA6Yz2WkG5w1yzAKBggqhkjOPQQDAgNI
ADBFAiEA5oM+8V8m4X8b0K3f2ZQ2j7V5v8y0ZQ2j7V5v8y0ZQ2gCIDpZ6y1XCcvE
5nX5WQyd8pQ8I8yv1L7v0uHm7z8pB6qF
-----END CERTIFICATE-----
`

// TestRenderOneBackup verifies a valid render leaves a .bak copy of what was
// there before, and replaces the target as usual.
func TestRenderOneBackup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.conf")
	os.WriteFile(target, []byte("old content"), 0600)

	tpl := filepath.Join(dir, "app.tpl")
	os.WriteFile(tpl, []byte("KEY={{ bao \"secret/data/nodes/n1/app#key\" }}"), 0600)

	t2 := SecretTarget{Template: tpl, Target: target}
	secrets := map[string]map[string]interface{}{
		"secret/data/nodes/n1/app": {"key": "new-value"},
	}
	exec := &MockExecutor{}
	if err := renderOne(t2, secrets, exec); err != nil {
		t.Fatalf("renderOne: %v", err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(content) != "KEY=new-value" {
		t.Fatalf("target not updated: %q", content)
	}

	bak, err := os.ReadFile(target + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(bak) != "old content" {
		t.Fatalf(".bak mismatch: got %q, want %q", bak, "old content")
	}
}

// TestRenderOneNoBackupOnFirstRender verifies a target that doesn't exist yet
// is not an error and produces no .bak.
func TestRenderOneNoBackupOnFirstRender(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.conf")

	tpl := filepath.Join(dir, "app.tpl")
	os.WriteFile(tpl, []byte("KEY={{ bao \"secret/data/nodes/n1/app#key\" }}"), 0600)

	t2 := SecretTarget{Template: tpl, Target: target}
	secrets := map[string]map[string]interface{}{
		"secret/data/nodes/n1/app": {"key": "v"},
	}
	if err := renderOne(t2, secrets, &MockExecutor{}); err != nil {
		t.Fatalf("renderOne: %v", err)
	}
	if _, err := os.Stat(target + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("expected no .bak on first render, got err=%v", err)
	}
}

// TestRenderOneValidPemReplacesTarget verifies rendered content that parses
// as valid PEM replaces the target and leaves a .bak, and runs the reload.
func TestRenderOneValidPemReplacesTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tls.crt")
	os.WriteFile(target, []byte("old cert"), 0600)

	tpl := filepath.Join(dir, "tls.tpl")
	os.WriteFile(tpl, []byte("{{ bao \"secret/data/nodes/n1/tls#cert\" }}"), 0600)

	t2 := SecretTarget{Template: tpl, Target: target, Reload: "systemctl reload nginx"}
	secrets := map[string]map[string]interface{}{
		"secret/data/nodes/n1/tls": {"cert": testCert},
	}
	exec := &MockExecutor{}
	if err := renderOne(t2, secrets, exec); err != nil {
		t.Fatalf("renderOne: %v", err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(content) != testCert {
		t.Fatalf("target not updated with rendered PEM")
	}
	if _, err := os.Stat(target + ".bak"); err != nil {
		t.Fatalf("expected .bak, got err=%v", err)
	}
	if len(exec.ExecutedCommands) != 1 {
		t.Fatalf("expected reload to run, got %v", exec.ExecutedCommands)
	}
}

// TestRenderOneInvalidPemLeavesTargetUntouched verifies rendered content that
// looks like PEM (starts with -----BEGIN) but doesn't parse is rejected: the
// existing target is left alone, no .bak is written, and the reload does not
// run. This is the case a template referencing a not-yet-existing secret path
// hits -- it renders an empty BEGIN/END block instead of destroying a live
// cert with nothing.
func TestRenderOneInvalidPemLeavesTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tls.crt")
	os.WriteFile(target, []byte(testCert), 0600)

	tpl := filepath.Join(dir, "tls.tpl")
	os.WriteFile(tpl, []byte("-----BEGIN CERTIFICATE-----\n{{ bao \"secret/data/nodes/n1/tls#cert\" }}\n-----END CERTIFICATE-----\n"), 0600)

	t2 := SecretTarget{Template: tpl, Target: target, Reload: "systemctl reload nginx"}
	// The referenced key does not exist in secrets, so the placeholder
	// renders to "" -- an empty, invalid PEM block.
	secrets := map[string]map[string]interface{}{}
	exec := &MockExecutor{}

	err := renderOne(t2, secrets, exec)
	if err == nil {
		t.Fatal("expected renderOne to reject invalid PEM, got nil error")
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(content) != testCert {
		t.Fatalf("target should be untouched, got %q", content)
	}
	if _, statErr := os.Stat(target + ".bak"); !os.IsNotExist(statErr) {
		t.Fatalf("expected no .bak on rejected render, got err=%v", statErr)
	}
	if len(exec.ExecutedCommands) != 0 {
		t.Fatalf("expected reload not to run, got %v", exec.ExecutedCommands)
	}
}

// TestRenderOneNonPemTargetUnvalidated verifies a target with no PEM markers
// keeps today's behavior exactly: no validation, empty substitutions and all.
func TestRenderOneNonPemTargetUnvalidated(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.env")
	os.WriteFile(target, []byte("old"), 0600)

	tpl := filepath.Join(dir, "app.tpl")
	os.WriteFile(tpl, []byte("KEY={{ bao \"secret/data/nodes/n1/app#missing\" }}"), 0600)

	t2 := SecretTarget{Template: tpl, Target: target}
	// The referenced key is absent -- renders to "KEY=", same as before this
	// change, since this target has nothing that looks like PEM.
	secrets := map[string]map[string]interface{}{
		"secret/data/nodes/n1/app": {},
	}
	if err := renderOne(t2, secrets, &MockExecutor{}); err != nil {
		t.Fatalf("renderOne: %v", err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(content) != "KEY=" {
		t.Fatalf("expected unvalidated render 'KEY=', got %q", content)
	}
}
