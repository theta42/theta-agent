package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	// The target should be 0600 (holds secrets).
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600, got %o", info.Mode().Perm())
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
