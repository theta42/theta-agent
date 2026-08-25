package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAgentYML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// The regression this command exists for: a host re-pointed at a rebuilt
// directory keeps a token the new directory never issued, and Credential()
// prefers it over the join key that would have worked.
func TestResetEnrollmentClearsTokenAndSigningKey(t *testing.T) {
	path := writeAgentYML(t, `server_url: "wss://sso.example.com"
auth_token: "tok_from_the_old_directory"
join_key: "join_abc"
public_key: "old-directory-signing-key"
location: "unknown"
`)
	cleared, err := resetEnrollment(path, "", false)
	if err != nil {
		t.Fatalf("resetEnrollment: %v", err)
	}
	if len(cleared) != 2 {
		t.Fatalf("cleared = %v, want auth_token and public_key", cleared)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if cfg.AuthToken != "" {
		t.Errorf("auth_token = %q, want empty", cfg.AuthToken)
	}
	if cfg.PublicKey != "" {
		t.Errorf("public_key = %q, want empty", cfg.PublicKey)
	}
	// The whole point is that the join key survives to be used.
	if cfg.JoinKey != "join_abc" {
		t.Errorf("join_key = %q, want it preserved", cfg.JoinKey)
	}
	if cfg.ServerURL != "wss://sso.example.com" {
		t.Errorf("server_url = %q, want it preserved", cfg.ServerURL)
	}
	if got := cfg.Credential(); got != "join_abc" {
		t.Errorf("Credential() = %q, want the join key -- clearing the token is what makes it win", got)
	}
}

// Clearing a token with nothing to fall back on leaves the host unable to
// authenticate at all, which is worse than the stale credential.
func TestResetEnrollmentRefusesWithoutAJoinKey(t *testing.T) {
	path := writeAgentYML(t, `server_url: "wss://sso.example.com"
auth_token: "tok_live"
join_key: ""
`)
	if _, err := resetEnrollment(path, "", false); err == nil {
		t.Fatal("expected a refusal when there is no join_key to fall back on")
	} else if !strings.Contains(err.Error(), "join_key") {
		t.Errorf("error should name the missing join_key, got %q", err)
	}

	cfg, _ := LoadConfig(path)
	if cfg.AuthToken != "tok_live" {
		t.Errorf("a refused reset must not modify the file; auth_token = %q", cfg.AuthToken)
	}
}

// The mesh key is this host's own identity and the directory only ever holds
// its public half, so re-enrolment re-registers the same key. Deleting it is
// opt-in.
func TestResetEnrollmentLeavesTheMeshKeyAloneByDefault(t *testing.T) {
	path := writeAgentYML(t, "server_url: \"wss://s\"\nauth_token: \"t\"\njoin_key: \"j\"\npublic_key: \"p\"\n")
	keyPath := filepath.Join(filepath.Dir(path), "wg_private.key")
	if err := os.WriteFile(keyPath, []byte("private-key-material\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := resetEnrollment(path, keyPath, false); err != nil {
		t.Fatalf("resetEnrollment: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("mesh key should survive a default reset: %v", err)
	}

	if _, err := resetEnrollment(path, keyPath, true); err != nil {
		t.Fatalf("resetEnrollment --keys: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("mesh key should be gone after --keys, stat err = %v", err)
	}
}

// A missing mesh key is the normal state on a host that never enrolled into
// the mesh; --keys must not turn that into a failure.
func TestResetEnrollmentKeysToleratesAMissingMeshKey(t *testing.T) {
	path := writeAgentYML(t, "server_url: \"wss://s\"\nauth_token: \"t\"\njoin_key: \"j\"\npublic_key: \"p\"\n")
	missing := filepath.Join(filepath.Dir(path), "never-created.key")
	if _, err := resetEnrollment(path, missing, true); err != nil {
		t.Fatalf("resetEnrollment --keys with no key present: %v", err)
	}
}
