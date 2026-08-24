package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.yml")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func fatalMessages(ps []verifyProblem) []string {
	var out []string
	for _, p := range ps {
		if p.Fatal {
			out = append(out, p.Message)
		}
	}
	return out
}

func validEd25519B64() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func TestVerifyAcceptsAUsableConfig(t *testing.T) {
	wgKeyPathOverride = filepath.Join(t.TempDir(), "absent.key")
	defer func() { wgKeyPathOverride = "" }()

	p := writeConfig(t, "server_url: https://sso.example.com\nauth_token: tok\npublic_key: "+validEd25519B64()+"\n")
	problems, checked := verifyConfigAt(p)
	if f := fatalMessages(problems); len(f) != 0 {
		t.Fatalf("a usable config was rejected: %v", f)
	}
	if len(checked) == 0 {
		t.Fatal("nothing was reported as checked")
	}
}

// The failure this exists for: a public_key that does not decode produces an
// agent that starts and connects, then rejects every signed command -- so the
// install looks successful and the host silently does nothing it is told.
func TestVerifyCatchesAnUnusablePublicKey(t *testing.T) {
	wgKeyPathOverride = filepath.Join(t.TempDir(), "absent.key")
	defer func() { wgKeyPathOverride = "" }()

	for name, key := range map[string]string{
		"not base64": "!!!! not base64 !!!!",
		"wrong size": base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"empty":      "",
	} {
		p := writeConfig(t, "server_url: https://sso.example.com\nauth_token: tok\npublic_key: \""+key+"\"\n")
		if f := fatalMessages(verifyConfigAtProblems(p)); len(f) == 0 {
			t.Errorf("%s public_key was accepted", name)
		}
	}
}

func verifyConfigAtProblems(p string) []verifyProblem {
	problems, _ := verifyConfigAt(p)
	return problems
}

func TestVerifyRequiresSomethingToAuthenticateWith(t *testing.T) {
	wgKeyPathOverride = filepath.Join(t.TempDir(), "absent.key")
	defer func() { wgKeyPathOverride = "" }()

	p := writeConfig(t, "server_url: https://sso.example.com\npublic_key: "+validEd25519B64()+"\n")
	f := fatalMessages(verifyConfigAtProblems(p))
	if len(f) == 0 || !strings.Contains(strings.Join(f, "\n"), "auth_token") {
		t.Fatalf("a config with no credential was accepted: %v", f)
	}

	// A join key alone is the correct state before first enrolment.
	p2 := writeConfig(t, "server_url: https://sso.example.com\njoin_key: tjk_x\npublic_key: "+validEd25519B64()+"\n")
	if f := fatalMessages(verifyConfigAtProblems(p2)); len(f) != 0 {
		t.Fatalf("a pre-enrolment config was rejected: %v", f)
	}
}

func TestVerifyCatchesAnUnusableServerURL(t *testing.T) {
	wgKeyPathOverride = filepath.Join(t.TempDir(), "absent.key")
	defer func() { wgKeyPathOverride = "" }()

	for _, u := range []string{"", "not a url"} {
		p := writeConfig(t, "server_url: \""+u+"\"\nauth_token: tok\npublic_key: "+validEd25519B64()+"\n")
		if f := fatalMessages(verifyConfigAtProblems(p)); len(f) == 0 {
			t.Errorf("server_url %q was accepted", u)
		}
	}
}

func TestVerifyReportsAMissingConfig(t *testing.T) {
	f := fatalMessages(verifyConfigAtProblems(filepath.Join(t.TempDir(), "nope.yml")))
	if len(f) == 0 {
		t.Fatal("a missing config file was accepted")
	}
}

// A corrupt WireGuard key produces a tunnel that never comes up, and the
// symptom ("the mesh does not work") points nowhere near the key.
func TestVerifyCatchesACorruptWireGuardKey(t *testing.T) {
	dir := t.TempDir()
	wgKeyPathOverride = filepath.Join(dir, "wg.key")
	defer func() { wgKeyPathOverride = "" }()

	if err := os.WriteFile(wgKeyPathOverride, []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	p := writeConfig(t, "server_url: https://sso.example.com\nauth_token: tok\npublic_key: "+validEd25519B64()+"\n")
	f := fatalMessages(verifyConfigAtProblems(p))
	if len(f) == 0 || !strings.Contains(strings.Join(f, "\n"), "WireGuard") {
		t.Fatalf("a corrupt WireGuard key was accepted: %v", f)
	}
}

func TestVerifyAcceptsAWellFormedWireGuardKey(t *testing.T) {
	dir := t.TempDir()
	wgKeyPathOverride = filepath.Join(dir, "wg.key")
	defer func() { wgKeyPathOverride = "" }()

	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := os.WriteFile(wgKeyPathOverride, []byte(key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p := writeConfig(t, "server_url: https://sso.example.com\nauth_token: tok\npublic_key: "+validEd25519B64()+"\n")
	if f := fatalMessages(verifyConfigAtProblems(p)); len(f) != 0 {
		t.Fatalf("a valid WireGuard key was rejected: %v", f)
	}
}

// A key anyone on the box can read is a warning, not a failure -- and never
// fires on Windows, which has no POSIX mode bits (Go reports 0666 for any file
// it created). Getting that wrong is what took every Windows artifact out of
// the v2.11.0 release.
func TestVerifyWarnsOnAWorldReadableKeyExceptOnWindows(t *testing.T) {
	dir := t.TempDir()
	wgKeyPathOverride = filepath.Join(dir, "wg.key")
	defer func() { wgKeyPathOverride = "" }()

	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := os.WriteFile(wgKeyPathOverride, []byte(key), 0644); err != nil {
		t.Fatal(err)
	}
	problems := verifyWireGuardKey()
	if runtime.GOOS == "windows" {
		if len(problems) != 0 {
			t.Fatalf("mode was checked on Windows, which has no POSIX mode bits: %v", problems)
		}
		return
	}
	if len(problems) != 1 || problems[0].Fatal {
		t.Fatalf("expected exactly one non-fatal warning, got %v", problems)
	}
}
