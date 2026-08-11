package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/mdns"
)

func withTempHostsFile(t *testing.T, initial string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if initial != "" {
		if err := os.WriteFile(path, []byte(initial), 0644); err != nil {
			t.Fatalf("seeding temp hosts file: %v", err)
		}
	}
	// setTestHostsPath redirects the platform hosts path at this temp file and
	// restores it on cleanup. Runs on every OS: Windows hosts tests use the
	// real Windows write path (minus the ipconfig flush, which the injected
	// path suppresses), so this is where the CRLF/Windows behavior is guarded.
	restore := setTestHostsPath(path)
	t.Cleanup(restore)
	return path
}

func TestApplyHostsOverride_AddsManagedBlock(t *testing.T) {
	path := withTempHostsFile(t, "127.0.0.1\tlocalhost\n")

	if err := applyHostsOverride(map[string]string{"sso.example.com": "10.0.0.5"}); err != nil {
		t.Fatalf("applyHostsOverride: %v", err)
	}

	got, _ := os.ReadFile(path)
	s := string(got)
	if !strings.Contains(s, "127.0.0.1\tlocalhost") {
		t.Errorf("existing content was clobbered: %q", s)
	}
	if !strings.Contains(s, hostsBlockBegin) || !strings.Contains(s, hostsBlockEnd) {
		t.Errorf("managed block markers missing: %q", s)
	}
	if !strings.Contains(s, "10.0.0.5\tsso.example.com") {
		t.Errorf("override entry missing: %q", s)
	}
}

func TestApplyHostsOverride_ReplacesPriorBlockRatherThanStacking(t *testing.T) {
	path := withTempHostsFile(t, "")
	if err := applyHostsOverride(map[string]string{"sso.example.com": "10.0.0.5"}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := applyHostsOverride(map[string]string{"sso.example.com": "10.0.0.9"}); err != nil {
		t.Fatalf("second apply: %v", err)
	}

	got, _ := os.ReadFile(path)
	s := string(got)
	if strings.Count(s, hostsBlockBegin) != 1 {
		t.Fatalf("expected exactly one managed block, got content: %q", s)
	}
	if strings.Contains(s, "10.0.0.5") {
		t.Errorf("stale override (10.0.0.5) should have been replaced, got: %q", s)
	}
	if !strings.Contains(s, "10.0.0.9") {
		t.Errorf("new override missing, got: %q", s)
	}
}

func TestApplyHostsOverride_EmptyEntriesRemovesBlockEntirely(t *testing.T) {
	path := withTempHostsFile(t, "127.0.0.1\tlocalhost\n")
	if err := applyHostsOverride(map[string]string{"sso.example.com": "10.0.0.5"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := applyHostsOverride(map[string]string{}); err != nil {
		t.Fatalf("clear: %v", err)
	}

	got, _ := os.ReadFile(path)
	s := string(got)
	if strings.Contains(s, hostsBlockBegin) || strings.Contains(s, "10.0.0.5") {
		t.Errorf("expected no discovery trace left after clearing, got: %q", s)
	}
	if !strings.Contains(s, "127.0.0.1\tlocalhost") {
		t.Errorf("pre-existing content should survive a full clear, got: %q", s)
	}
}

func TestApplyHostsOverride_CRLFWindowsHostsFile(t *testing.T) {
	// Windows hosts files use CRLF. The rewrite must (a) match the block
	// markers on a CRLF file, (b) write back with the platform EOL, and (c)
	// not double up \r\r\n from the read side.
	path := withTempHostsFile(t, "127.0.0.1\tlocalhost\r\n192.168.1.5\tsomeotherhost\r\n")

	if err := applyHostsOverride(map[string]string{"sso.example.com": "10.0.0.5"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := applyHostsOverride(map[string]string{"sso.example.com": "10.0.0.9"}); err != nil {
		t.Fatalf("reapply: %v", err)
	}

	got, _ := os.ReadFile(path)
	s := string(got)
	if strings.Contains(s, "\r\r\n") {
		t.Fatalf("doubled CR detected (CRLF handled wrong): %q", s)
	}
	if strings.Contains(s, "10.0.0.5") {
		t.Errorf("stale override should be replaced on a CRLF file, got: %q", s)
	}
	if !strings.Contains(s, "10.0.0.9\tsso.example.com") {
		t.Errorf("override entry missing on CRLF file, got: %q", s)
	}
	if strings.Count(s, hostsBlockBegin) != 1 {
		t.Errorf("expected exactly one managed block, got: %q", s)
	}
	for _, want := range []string{"127.0.0.1\tlocalhost", "192.168.1.5\tsomeotherhost"} {
		if !strings.Contains(s, want) {
			t.Errorf("pre-existing content %q was clobbered, got: %q", want, s)
		}
	}
}

func TestHostFromURL(t *testing.T) {
	cases := map[string]string{
		"https://sso.example.com:443/api": "sso.example.com",
		"http://sso.example.com":          "sso.example.com",
		"not a url at all":                "",
		"":                                "",
	}
	for in, want := range cases {
		if got := hostFromURL(in); got != want {
			t.Errorf("hostFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEntryAnnouncesHost(t *testing.T) {
	entry := &mdns.ServiceEntry{InfoFields: []string{"hosts=sso.example.com,proxy.example.com"}}
	if !entryAnnouncesHost(entry, "sso.example.com") {
		t.Error("expected match for sso.example.com")
	}
	if !entryAnnouncesHost(entry, "proxy.example.com") {
		t.Error("expected match for proxy.example.com")
	}
	if entryAnnouncesHost(entry, "jump.example.com") {
		t.Error("expected no match for a host not in the TXT record")
	}
}
