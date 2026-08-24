package main

import (
	"os"
	"strings"
	"testing"
)

// A managed block outlives the process that wrote it. When the agent restarts,
// that block is stale state of its own making -- and worse, it feeds the
// resolver, so the "already resolves to the discovered IP, no override needed"
// shortcut in StartLocalDiscovery compares the agent's own previous answer
// against itself and concludes there is nothing to do. A block written by an
// earlier version that broke TLS therefore survived every restart forever.
func TestRevertOverrideClearsTheManagedBlockAndRoute(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hosts"
	seed := "127.0.0.1\tlocalhost\n" +
		hostsBlockBegin + "\n" +
		"192.168.1.57\tsso.example.com\n" +
		hostsBlockEnd + "\n"
	if err := os.WriteFile(path, []byte(seed), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	restore := setTestHostsPath(path)
	defer restore()

	origExec := routeExec
	var routeArgs []string
	routeExec = func(name string, args ...string) ([]byte, error) {
		routeArgs = append([]string{name}, args...)
		return nil, nil
	}
	defer func() { routeExec = origExec }()

	lastIP := "192.168.1.57"
	overridden := true
	revertOverride("sso.example.com", &lastIP, &overridden)

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	got := string(out)
	if strings.Contains(got, "sso.example.com") {
		t.Fatalf("managed entry survived the revert:\n%s", got)
	}
	if !strings.Contains(got, "127.0.0.1\tlocalhost") {
		t.Fatalf("revert ate an unmanaged line:\n%s", got)
	}
	if overridden {
		t.Fatal("revert left the override flag set")
	}
	if lastIP != "" {
		t.Fatalf("revert left lastIP = %q", lastIP)
	}
	if len(routeArgs) == 0 {
		t.Fatal("revert did not tear down the pinned host route")
	}
}

// Half a teardown is worse than none: the hosts entry going away while the /32
// route stays pins packets at an address nothing resolves to any more. The
// failure path must not advance the state either.
func TestRevertOverrideKeepsStateWhenTheHostsFileCannotBeWritten(t *testing.T) {
	restore := setTestHostsPath(t.TempDir() + "/no/such/dir/hosts")
	defer restore()

	origExec := routeExec
	routeCalled := false
	routeExec = func(name string, args ...string) ([]byte, error) {
		routeCalled = true
		return nil, nil
	}
	defer func() { routeExec = origExec }()

	lastIP := "192.168.1.57"
	overridden := true
	revertOverride("sso.example.com", &lastIP, &overridden)

	if routeCalled {
		t.Fatal("tore down the route after failing to clear the hosts file")
	}
	if !overridden || lastIP == "" {
		t.Fatal("state was advanced even though the revert failed")
	}
}
