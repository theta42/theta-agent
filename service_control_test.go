package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// argvRecorder captures the exact argv it was asked to run. The whole class of
// bug here is "ran the wrong thing", so the assertion has to be on argv and not
// on a substring.
type argvRecorder struct {
	calls [][]string
	// fail names commands that should report failure, so a test can describe
	// a host where (say) `ip link show` finds no interface.
	fail map[string]bool
}

func (r *argvRecorder) Execute(command string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{command}, args...))
	if r.fail[command] {
		return nil, errors.New("mock: " + command + " failed")
	}
	return []byte("ok"), nil
}
func (r *argvRecorder) WriteFile(string, []byte, os.FileMode) error { return nil }
func (r *argvRecorder) ReadFile(string) ([]byte, error)             { return nil, nil }

func withServiceExecutor(t *testing.T) (*argvRecorder, PlatformOps) {
	t.Helper()
	rec := &argvRecorder{}
	prev := serviceExecutor
	serviceExecutor = rec
	t.Cleanup(func() { serviceExecutor = prev })
	// linuxPlatformOps is the systemd path; give it the same recorder so one
	// assertion style covers every branch.
	return rec, &linuxPlatformOps{exec: rec}
}

// The regression: every subtype went to systemctl, so restarting a docker
// container targeted a unit that does not exist.
func TestControlServiceDispatchesOnSubtype(t *testing.T) {
	cases := []struct {
		subtype string
		action  string
		want    []string
	}{
		{"systemd", "restart", []string{"systemctl", "restart", "nginx"}},
		{"", "restart", []string{"systemctl", "restart", "nginx"}},
		{"SystemD", "start", []string{"systemctl", "start", "nginx"}},
		{"docker", "restart", []string{"docker", "restart", "nginx"}},
		{"podman", "stop", []string{"podman", "stop", "nginx"}},
		{"docker", "status", []string{"docker", "inspect", "nginx"}},
		// rc-service takes the service first and the verb second -- the
		// opposite order to systemctl.
		{"openrc", "restart", []string{"rc-service", "nginx", "restart"}},
	}
	for _, tc := range cases {
		rec, ops := withServiceExecutor(t)
		if _, err := controlService(ops, tc.subtype, "nginx", tc.action); err != nil {
			t.Fatalf("subtype %q action %q: %v", tc.subtype, tc.action, err)
		}
		if len(rec.calls) != 1 {
			t.Fatalf("subtype %q: %d commands run, want 1", tc.subtype, len(rec.calls))
		}
		got := rec.calls[0]
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("subtype %q action %q ran %v, want %v", tc.subtype, tc.action, got, tc.want)
		}
	}
}

// ServiceControl interpolates the action into an argv, so it is an allowlist,
// not a passthrough.
func TestControlServiceRefusesUnknownActions(t *testing.T) {
	for _, action := range []string{"", "mask", "--version", "restart; rm -rf /", "enable"} {
		rec, ops := withServiceExecutor(t)
		if _, err := controlService(ops, "systemd", "nginx", action); err == nil {
			t.Errorf("action %q was accepted; expected a refusal", action)
		}
		if len(rec.calls) != 0 {
			t.Errorf("action %q ran %v; nothing should have been executed", action, rec.calls)
		}
	}
}

// Containers have no reload. Quietly substituting a restart would be a
// surprising thing to do to a running service.
func TestControlServiceRefusesReloadForContainers(t *testing.T) {
	for _, subtype := range []string{"docker", "podman"} {
		rec, ops := withServiceExecutor(t)
		_, err := controlService(ops, subtype, "nginx", "reload")
		if err == nil {
			t.Fatalf("%s reload was accepted", subtype)
		}
		if !strings.Contains(err.Error(), "start, stop or restart") {
			t.Errorf("%s reload error should say what IS available, got %q", subtype, err)
		}
		if len(rec.calls) != 0 {
			t.Errorf("%s reload ran %v", subtype, rec.calls)
		}
	}
}

func TestControlServiceRequiresAName(t *testing.T) {
	_, ops := withServiceExecutor(t)
	if _, err := controlService(ops, "systemd", "", "restart"); err == nil {
		t.Fatal("an empty service name was accepted")
	}
}
