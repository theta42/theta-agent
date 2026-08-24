package main

import (
	"strings"
	"testing"
)

// recordingExecutor is stubCommandExecutor plus a log of every command run, so
// these tests can assert on what was actually invoked -- the whole class of bug
// here was "ran the wrong thing and reported success".
type recordingExecutor struct {
	stubCommandExecutor
	calls []string
}

func (r *recordingExecutor) Execute(command string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, command+" "+strings.Join(args, " "))
	return r.stubCommandExecutor.Execute(command, args...)
}

func (r *recordingExecutor) ran(substr string) bool {
	for _, c := range r.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// A single active Wayland session for user "alice", the shape logind reports on
// a current GNOME/KDE desktop.
func waylandStub() *recordingExecutor {
	return &recordingExecutor{stubCommandExecutor: stubCommandExecutor{
		responses: map[string]string{
			"loginctl list-sessions --no-legend":                                           "3 1000 alice seat0 tty2\n",
			"loginctl show-session 3 --property=Type --property=Active --property=Display": "Type=wayland\nActive=yes\nDisplay=\n",
		},
	}}
}

func TestDesktopControlLocksResolvedSession(t *testing.T) {
	stub := waylandStub()
	p := &linuxPlatformOps{exec: stub}

	out, err := p.DesktopControl("lock_session", "")
	if err != nil {
		t.Fatalf("lock failed: %v", err)
	}
	// Must target the session by ID, not fire a blind lock-sessions.
	if !stub.ran("loginctl lock-session 3") {
		t.Fatalf("did not lock session by id; calls=%v", stub.calls)
	}
	// Must not reach for X11 tooling that cannot work under Wayland or as root.
	for _, bad := range []string{"xset", "xdg-screensaver", "DISPLAY=:0"} {
		if stub.ran(bad) {
			t.Fatalf("used X11-only tooling %q; calls=%v", bad, stub.calls)
		}
	}
	if !strings.Contains(string(out), "alice") {
		t.Fatalf("output should name the session user, got %q", out)
	}
}

func TestDesktopControlLogoutUsesSessionID(t *testing.T) {
	stub := waylandStub()
	p := &linuxPlatformOps{exec: stub}

	if _, err := p.DesktopControl("logout_user", ""); err != nil {
		t.Fatalf("logout failed: %v", err)
	}
	if !stub.ran("loginctl terminate-session 3") {
		t.Fatalf("logout did not pass a session id; calls=%v", stub.calls)
	}
	// The old code called terminate-session with no argument and then pkill'd.
	for _, c := range stub.calls {
		if c == "loginctl terminate-session " || c == "loginctl terminate-session" {
			t.Fatalf("terminate-session called with no session id")
		}
	}
	if stub.ran("pkill") {
		t.Fatalf("fell back to pkill; calls=%v", stub.calls)
	}
}

func TestDesktopControlLogoutNamedUser(t *testing.T) {
	stub := waylandStub()
	p := &linuxPlatformOps{exec: stub}

	if _, err := p.DesktopControl("logout_user", "alice"); err != nil {
		t.Fatalf("logout failed: %v", err)
	}
	if !stub.ran("loginctl terminate-user alice") {
		t.Fatalf("did not terminate the named user; calls=%v", stub.calls)
	}
}

func TestDesktopControlNoGraphicalSessionReportsError(t *testing.T) {
	// A headless box: one tty session, nothing graphical.
	stub := &recordingExecutor{stubCommandExecutor: stubCommandExecutor{
		responses: map[string]string{
			"loginctl list-sessions --no-legend":                                           "7 1000 bob  pts/0\n",
			"loginctl show-session 7 --property=Type --property=Active --property=Display": "Type=tty\nActive=yes\nDisplay=\n",
		},
	}}
	p := &linuxPlatformOps{exec: stub}

	if _, err := p.DesktopControl("logout_user", ""); err == nil {
		t.Fatalf("expected an error when there is no graphical session")
	}
}

func TestDesktopControlDisplayOffPrefersX11Session(t *testing.T) {
	stub := &recordingExecutor{stubCommandExecutor: stubCommandExecutor{
		responses: map[string]string{
			"loginctl list-sessions --no-legend":                                           "2 1000 carol seat0 tty1\n",
			"loginctl show-session 2 --property=Type --property=Active --property=Display": "Type=x11\nActive=yes\nDisplay=:0\n",
		},
	}}
	p := &linuxPlatformOps{exec: stub}

	if _, err := p.DesktopControl("display_off", ""); err != nil {
		t.Fatalf("display_off failed: %v", err)
	}
	// xset must run as the session's own user, against that session's display.
	if !stub.ran("runuser -u carol -- env DISPLAY=:0 xset dpms force off") {
		t.Fatalf("did not run xset as the session user; calls=%v", stub.calls)
	}
}

func TestDesktopControlDisplayOffFallsBackOnWayland(t *testing.T) {
	stub := waylandStub()
	p := &linuxPlatformOps{exec: stub}

	out, err := p.DesktopControl("display_off", "")
	if err != nil {
		t.Fatalf("display_off failed: %v", err)
	}
	if stub.ran("xset") {
		t.Fatalf("ran xset against a Wayland session; calls=%v", stub.calls)
	}
	if !strings.Contains(string(out), "locked instead") {
		t.Fatalf("fallback should say what it did, got %q", out)
	}
}

func TestDesktopControlUnknownAction(t *testing.T) {
	p := &linuxPlatformOps{exec: &recordingExecutor{}}
	if _, err := p.DesktopControl("explode", ""); err == nil {
		t.Fatalf("expected an error for an unknown action")
	}
}
