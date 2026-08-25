package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// failingExecutor is a host where nothing runs -- which is how
// linuxPlatformOps.WireGuardState() learns there is no interface.
type failingExecutor struct{}

func (failingExecutor) Execute(string, ...string) ([]byte, error) {
	return nil, errors.New("no such device")
}
func (failingExecutor) WriteFile(string, []byte, os.FileMode) error { return nil }
func (failingExecutor) ReadFile(string) ([]byte, error)             { return nil, errors.New("nope") }

// resetTunnelPolicyState clears the package-level state these tests set, so
// one case cannot decide the next one's answer.
func resetTunnelPolicyState(t *testing.T) {
	t.Helper()
	restore := func() {
		homeState.mu.Lock()
		homeState.currentExit = nil
		homeState.homeSiteID = 0
		homeState.exits = nil
		homeState.isHome = false
		homeState.homeKnown = false
		homeState.autoVPN = false
		homeState.mu.Unlock()
	}
	restore()
	t.Cleanup(restore)
}

func intPtr(v int) *int { return &v }

// The policy, stated once: away means up; a remote exit means up wherever you
// are; home with your own site (or nothing) selected means down.
func TestTunnelShouldBeUp(t *testing.T) {
	cases := []struct {
		name       string
		isHome     bool
		homeSiteID int
		exit       *int
		want       bool
	}{
		{"away, no exit -- the whole point of auto-vpn", false, 1, nil, true},
		{"away, own site as exit", false, 1, intPtr(1), true},
		{"away, remote exit", false, 1, intPtr(2), true},
		{"home, no exit", true, 1, nil, false},
		// The regression this encodes: coming home used to tear down an exit
		// the user had deliberately chosen for geolocation.
		{"home, remote exit -- geolocation", true, 1, intPtr(2), true},
		{"home, own site as exit is not an exit", true, 1, intPtr(1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetTunnelPolicyState(t)
			SetMeshIdentity(tc.homeSiteID, tc.exit)
			if got := tunnelShouldBeUp(tc.isHome); got != tc.want {
				t.Errorf("tunnelShouldBeUp(isHome=%v) with site %d exit %v = %v, want %v",
					tc.isHome, tc.homeSiteID, tc.exit, got, tc.want)
			}
		})
	}
}

// Before the site id arrives from enrolment the only thing to go on is the
// exit list, which flags the device's own site.
func TestRemoteExitSelectedFallsBackToTheExitList(t *testing.T) {
	resetTunnelPolicyState(t)
	SetMeshExits([]TrayExit{{SiteID: 1, IsLocal: true}, {SiteID: 2, IsLocal: false}}, nil)

	SetMeshIdentity(0, intPtr(1))
	if remoteExitSelected() {
		t.Error("site 1 is flagged local; it is not a remote exit")
	}
	SetMeshIdentity(0, intPtr(2))
	if !remoteExitSelected() {
		t.Error("site 2 is not local; it is a remote exit")
	}
	// An id in neither list is still a deliberate selection.
	SetMeshIdentity(0, intPtr(7))
	if !remoteExitSelected() {
		t.Error("an unknown exit id should be honoured, not ignored")
	}
}

func TestWantWireGuardUpBeforeAnythingIsMeasured(t *testing.T) {
	resetTunnelPolicyState(t)
	SetAutoVPN(true)
	// homeKnown is false: nothing has been measured. Staying down is the
	// recoverable answer -- the monitor runs within the minute.
	if wantWireGuardUp() {
		t.Error("raised the tunnel before home/away had been determined even once")
	}
	SetHomeState(false)
	if !wantWireGuardUp() {
		t.Error("away and auto-vpn on: the tunnel should be wanted")
	}
}

// Auto-VPN off means the user drives the tunnel. A push must refresh a live
// one and must not raise one they left down.
func TestWantWireGuardUpWithAutoVPNOff(t *testing.T) {
	resetTunnelPolicyState(t)
	SetAutoVPN(false)
	SetHomeState(false) // away: auto-vpn WOULD want it up

	rec := &argvRecorder{}
	prev := defaultPlatformOps
	defer func() { defaultPlatformOps = prev }()

	// `ip link show` failing is how linuxPlatformOps reports "no interface".
	defaultPlatformOps = &linuxPlatformOps{exec: &failingExecutor{}, tunnelName: "theta-mesh"}
	if wantWireGuardUp() {
		t.Error("raised a tunnel the user had deliberately left down")
	}
	defaultPlatformOps = &linuxPlatformOps{exec: rec, tunnelName: "theta-mesh"}
	if !wantWireGuardUp() {
		t.Error("a live tunnel should be refreshed so a new exit takes effect")
	}
}

// A pushed config must always land on disk. Whether it is RUN is a separate
// decision -- applying unconditionally meant a push to a host sitting at home
// brought the tunnel up and the next monitor tick tore it back down.
func TestWireGuardApplyActivationDependsOnState(t *testing.T) {
	cases := []struct {
		name       string
		isHome     bool
		exit       *int
		wantUp     bool
		wantStatus string
	}{
		{"at home, no exit: stored only", true, nil, false, "ok"},
		{"at home, remote exit: raised", true, intPtr(2), true, "ok"},
		{"away: raised", false, nil, true, "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetTunnelPolicyState(t)
			withLookPath(t, "wg", "wg-quick")
			SetAutoVPN(true)
			SetHomeState(tc.isHome)

			cm := &ConfigManager{current: &Config{
				PublicKey:    testPubKeyB64(),
				Capabilities: Capabilities{WireGuard: boolPtr(true)},
			}}
			mockExec := &MockExecutor{}
			conf := filepath.Join(t.TempDir(), "theta-mesh.conf")
			prev := defaultPlatformOps
			defaultPlatformOps = &linuxPlatformOps{exec: mockExec, tunnelName: "theta-mesh", confPath: conf}
			defer func() { defaultPlatformOps = prev }()

			payload := map[string]interface{}{
				"config": "[Interface]\nAddress = 10.1.128.2/32\n",
				"siteId": float64(1),
			}
			if tc.exit != nil {
				payload["exitSiteId"] = float64(*tc.exit)
			} else {
				payload["exitSiteId"] = nil
			}
			mockConn := &MockConn{}
			handleCommand(cm, WSMessage{Type: "wireguard_apply", Payload: sign(t, payload)}, mockConn, mockExec, nil)

			if len(mockConn.Messages) != 1 {
				t.Fatalf("expected 1 response, got %d", len(mockConn.Messages))
			}
			var resp map[string]string
			if err := json.Unmarshal(mockConn.Messages[0], &resp); err != nil {
				t.Fatal(err)
			}
			if resp["status"] != tc.wantStatus {
				t.Errorf("status = %q, want %q (%q)", resp["status"], tc.wantStatus, resp["message"])
			}

			// The config lands on disk either way. That is what makes it
			// possible to deliver it at enrolment, ahead of the moment it is
			// needed.
			body, err := os.ReadFile(conf)
			if err != nil {
				t.Fatalf("config was not persisted: %v", err)
			}
			if !strings.Contains(string(body), "10.1.128.2/32") {
				t.Errorf("persisted config is %q", body)
			}

			raised := false
			for _, cmd := range mockExec.ExecutedCommands {
				if len(cmd) >= 2 && cmd[0] == "wg-quick" && cmd[1] == "up" {
					raised = true
				}
			}
			if raised != tc.wantUp {
				t.Errorf("wg-quick up ran = %v, want %v (commands: %v)", raised, tc.wantUp, mockExec.ExecutedCommands)
			}
		})
	}
}
