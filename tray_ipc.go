package main

// IPC protocol between the root daemon (theta-agent) and the desktop tray
// (theta-agent-tray). Both processes communicate via a Unix domain socket at
// /run/theta/tray.sock (created by the daemon; the tray connects to it).
//
// Protocol: newline-delimited JSON. The daemon streams TrayStatus messages to
// any connected tray client. The tray sends TrayCommand messages to the daemon.

import (
	"encoding/json"
	"runtime"
)

// TraySocketPaths are the paths the daemon tries to bind, in order.
//
// Windows has no /run or /tmp. The daemon runs as the SYSTEM service while the
// tray runs as the logged-in user, so the socket lives in the shared data dir
// (%ProgramData%\Theta42, created by the installer with a Users-writable ACL)
// rather than a per-user temp dir — the two processes must agree on one path.
// Linux keeps the original /run/theta path with a /tmp fallback.
var TraySocketPaths = func() []string {
	if runtime.GOOS == "windows" {
		return []string{windowsTraySocketPath()}
	}
	return []string{"/run/theta/tray.sock", "/tmp/theta-tray.sock"}
}()

// TraySocket is the canonical socket path the tray dials. It matches the last
// entry in TraySocketPaths on each platform.
var TraySocket = func() string {
	if runtime.GOOS == "windows" {
		return windowsTraySocketPath()
	}
	return "/tmp/theta-tray.sock"
}()


// TrayColor represents the icon color state.
type TrayColor string

const (
	ColorRed    TrayColor = "red"    // not connected to directory
	ColorYellow TrayColor = "yellow" // connected, but not home
	ColorGreen  TrayColor = "green"  // connected, on home LAN (public IP matches)
	ColorBlue   TrayColor = "blue"   // connected + WireGuard tunnel active to home site
)

// TrayStatus is sent from the daemon to the tray on every state change.
type TrayStatus struct {
	Color          TrayColor `json:"color"`
	Connected      bool      `json:"connected"`       // directory WebSocket is up
	IsHome         bool      `json:"is_home"`         // public IP matches home site
	VPNActive      bool      `json:"vpn_active"`      // WireGuard tunnel is up
	AutoVPN        bool      `json:"auto_vpn"`        // auto-connect preference
	SiteName       string    `json:"site_name"`       // configured site name
	AgentPublicIP  string    `json:"agent_public_ip"` // this agent's detected public IP
	HomePublicIP   string    `json:"home_public_ip"`  // home site's public IP (from directory)
	StatusText     string    `json:"status_text"`     // one-line human description
}

// TrayCommand is sent from the tray to the daemon.
type TrayCommand struct {
	Command string `json:"command"` // "set_auto_vpn", "vpn_connect", "vpn_disconnect"
	Value   bool   `json:"value"`   // used by set_auto_vpn
}

func encodeTrayStatus(s TrayStatus) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func decodeTrayCommand(data []byte) (TrayCommand, error) {
	var cmd TrayCommand
	err := json.Unmarshal(data, &cmd)
	return cmd, err
}

func decodeTrayStatus(data []byte) (TrayStatus, error) {
	var s TrayStatus
	err := json.Unmarshal(data, &s)
	return s, err
}
