package main

// Platform paths. Windows has no /etc, /run or /tmp, so the agent's
// filesystem touchpoints move under %ProgramData%\Theta42, which SYSTEM (the
// service) and authenticated users (the tray) can both reach.

import (
	"os"
	"path/filepath"
	"runtime"
)

// windowsDataDir returns %ProgramData%\Theta42.
func windowsDataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Theta42")
}

// defaultConfigPath returns the platform's agent.yml location.
func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsDataDir(), "agent.yml")
	}
	return "/etc/theta42/agent.yml"
}

// defaultLdapSocketPath returns the local LDAP byte-pump socket. Windows has no
// AF_UNIX in a stable location that both service and clients share, so it
// relies on the TCP loopback listener (127.0.0.1:389) that ldapTunnel.start
// falls back to.
func defaultLdapSocketPath() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/run/theta/ldap.sock"
}

// windowsTraySocketPath returns the tray IPC socket path. It lives in the
// shared data dir (not the per-user temp dir) because the daemon runs as the
// SYSTEM service while the tray runs as the logged-in user; the installer
// grants Users write access to this directory and its children.
func windowsTraySocketPath() string {
	return filepath.Join(windowsDataDir(), "tray.sock")
}
