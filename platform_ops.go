package main

// PlatformOps abstracts the system operations the command dispatcher needs.
// Command dispatch, capability gating and Ed25519 verification are
// platform-neutral (websocket.go); the actual mechanics differ per OS:
//
//   - linuxPlatformOps (platform_linuxops.go) — systemctl, journalctl, bash, ...
//   - windowsPlatformOps (platform_windows.go) — sc.exe, powershell, the
//     theta-agent-helper for session-0 ops and staged self-update.
//
// defaultPlatformOps is pinned at startup (runAgent) and swappable in tests so
// command dispatch can be exercised identically on any host.

type PlatformOps interface {
	// Reboot restarts the host.
	Reboot() ([]byte, error)

	// Shutdown powers the host off.
	Shutdown() ([]byte, error)

	// FetchLogs returns the last `lines` log lines for a service.
	FetchLogs(service string, lines int) ([]byte, error)

	// ServiceControl runs an action (start/stop/restart/status/...) against a
	// Windows service. Actions that don't map are executed best-effort.
	ServiceControl(service, action string) ([]byte, error)

	// RunScript executes an operator-supplied script (arbitrary_bash).
	RunScript(script string) ([]byte, error)

	// DesktopControl runs a desktop-control subaction (lock/logout/display/sleep)
	// for a target user.
	DesktopControl(subAction, targetUser string) ([]byte, error)

	// ConfigureLDAP writes the pushed LDAP configuration. Linux configures
	// SSSD; Windows manages logon via OpenCredential instead and declines.
	ConfigureLDAP(configData string) error

	// ApplyUpdate downloads, verifies and stages a new binary. The swap is
	// platform-specific: Linux renames over the running binary, Windows writes
	// a `.new` next to it and hands the swap to theta-agent-helper (the running
	// exe is locked and the service must stop first).
	ApplyUpdate(downloadURL, checksum string) error

	// SelfRestart terminates the agent so a staged update takes effect. Linux
	// exits; the Windows service handler stops itself (the helper restarts it).
	SelfRestart()
}

// defaultPlatformOps is the ops implementation the command dispatcher uses.
// Pinned by runAgent after config load; tests override it directly.
var defaultPlatformOps = NewPlatformOps(&Config{}, &SystemExecutor{})
