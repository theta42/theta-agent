//go:build !windows

package main

// maybeRunAsService is a no-op on non-Windows hosts: the agent runs in the
// foreground under systemd / init and is driven by SIGTERM.
func maybeRunAsService() bool {
	return false
}
