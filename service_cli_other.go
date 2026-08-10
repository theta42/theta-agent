//go:build !windows

package main

// handleServiceCommand is a no-op outside Windows: the agent is managed by
// systemd/init there.
func handleServiceCommand(args []string) {}
