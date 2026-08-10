//go:build !windows

package main

// NewPlatformOps returns the Linux/POSIX implementation (systemctl, journalctl,
// bash). It is the fallback for any non-Windows host.
func NewPlatformOps(cfg *Config, exec Executor) PlatformOps {
	return &linuxPlatformOps{exec: exec}
}
