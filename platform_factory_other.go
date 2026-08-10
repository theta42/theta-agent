//go:build !windows

package main

// NewPlatformOps returns the Linux/POSIX implementation (systemctl, journalctl,
// bash). It is the fallback for any non-Windows host.
func NewPlatformOps(cfg *Config, exec Executor) PlatformOps {
	name := cfg.WireGuard.TunnelName
	if name == "" {
		name = "theta-mesh"
	}
	conf := cfg.WireGuard.Conf
	if conf == "" {
		conf = defaultWireGuardConfPath(name)
	}
	return &linuxPlatformOps{
		exec:       exec,
		tunnelName: name,
		confPath:   conf,
	}
}
