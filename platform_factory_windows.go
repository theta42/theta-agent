//go:build windows

package main

// NewPlatformOps returns the Windows implementation.
func NewPlatformOps(cfg *Config, exec Executor) PlatformOps {
	name := cfg.WireGuard.TunnelName
	if name == "" {
		name = "theta-mesh"
	}
	conf := cfg.WireGuard.Conf
	if conf == "" {
		conf = defaultWireGuardConfPath(name)
	}
	return &windowsPlatformOps{
		exec:        exec,
		helperPath:  cfg.DesktopHelper,
		serviceName: cfg.ServiceName,
		tunnelName:  name,
		confPath:    conf,
		wgExe:       cfg.WireGuard.Executable,
	}
}
