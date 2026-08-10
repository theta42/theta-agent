//go:build windows

package main

// NewPlatformOps returns the Windows implementation.
func NewPlatformOps(cfg *Config, exec Executor) PlatformOps {
	return &windowsPlatformOps{
		exec:        exec,
		helperPath:  cfg.DesktopHelper,
		serviceName: cfg.ServiceName,
	}
}
