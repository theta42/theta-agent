//go:build windows

package main

import (
	"fmt"
	"log"
)

// swapUpdatedBinary installs a freshly downloaded binary at binPath. The
// running theta-agent service keeps the exe image locked, so the file cannot
// be renamed over directly: stage it as <binPath>.new and hand the swap to the
// detached session helper, which waits for the service to stop, swaps, and
// restarts it (mirrors windowsPlatformOps.ApplyUpdate). Returns true when the
// caller must not restart anything itself.
func swapUpdatedBinary(cfg *Config, tmpPath, binPath string) (bool, error) {
	newPath := binPath + ".new"
	if err := moveFile(tmpPath, newPath); err != nil {
		return false, fmt.Errorf("stage new binary: %w", err)
	}

	helper := ""
	service := "theta-agent"
	if cfg != nil {
		helper = cfg.DesktopHelper
		if cfg.ServiceName != "" {
			service = cfg.ServiceName
		}
	}
	if helper == "" {
		return false, fmt.Errorf(
			"desktop_helper is not configured; stop the %s service, replace %s with %s, then start it again",
			service, binPath, newPath)
	}

	if err := spawnDetached(helper, "update", newPath, binPath, service); err != nil {
		return false, fmt.Errorf("launch updater helper: %w", err)
	}
	log.Printf("[+] Update staged (%s -> %s); the helper will restart the %s service with the new binary.", newPath, binPath, service)
	return true, nil
}
