//go:build windows

package main

// Service management CLI (theta-agent install-service / remove-service). The
// Inno installer also drives this rather than hand-rolling `sc create`.

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc/mgr"
)

func handleServiceCommand(args []string) {
	action := "install"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "install":
		installService()
	case "remove":
		removeService()
	default:
		fmt.Fprintf(os.Stderr, "usage: theta-agent %s [install|remove]\n", action)
		os.Exit(1)
	}
}

func installService() {
	exe, err := os.Executable()
	if err != nil {
		logFatal("cannot resolve agent path: %v", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		logFatal("cannot connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService("theta-agent")
	if err == nil {
		s.Close()
		fmt.Println("[+] theta-agent service already exists")
		return
	}

	cfg := mgr.Config{
		DisplayName:      "Theta Agent",
		Description:      "Theta42 unified endpoint management agent (telemetry, remote ops, LDAP logon, WireGuard mesh)",
		ServiceStartName: "LocalSystem",
		StartType:        mgr.StartAutomatic,
	}
	s, err = m.CreateService("theta-agent", exe, cfg, "is", "auto")
	if err != nil {
		logFatal("cannot create service: %v", err)
	}
	defer s.Close()

	// Start it immediately so the daemon binds the tray IPC socket and the
	// credential provider is live without waiting for a reboot.
	if err := s.Start(); err != nil {
		logFatal("cannot start service: %v", err)
	}
	fmt.Printf("[+] Registered and started theta-agent service (%s)\n", filepath.Base(exe))
}

func removeService() {
	m, err := mgr.Connect()
	if err != nil {
		logFatal("cannot connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService("theta-agent")
	if err != nil {
		fmt.Println("[!] theta-agent service not found")
		return
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		logFatal("cannot delete service: %v", err)
	}
	fmt.Println("[+] Removed theta-agent service")
}

func logFatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[!] "+format+"\n", args...)
	os.Exit(1)
}
