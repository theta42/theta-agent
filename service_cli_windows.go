//go:build windows

package main

// Service management CLI (theta-agent install-service / remove-service). The
// Inno installer also drives this rather than hand-rolling `sc create`.

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
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

	cfg := mgr.Config{
		// UpdateConfig passes these to ChangeServiceConfig verbatim -- unlike
		// CreateService there is no zero-value defaulting, and ServiceType 0
		// is not SERVICE_NO_CHANGE (that's 0xFFFFFFFF) but simply invalid
		// ("The parameter is incorrect"). Set everything explicitly.
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorIgnore,
		DisplayName:      "Theta Agent",
		Description:      "Theta42 unified endpoint management agent (telemetry, remote ops, LDAP logon, WireGuard mesh)",
		ServiceStartName: "LocalSystem",
	}

	if s, err := m.OpenService("theta-agent"); err == nil {
		// Upgrade path: the installer runs this on every install. The old
		// binary is still running (and holding its image locked) unless we
		// stop the service first; then refresh the config and start again so
		// an upgrade actually brings up the new version.
		defer s.Close()
		fmt.Println("[+] theta-agent service already exists -- updating and restarting it")
		stopWindowsService(s)
		// Rewrite ImagePath too: installs before v2.9.1 carried stray
		// positional arguments ("is auto", cargo-culted from the x/sys doc
		// example) that runAgent then misread as a config path, killing the
		// daemon on every start.
		cfg.BinaryPathName = syscall.EscapeArg(exe)
		if err := s.UpdateConfig(cfg); err != nil {
			logFatal("cannot update service configuration: %v", err)
		}
		if err := s.Start(); err != nil {
			logFatal("cannot start service: %v", err)
		}
		waitForServiceRunning(s)
		fmt.Printf("[+] Updated and restarted theta-agent service (%s)\n", filepath.Base(exe))
		return
	}

	s, err := m.CreateService("theta-agent", exe, cfg)
	if err != nil {
		logFatal("cannot create service: %v", err)
	}
	defer s.Close()

	// Start it immediately so the daemon binds the tray IPC socket and the
	// credential provider is live without waiting for a reboot.
	if err := s.Start(); err != nil {
		logFatal("cannot start service: %v", err)
	}
	waitForServiceRunning(s)
	fmt.Printf("[+] Registered and started theta-agent service (%s)\n", filepath.Base(exe))
}

// waitForServiceRunning waits briefly for SCM to report the service actually
// reached RUNNING and warns if it did not -- a daemon that exits during
// startup otherwise fails silently here (the tray just retries its socket
// forever), which cost us a whole release to diagnose.
func waitForServiceRunning(s *mgr.Service) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, err := s.Query()
		if err == nil && status.State == svc.Running {
			return
		}
		if err != nil || status.State == svc.Stopped || time.Now().After(deadline) {
			fmt.Println("[!] WARNING: theta-agent service did not reach RUNNING -- check %ProgramData%\\Theta42\\agent.log for the startup error")
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// stopWindowsService asks a running service to stop and waits (bounded) for
// SCM to report it stopped -- sc stop / s.Control are asynchronous, and the
// caller usually wants the exe image lock actually released.
func stopWindowsService(s *mgr.Service) {
	status, err := s.Query()
	if err != nil || status.State == svc.Stopped {
		return
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err = s.Query()
		if err != nil || status.State == svc.Stopped {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
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
