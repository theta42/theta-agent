package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

// wsConnected is flipped atomically by connectWebSocket as the connection
// comes up and drops, so StartHomeMonitor can read it without a mutex.
var wsConnected atomic.Bool

// agentStopCh closes once the agent should exit: a SIGINT/SIGTERM in the
// foreground, or the SCM stop request when running as a Windows service. Both
// runAgent (foreground) and the service handler wait on it.
var (
	agentStopOnce sync.Once
	agentStopCh   = make(chan struct{})
)

// currentCM lets the tray IPC server persist preferences (auto_vpn) and reset
// enrollment into the live config file. Set once in runAgent.
var currentCM *ConfigManager

// currentWriter is the safe writer for the live WebSocket connection, set by
// connectWebSocket on connect and cleared on disconnect. The tray IPC server
// uses it to push register_service/unregister_service frames over the daemon's
// own connection (the CLI must not open a competing one -- it would supersede
// the daemon's and lose the frame). Guarded by currentWriterMu.
var (
	currentWriterMu sync.RWMutex
	currentWriter   MessageWriter
)

// stopAgent signals the running agent to shut down. Idempotent.
func stopAgent() {
	agentStopOnce.Do(func() { close(agentStopCh) })
}

func main() {
	if len(os.Args) > 1 && handleCLI(os.Args[1:]) {
		return
	}

	// Windows: when installed as a service the SCM starts us and svc.Run takes
	// over the process lifecycle. Foreground (or any other OS) falls through to
	// runAgent, which blocks until a signal arrives.
	if maybeRunAsService() {
		return
	}

	runAgent()
}

// runAgent runs the agent daemon until stopAgent is called.
func runAgent() {
	log.Println("Starting Theta Agent...")

	// Attempt to load configuration
	configPath := defaultConfigPath()
	// An explicit positional argument only overrides the default when it is
	// actually a file -- installs before v2.9.1 had ImagePath arguments
	// ("is auto") that were misread as a config path here and killed the
	// daemon on every service start.
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		if _, err := os.Stat(os.Args[1]); err == nil {
			configPath = os.Args[1]
		}
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		log.Fatalf("Error loading configuration from %s: %v", configPath, err)
	}
	cfg := cm.Get()

	log.Printf("Connecting to Theta Directory at %s", cfg.ServerURL)
	log.Printf("Loaded capabilities: Telemetry=%v, LDAP=%v, Reboot=%v, Bash=%v",
		cfg.Capabilities.Telemetry,
		cfg.Capabilities.ConfigureLDAP,
		cfg.Capabilities.Reboot,
		cfg.Capabilities.ArbitraryBash,
	)

	// Initialize system executor and pin the platform ops the command
	// dispatcher runs behind.
	exec := &SystemExecutor{}
	defaultPlatformOps = NewPlatformOps(cfg, exec)
	currentCM = cm

	// Seed the auto-VPN preference from disk; the tray checkbox updates it.
	SetAutoVPN(cfg.AutoVPN)

	// Say up front when the mesh cannot possibly work. Without this the only
	// symptom is one exec error, minutes or days later, at the moment auto-VPN
	// first fires -- see wg_tools.go.
	if cfg.Capabilities.WireGuardEnabled() {
		if err := checkWireGuardTools(); err != nil {
			log.Printf("[mesh] WARNING: this host cannot bring up the mesh tunnel: %v", err)
		}
	}

	// Tray IPC server — desktop tray connects here for status updates.
	go globalTrayServer.Start()

	// WebSocket connection to Theta Directory
	go connectWebSocket(cm, exec)

	// Home detection + tray status push (polls public IP every 60s).
	go StartHomeMonitor(cfg, func() bool { return wsConnected.Load() })

	// mDNS local-discovery (MULTI_SITE_SPEC.md Appendix B) -- always on: a
	// local announcement is only acted on when it fronts our own server_url.
	go StartLocalDiscovery(cm)

	// Foreground: exit on SIGINT/SIGTERM. A Windows service ignores these and
	// is driven by its own handler.
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs
		stopAgent()
	}()

	<-agentStopCh

	fmt.Println("Shutting down Theta Agent...")

	// Clean up WireGuard mesh interface if active so the host does not retain
	// stale routes or interfaces when the agent service is stopped.
	if defaultPlatformOps != nil && defaultPlatformOps.WireGuardState() {
		log.Println("[mesh] Tearing down WireGuard interface on shutdown...")
		if err := defaultPlatformOps.RemoveWireGuard(); err != nil {
			log.Printf("[mesh] Error tearing down WireGuard on shutdown: %v", err)
		}
	}
}
