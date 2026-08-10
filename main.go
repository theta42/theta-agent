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
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		configPath = os.Args[1]
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

	// Tray IPC server — desktop tray connects here for status updates.
	go globalTrayServer.Start()

	// WebSocket connection to Theta Directory
	go connectWebSocket(cm, exec)

	// Home detection + tray status push (polls public IP every 60s).
	go StartHomeMonitor(cfg, func() bool { return wsConnected.Load() })

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
}
