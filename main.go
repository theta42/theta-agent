package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
)

// wsConnected is flipped atomically by connectWebSocket as the connection
// comes up and drops, so StartHomeMonitor can read it without a mutex.
var wsConnected atomic.Bool

func main() {
	if len(os.Args) > 1 && handleCLI(os.Args[1:]) {
		return
	}

	log.Println("Starting Theta Agent...")

	// Attempt to load configuration
	configPath := "/etc/theta42/agent.yml"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		configPath = os.Args[1]
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		log.Fatalf("Error loading configuration from %s: %v", configPath, err)
	}
	cfg := cm.Get()

	log.Printf("Connecting to SSO Manager at %s", cfg.ServerURL)
	log.Printf("Loaded capabilities: Telemetry=%v, LDAP=%v, Reboot=%v, Bash=%v",
		cfg.Capabilities.Telemetry,
		cfg.Capabilities.ConfigureLDAP,
		cfg.Capabilities.Reboot,
		cfg.Capabilities.ArbitraryBash,
	)

	// Initialize system executor
	exec := &SystemExecutor{}

	// Tray IPC server — desktop tray connects here for status updates.
	go globalTrayServer.Start()

	// WebSocket connection to SSO Manager
	go connectWebSocket(cm, exec)

	// Home detection + tray status push (polls public IP every 60s).
	go StartHomeMonitor(cfg, func() bool { return wsConnected.Load() })

	// Block until signal is received
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	fmt.Println("Shutting down Theta Agent...")
}
