package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	log.Println("Starting Theta Agent...")

	// Attempt to load configuration
	configPath := "/etc/theta/agent.yml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Error loading configuration from %s: %v", configPath, err)
	}

	log.Printf("Connecting to SSO Manager at %s", cfg.ServerURL)
	log.Printf("Loaded capabilities: Telemetry=%v, LDAP=%v, Reboot=%v, Bash=%v", 
		cfg.Capabilities.Telemetry, 
		cfg.Capabilities.ConfigureLDAP, 
		cfg.Capabilities.Reboot, 
		cfg.Capabilities.ArbitraryBash,
	)

	// WebSocket connection to SSO Manager
	go connectWebSocket(cfg)

	// Block until signal is received
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	fmt.Println("Shutting down Theta Agent...")
}
