package main

import (
	"encoding/json"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type WSMessage struct {
	Type    string                 `json:"type"`
	Payload map[string]interface{} `json:"payload"`
}

func connectWebSocket(cfg *Config) {
	for {
		// Ensure protocol is ws/wss
		serverURL := strings.Replace(cfg.ServerURL, "http://", "ws://", 1)
		serverURL = strings.Replace(serverURL, "https://", "wss://", 1)

		u, err := url.Parse(serverURL)
		if err != nil {
			log.Fatalf("Invalid ServerURL: %v", err)
		}
		u.Path = "/api/agent/ws"
		u.RawQuery = "token=" + cfg.AuthToken

		log.Printf("Connecting to %s", u.String())

		c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {
			log.Printf("Dial error: %v. Retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Println("Successfully connected to SSO Manager.")

		// Start telemetry if enabled
		var telemetryTicker *time.Ticker
		var telemetryDone chan bool
		if cfg.Capabilities.Telemetry {
			telemetryTicker, telemetryDone = startTelemetry(c, cfg)
		}

		// Read loop
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("WebSocket read error:", err)
				break // break read loop, reconnect
			}

			var msg WSMessage
			if err := json.Unmarshal(message, &msg); err != nil {
				log.Printf("Error unmarshaling message: %v", err)
				continue
			}

			handleCommand(cfg, msg, c)
		}

		// Cleanup on disconnect
		c.Close()
		if telemetryTicker != nil {
			telemetryTicker.Stop()
			telemetryDone <- true
		}

		log.Println("WebSocket disconnected. Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

func handleCommand(cfg *Config, msg WSMessage, c *websocket.Conn) {
	log.Printf("Received command: %s", msg.Type)

	switch msg.Type {
	case "config":
		log.Printf("Received config payload: %v", msg.Payload)
	case "reboot":
		if !cfg.Capabilities.Reboot {
			log.Println("Reboot rejected: capability disabled in agent.yml")
			return
		}
		log.Println("Reboot capability enabled. (Simulation: rebooting system...)")
	case "service_restart":
		serviceName, ok := msg.Payload["service"].(string)
		if !ok || !cfg.Capabilities.CanManageService(serviceName) {
			log.Printf("Service restart rejected for '%s': not in allowed service list", serviceName)
			return
		}
		log.Printf("Restarting service %s...", serviceName)
	default:
		log.Printf("Unknown command type: %s", msg.Type)
	}
}

func startTelemetry(c *websocket.Conn, cfg *Config) (*time.Ticker, chan bool) {
	ticker := time.Ticker{C: nil} // placeholder logic
	done := make(chan bool)
	log.Println("Telemetry loop started (placeholder).")
	return &ticker, done
}
