package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

type MessageWriter interface {
	WriteMessage(messageType int, data []byte) error
}

func verifySignature(cfg *Config, msg WSMessage) bool {
	if cfg.PublicKey == "" {
		log.Println("No public key configured; skipping signature verification")
		return true
	}

	sigB64, ok := msg.Payload["signature"].(string)
	if !ok {
		log.Println("High-risk command missing signature")
		return false
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		log.Printf("Invalid base64 signature: %v", err)
		return false
	}

	// Create canonical payload for verification (remove signature key)
	payloadCopy := make(map[string]interface{})
	for k, v := range msg.Payload {
		if k != "signature" {
			payloadCopy[k] = v
		}
	}
	canonicalPayload, _ := json.Marshal(payloadCopy)

	pubKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		log.Printf("Invalid public key in config: %v", err)
		return false
	}

	return ed25519.Verify(pubKeyBytes, canonicalPayload, sig)
}

func connectWebSocket(cm *ConfigManager, exec Executor) {
	for {
		cfg := cm.Get()
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

		// Start telemetry and discovery
		StartTelemetryLoop(c, cfg, exec)

		// Heartbeat loop
		go func() {
			ticker := time.NewTicker(60 * time.Second)
			for range ticker.C {
				hb := WSMessage{Type: "heartbeat", Payload: map[string]interface{}{"timestamp": time.Now().Format(time.RFC3339)}}
				payload, _ := json.Marshal(hb)
				if err := c.WriteMessage(websocket.TextMessage, payload); err != nil {
					return
				}
			}
		}()

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

			handleCommand(cm, msg, c, exec)
		}

		// Cleanup on disconnect
		c.Close()

		log.Println("WebSocket disconnected. Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

func handleCommand(cm *ConfigManager, msg WSMessage, c MessageWriter, exec Executor) {
	cfg := cm.Get()
	log.Printf("Received command: %s", msg.Type)

	sendResponse := func(status string, message string) {
		resp, _ := json.Marshal(map[string]string{"status": status, "message": message})
		c.WriteMessage(websocket.TextMessage, resp)
	}

	switch msg.Type {
	case "reload_config":
		if err := cm.Reload(); err != nil {
			log.Printf("Reload failed: %v", err)
			sendResponse("error", "failed to reload config")
		} else {
			log.Println("Configuration reloaded successfully.")
			sendResponse("ok", "configuration reloaded")
		}
	case "fetch_logs":
		out, err := exec.Execute("journalctl", "-u", "theta-agent", "-n", "100")
		if err != nil {
			log.Printf("Log fetch failed: %v", err)
			sendResponse("error", "failed to fetch logs")
			return
		}
		resp := map[string]string{
			"status": "ok",
			"logs":   string(out),
		}
		respPayload, _ := json.Marshal(resp)
		c.WriteMessage(websocket.TextMessage, respPayload)
		return
	case "update_binary":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.ArbitraryBash { // Use Bash as a proxy for "dangerous update" capability
			sendResponse("error", "update capability disabled")
			return
		}

		url, _ := msg.Payload["url"].(string)
		checksum, _ := msg.Payload["sha256"].(string)
		if url == "" || checksum == "" {
			sendResponse("error", "missing url or checksum")
			return
		}

		log.Printf("Updating binary from %s...", url)
		// implementation of download and replace
		// ... (simplified for now, using a shell command via executor for brevity in this turn)
		script := fmt.Sprintf("curl -fsSL %s -o /tmp/theta-agent.new && sha256sum -c <(echo '%s  /tmp/theta-agent.new') && mv /tmp/theta-agent.new $(readlink -f /proc/self/exe)", url, checksum)
		if _, err := exec.Execute("bash", "-c", script); err != nil {
			log.Printf("Update failed: %v", err)
			sendResponse("error", "update failed")
			return
		}
		sendResponse("ok", "update applied. restarting agent...")
		os.Exit(0)
	case "config":
		log.Printf("Received config payload: %v", msg.Payload)
		sendResponse("ok", "Configuration received")
	case "reboot":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.Reboot {
			log.Println("Reboot rejected: capability disabled in agent.yml")
			sendResponse("error", "reboot capability disabled")
			return
		}
		log.Printf("Executing reboot...")
		if _, err := exec.Execute("reboot"); err != nil {
			log.Printf("Reboot failed: %v", err)
			sendResponse("error", "reboot failed")
			return
		}
		sendResponse("ok", "system rebooting")
	case "service_restart":
		serviceName, ok := msg.Payload["service"].(string)
		if !ok || !cfg.Capabilities.CanManageService(serviceName) {
			log.Printf("Service restart rejected for '%s': not in allowed service list", serviceName)
			sendResponse("error", "service restart rejected")
			return
		}
		log.Printf("Restarting service %s...", serviceName)
		if _, err := exec.Execute("systemctl", "restart", serviceName); err != nil {
			log.Printf("Service restart failed: %v", err)
			sendResponse("error", "restart failed")
			return
		}
		sendResponse("ok", "service restarted")
	case "configure_ldap":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.ConfigureLDAP {
			log.Println("LDAP config rejected: capability disabled in agent.yml")
			sendResponse("error", "LDAP config disabled")
			return
		}

		configData, ok := msg.Payload["config"].(string)
		if !ok {
			log.Println("LDAP config payload missing or not a string")
			sendResponse("error", "invalid config payload")
			return
		}

		log.Println("Pushing updated SSSD configuration...")
		if err := exec.WriteFile("/etc/sssd/sssd.conf", []byte(configData), 0600); err != nil {
			log.Printf("Failed to write SSSD config: %v", err)
			sendResponse("error", "failed to write config")
			return
		}

		log.Println("Restarting SSSD service...")
		if _, err := exec.Execute("systemctl", "restart", "sssd"); err != nil {
			log.Printf("SSSD restart failed: %v", err)
			sendResponse("error", "failed to restart sssd")
			return
		}
		sendResponse("ok", "LDAP configuration updated")
	case "arbitrary_bash":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.ArbitraryBash {
			log.Println("Bash execution rejected: capability disabled in agent.yml")
			sendResponse("error", "bash execution disabled")
			return
		}

		script, ok := msg.Payload["script"].(string)
		if !ok {
			log.Println("Bash payload missing or not a string")
			sendResponse("error", "invalid script payload")
			return
		}

		log.Printf("Executing remote script: %s", script)
		out, err := exec.Execute("bash", "-c", script)
		if err != nil {
			log.Printf("Script execution failed: %v", err)
			sendResponse("error", fmt.Sprintf("execution failed: %v", err))
			return
		}

		resp := map[string]string{
			"status": "ok",
			"output": string(out),
		}
		respPayload, _ := json.Marshal(resp)
		c.WriteMessage(websocket.TextMessage, respPayload)
		return
	default:
		log.Printf("Unknown command type: %s", msg.Type)
		sendResponse("error", "unknown command type")
	}
}
