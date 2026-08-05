package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type WSMessage struct {
	Type    string                 `json:"type"`
	Payload map[string]interface{} `json:"payload"`
}

// Application close codes the SSO uses to say "your enrollment is the problem"
// (PROTOCOL.md §1.1). All three mean retrying quickly is pointless.
const (
	closeUnauthorized = 4001 // token was never issued, or is unknown
	closeSuperseded   = 4002 // another connection took over this enrollment
	closeRevoked      = 4003 // enrollment revoked or deleted by an admin
	closeTokenRotated = 4004 // token rotated; agent.yml holds the old one
)

// How long to wait before retrying after the server rejects our credential.
// Short enough that a re-enrollment is picked up without a restart, long enough
// that a decommissioned agent is not a permanent load on the SSO.
const authRetryInterval = 5 * time.Minute

type MessageWriter interface {
	WriteMessage(messageType int, data []byte) error
}

// canonicalize produces the exact bytes the server signed (PROTOCOL.md §5):
// keys sorted alphabetically, no whitespace, `signature` omitted.
//
// encoding/json sorts map keys for us, but by default it also escapes <, > and
// & as <, > and & -- which Node's JSON.stringify on the server
// does not. Any payload containing those characters therefore hashed
// differently on each side and the signature failed. For arbitrary_bash that is
// most real scripts: `>` redirection and `&&` are everywhere. SetEscapeHTML
// (false) is what makes the two encoders agree.
//
// Encoder.Encode also appends a trailing newline, which must be trimmed or it
// is signed-over data the server never produced.
func canonicalize(payload map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func verifySignature(cfg *Config, msg WSMessage) bool {
	// Fail CLOSED. This used to return true when no public key was configured,
	// which meant an agent installed without a `public_key` would execute
	// reboot / configure_ldap / arbitrary_bash from anything that could reach
	// its socket, with no verification at all -- the exact commands the
	// signature exists to protect. An agent that cannot verify must not act.
	if cfg.PublicKey == "" {
		log.Println("Refusing high-risk command: no public_key configured in agent.yml")
		return false
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
	canonicalPayload, err := canonicalize(payloadCopy)
	if err != nil {
		log.Printf("Could not canonicalize payload for verification: %v", err)
		return false
	}

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
		u.RawQuery = "token=" + url.QueryEscape(cfg.AuthToken)

		// Never log u.String(): RawQuery carries the auth token, and agent logs
		// are routinely shipped around and pasted into issues.
		log.Printf("Connecting to %s%s", u.Host, u.Path)

		c, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {
			// The server now rejects tokens it did not issue. Retrying a bad
			// credential every 5s just floods the SSO and its audit log
			// forever, so back off hard and say plainly what is wrong.
			if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
				log.Printf("Server rejected our token (HTTP %d). Enroll this agent in the SSO Directory and put the issued token in agent.yml. Retrying in %s.", resp.StatusCode, authRetryInterval)
				time.Sleep(authRetryInterval)
				continue
			}
			log.Printf("Dial error: %v. Retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Println("Successfully connected to SSO Manager.")

		stopCh := make(chan struct{})

		// Start telemetry and discovery with stopCh lifecycle control
		StartTelemetryLoop(c, cm, exec, stopCh)

		// Heartbeat loop
		go func() {
			ticker := time.NewTicker(60 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopCh:
					return
				case <-ticker.C:
					hb := WSMessage{Type: "heartbeat", Payload: map[string]interface{}{"timestamp": time.Now().Format(time.RFC3339)}}
					payload, _ := json.Marshal(hb)
					if err := c.WriteMessage(websocket.TextMessage, payload); err != nil {
						return
					}
				}
			}
		}()

		// Set when the server closes us for an enrollment problem rather than a
		// transient fault, so the reconnect below can back off instead of
		// spinning on a credential that will not start working by itself.
		authRejected := false

		// Read loop
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				// The SSO accepts the upgrade and only then closes with an
				// application code, so an auth failure surfaces here rather
				// than at Dial.
				if websocket.IsCloseError(err, closeUnauthorized, closeRevoked, closeTokenRotated) {
					authRejected = true
					log.Printf("Server closed the connection: %v. This agent's token is not valid for that SSO — re-enroll it and update agent.yml.", err)
				} else {
					log.Println("WebSocket read error:", err)
				}
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
		close(stopCh)
		c.Close()

		if authRejected {
			log.Printf("Reconnecting in %s.", authRetryInterval)
			time.Sleep(authRetryInterval)
			continue
		}

		log.Println("WebSocket disconnected. Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

func handleCommand(cm *ConfigManager, msg WSMessage, c MessageWriter, exec Executor) {
	cfg := cm.Get()
	// Don't log the server's fire-and-forget heartbeat ack — it arrives every
	// 60s and is not a command to act on; logging it is pure per-minute noise.
	if msg.Type != "heartbeat_ack" {
		log.Printf("Received command: %s", msg.Type)
	}

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
		serviceName, _ := msg.Payload["service"].(string)
		if serviceName == "" {
			serviceName = "theta-agent"
		}

		if serviceName != "theta-agent" && !cfg.Capabilities.CanManageService(serviceName) {
			log.Printf("Fetch logs rejected for '%s': not in allowed service list", serviceName)
			sendResponse("error", "service log fetch rejected")
			return
		}

		linesCount := 100
		if l, ok := msg.Payload["lines"].(float64); ok && l > 0 {
			linesCount = int(l)
		}

		log.Printf("Fetching logs for service %s (%d lines)...", serviceName, linesCount)
		out, err := exec.Execute("journalctl", "-u", serviceName, "-n", fmt.Sprintf("%d", linesCount), "--no-pager")
		if err != nil {
			log.Printf("Log fetch failed: %v", err)
			sendResponse("error", "failed to fetch logs")
			return
		}
		resp := map[string]interface{}{
			"status":  "ok",
			"service": serviceName,
			"logs":    string(out),
		}
		respPayload, _ := json.Marshal(resp)
		c.WriteMessage(websocket.TextMessage, respPayload)
		return
	case "update_binary":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.ArbitraryBash {
			sendResponse("error", "update capability disabled")
			return
		}

		urlStr, _ := msg.Payload["url"].(string)
		checksum, _ := msg.Payload["sha256"].(string)
		if urlStr == "" || checksum == "" {
			sendResponse("error", "missing url or sha256 checksum")
			return
		}

		log.Printf("Updating binary from %s...", urlStr)
		if err := downloadAndUpdateBinary(urlStr, checksum); err != nil {
			log.Printf("Update failed: %v", err)
			sendResponse("error", fmt.Sprintf("update failed: %v", err))
			return
		}
		sendResponse("ok", "update applied successfully; restarting agent...")
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
	// heartbeat_ack is the server's acknowledgement of the agent's own periodic
	// heartbeat (the agent sends `heartbeat`, the server answers `heartbeat_ack`).
	// There is nothing to do with it -- it is not a command to run, and answering
	// an ack with an error response would inject spurious errors into the
	// command-response channel every minute. Silently ignore.
	case "heartbeat_ack":
		return
	default:
		log.Printf("Unknown command type: %s", msg.Type)
		sendResponse("error", "unknown command type")
	}
}

func downloadAndUpdateBinary(downloadURL string, expectedSHA256 string) error {
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("http fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status: %s", resp.Status)
	}

	tmpFile, err := os.CreateTemp("", "theta-agent-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	if _, err := io.Copy(writer, resp.Body); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to save binary: %w", err)
	}
	tmpFile.Close()

	actualSHA256 := fmt.Sprintf("%x", hasher.Sum(nil))
	if !strings.EqualFold(actualSHA256, strings.TrimSpace(expectedSHA256)) {
		return fmt.Errorf("sha256 mismatch: expected %s, got %s", expectedSHA256, actualSHA256)
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to resolve current binary path: %w", err)
	}

	resolvedPath, err := filepath.EvalSymlinks(selfPath)
	if err == nil {
		selfPath = resolvedPath
	}

	if err := os.Rename(tmpPath, selfPath); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	return nil
}
