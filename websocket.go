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

	// G-1 signature envelope: the signature covers {type, payload}, so bind the
	// command type into the canonical bytes. A signature for one command type
	// then cannot be replayed as another (H7 — type-portable replay).
	payloadCopy := make(map[string]interface{})
	payloadCopy["type"] = msg.Type
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
			log.Printf("Invalid ServerURL: %v. Retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}
		u.Path = "/api/agent/ws"
		// Our own token once enrolled, else the join key. The hostname lets the
		// server name a self-enrolling host something meaningful instead of a
		// generated placeholder.
		q := url.Values{}
		if hn, err := os.Hostname(); err == nil && hn != "" {
			q.Set("hostname", hn)
		}
		// Only on the join-key path: `site` tells the directory which site to
		// file this machine's new host row under, and it has no meaning once
		// we are enrolled and the host row exists. Sending it always would
		// invite a future server to act on it for an established agent, which
		// is the roaming case local_discovery.go deliberately does not build.
		if cfg.AuthToken == "" {
			if site := resolveSiteHint(cfg); site != "" {
				q.Set("site", site)
			}
		}
		u.RawQuery = q.Encode()

		// Prefer the Authorization header over the query string: a token in a
		// URL is logged by proxies, appears in server access logs, and sits in
		// browser history. The header keeps it out of those surfaces. The
		// server accepts both (api_agent.js falls back to ?token=), so this is
		// a pure improvement with no compatibility cost.
		//
		// Never log u.String() below: even with the header set, the credential
		// may still be present in the query during the join-key flow, and
		// agent logs are routinely shipped around and pasted into issues.
		var headers http.Header
		if cred := cfg.Credential(); cred != "" {
			headers = http.Header{}
			headers.Set("Authorization", cred)
		}

		if cfg.Credential() == "" {
			log.Printf("No auth_token or join_key in %s -- nothing to authenticate with. Retrying in %s.", cm.configPath, authRetryInterval)
			time.Sleep(authRetryInterval)
			continue
		}

		// Never log u.String(): RawQuery carries the auth token, and agent logs
		// are routinely shipped around and pasted into issues.
		log.Printf("Connecting to %s%s", u.Host, u.Path)

		c, resp, err := websocket.DefaultDialer.Dial(u.String(), headers)
		if err != nil {
			// The server now rejects tokens it did not issue. Retrying a bad
			// credential every 5s just floods the SSO and its audit log
			// forever, so back off hard and say plainly what is wrong.
			if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
				log.Printf("Server rejected our token (HTTP %d). Enroll this agent in the Theta Directory and put the issued token in agent.yml. Retrying in %s.", resp.StatusCode, authRetryInterval)
				time.Sleep(authRetryInterval)
				continue
			}
			log.Printf("Dial error: %v. Retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Println("Successfully connected to Theta Directory.")
		wsConnected.Store(true)

		// Register this host's WireGuard public key. Done per-connect rather
		// than once at boot: the key is stable, the server side is idempotent
		// by agent id, and doing it here repairs a device row that was deleted
		// at the far end or was never created because the agent predates mesh
		// enrolment. Runs in the background so a slow or unreachable REST
		// endpoint cannot delay the WSS session.
		//
		// It gets the ConfigManager, not the snapshot above: a self-enrolling
		// host dials with its join key and is issued its real auth token over
		// this very connection a moment later, and the REST endpoint only
		// accepts the latter. See ensureMeshIdentity.
		go ensureMeshIdentity(cm)

		stopCh := make(chan struct{})

		// All outbound writes go through the safe writer: gorilla allows only one
		// concurrent writer, and telemetry, heartbeat, the LDAP tunnel and command
		// responses all write to the same socket.
		sw := &safeWriter{c: c}
		currentWriterMu.Lock()
		currentWriter = sw
		currentWriterMu.Unlock()

		// Local LDAP byte-pump tunnel (DESIGN.md §4). The agent never parses LDAP;
		// it forwards raw bytes to the SSO and writes the responses back.
		tunnel := newLdapTunnel(func(msg WSMessage) error {
			return sendTunnelMessage(sw, msg)
		})
		if cfg.Capabilities.LdapTunnel || cfg.Capabilities.ConfigureLDAP {
			socketPath := cfg.LdapSocket
			if socketPath == "" {
				socketPath = defaultLdapSocketPath()
			}
			go tunnel.start(socketPath, stopCh)
		}

		// Start telemetry and discovery with stopCh lifecycle control
		StartTelemetryLoop(sw, cm, exec, stopCh)

		// WebSocket keepalive: a ping/pong frame every 60s with a 90s read
		// deadline. Without this, a silent peer (NAT drop, cable pull) leaves
		// the read loop blocked forever and the agent never reconnects. The
		// pong handler resets the read deadline on every pong; if the deadline
		// elapses the connection closes and the read loop exits, triggering
		// reconnect.
		const readLimit = 1 << 20 // 1 MiB — reject any frame larger than this
		c.SetReadLimit(readLimit)
		c.SetPongHandler(func(string) error {
			return c.SetReadDeadline(time.Now().Add(90 * time.Second))
		})
		if err := c.SetReadDeadline(time.Now().Add(90 * time.Second)); err != nil {
			log.Printf("Failed to set initial read deadline: %v", err)
			c.Close()
			continue
		}

		// Ping ticker sends a ping every 60s; the server's pong resets the
		// read deadline via the pong handler above.
		pingTicker := time.NewTicker(60 * time.Second)
		defer pingTicker.Stop()

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
					if err := sw.WriteMessage(websocket.TextMessage, payload); err != nil {
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
				if websocket.IsCloseError(err, closeUnauthorized, closeRevoked, closeTokenRotated, closeSuperseded) {
					authRejected = true
					log.Printf("Server closed the connection: %v. This agent's token is not valid for that Theta Directory — re-enroll it and update agent.yml.", err)
				} else {
					log.Println("WebSocket read error:", err)
				}
				break // break read loop, reconnect
			}
			// Reset the read deadline on every successful message; the pong
			// handler does the same for pong frames.
			if err := c.SetReadDeadline(time.Now().Add(90 * time.Second)); err != nil {
				log.Printf("Failed to reset read deadline: %v", err)
				break
			}

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("Error unmarshaling message: %v", err)
			continue
		}

		handleCommand(cm, msg, sw, exec, tunnel)
	}

	// Cleanup on disconnect
	wsConnected.Store(false)
	currentWriterMu.Lock()
	currentWriter = nil
	currentWriterMu.Unlock()
	close(stopCh)
	c.Close()

	if authRejected {
		log.Printf("Reconnecting in %s.", authRetryInterval)
		time.Sleep(authRetryInterval)
		continue
	}

	log.Println("WebSocket disconnected. Reconnecting in 5 seconds...")
	// A local-discovery apply/revert (hosts override + route change) wants
	// the new resolution path picked up right away rather than after the
	// full backoff. discoveryChangedCh is drained here only; a change
	// while still connected takes effect on the next natural reconnect.
	select {
	case <-discoveryChangedCh:
		log.Println("Local-discovery routing changed; reconnecting immediately.")
	case <-time.After(5 * time.Second):
	}
}

}

func handleCommand(cm *ConfigManager, msg WSMessage, c MessageWriter, exec Executor, tunnel *ldapTunnel) {
	cfg := cm.Get()

	// debugf logs full payloads (scripts, config data) only when
	// verbose_logging is enabled in agent.yml. These payloads can hold
	// credentials or sensitive config, so the default (off) logs only a
	// one-line summary.
	debugf := func(format string, a ...interface{}) {
		if cfg.VerboseLogging {
			log.Printf("[verbose]"+format, a...)
		}
	}

	// Don't log the server's fire-and-forget heartbeat ack — it arrives every
	// 60s and is not a command to act on; logging it is pure per-minute noise.
	// The LDAP tunnel is high-frequency (every chunk of a bind/search), so it is
	// not logged either.
	if msg.Type != "heartbeat_ack" && msg.Type != "ldap_tunnel" {
		log.Printf("Received command: %s", msg.Type)
	}

	sendResponse := func(status string, message string) {
		resp, _ := json.Marshal(map[string]string{"status": status, "message": message})
		c.WriteMessage(websocket.TextMessage, resp)
	}
	switch msg.Type {
	case "ldap_tunnel":
		// SSO→agent direction of the LDAP byte pump: write the response bytes to
		// the matching local socket.
		if tunnel != nil {
			tunnel.handleMessage(msg.Payload)
		}
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
			if linesCount > 2000 {
				linesCount = 2000
			}
		}

		log.Printf("Fetching logs for service %s (%d lines)...", serviceName, linesCount)
		out, err := defaultPlatformOps.FetchLogs(serviceName, linesCount)
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
		// Self-update is its own signed high-risk operation, independent of
		// arbitrary_bash. It used to be gated behind ArbitraryBash, which meant
		// a host with `arbitrary_bash: false` (the security-conscious default)
		// could never be self-updated from the directory even though the update
		// is verified by the Ed25519 signature above. Dropping that coupling
		// makes update_binary available to any host that holds the directory's
		// public key, matching the README's separation of the two operations.

		urlStr, _ := msg.Payload["url"].(string)
		checksum, _ := msg.Payload["sha256"].(string)
		if urlStr == "" || checksum == "" {
			sendResponse("error", "missing url or sha256 checksum")
			return
		}

		log.Printf("Updating binary from %s...", urlStr)
		if err := defaultPlatformOps.ApplyUpdate(urlStr, checksum); err != nil {
			log.Printf("Update failed: %v", err)
			sendResponse("error", fmt.Sprintf("update failed: %v", err))
			return
		}
		sendResponse("ok", "update applied successfully; restarting agent...")
		defaultPlatformOps.SelfRestart()
	case "config":
		// A config frame carrying credentials means the server accepted our
		// join key and enrolled this host.
		enrolled, _ := msg.Payload["enrolled"].(bool)
		if enrolled {
			token, _ := msg.Payload["auth_token"].(string)
			pubKey, _ := msg.Payload["public_key"].(string)
			if err := cm.PersistEnrollment(token, pubKey); err != nil {
				log.Printf("Enrolled, but could not persist credentials: %v", err)
				log.Printf("This agent will re-enroll on every reconnect until %s is writable.", cm.configPath)
			} else {
				log.Printf("Enrolled with Theta Directory. Credentials written to %s; the join key is no longer needed.", cm.configPath)
			}
		}
		// Home-detection inputs pushed by the directory. site_public_ip is the
		// weaker of the two (CGNAT and multi-WAN sites both break the
		// comparison); site_lan_endpoint is a host:port that only resolves or
		// routes on the home LAN, so reaching it settles the question.
		if sitePublicIP, ok := msg.Payload["site_public_ip"].(string); ok && sitePublicIP != "" {
			SetHomePublicIP(sitePublicIP)
			log.Printf("[home-detect] home site public IP: %s", sitePublicIP)
		}
		if lanEndpoint, ok := msg.Payload["site_lan_endpoint"].(string); ok && lanEndpoint != "" {
			SetHomeLanEndpoint(lanEndpoint)
			log.Printf("[home-detect] home LAN endpoint: %s", lanEndpoint)
		}
		// White-label branding pushed by the directory.
		if orgName, ok := msg.Payload["organization_name"].(string); ok && orgName != "" {
			SetOrganizationName(orgName)
			log.Printf("[branding] organization name: %s", orgName)
		}
		debugf("config payload (full): %v", msg.Payload)
		log.Printf("Received config payload: %d fields", len(msg.Payload))
		if enrolled {
			sendResponse("ok", "enrollment stored")
		} else {
			sendResponse("ok", "Configuration received")
		}
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
		if _, err := defaultPlatformOps.Reboot(); err != nil {
			log.Printf("Reboot failed: %v", err)
			sendResponse("error", "reboot failed")
			return
		}
		sendResponse("ok", "system rebooting")
	case "shutdown":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.Reboot {
			log.Println("Shutdown rejected: capability disabled in agent.yml")
			sendResponse("error", "shutdown capability disabled")
			return
		}
		log.Printf("Executing shutdown...")
		sendResponse("ok", "system shutting down")
		if _, err := defaultPlatformOps.Shutdown(); err != nil {
			log.Printf("Shutdown failed: %v", err)
		}
		return
	case "desktop_control", "lock_session", "logout_user", "display_off", "sleep_host":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		subAction, _ := msg.Payload["subAction"].(string)
		if subAction == "" {
			subAction = msg.Type
		}
		targetUser, _ := msg.Payload["user"].(string)
		log.Printf("Executing desktop control action '%s' for user '%s'...", subAction, targetUser)

		switch subAction {
		case "lock_session", "lock", "logout_user", "logout", "display_off", "sleep_host", "sleep":
		default:
			sendResponse("error", fmt.Sprintf("unknown desktop action '%s'", subAction))
			return
		}

		out, err := defaultPlatformOps.DesktopControl(subAction, targetUser)

		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		respMap := map[string]interface{}{
			"status":    "ok",
			"subAction": subAction,
			"output":    string(out),
			"error":     errMsg,
		}
		respPayload, _ := json.Marshal(respMap)
		c.WriteMessage(websocket.TextMessage, respPayload)
		return
	case "systemd_action":
		serviceName, _ := msg.Payload["service"].(string)
		action, _ := msg.Payload["action"].(string)
		// The Directory records what KIND of service each resource is; a
		// docker container sent to `systemctl restart` targets a unit that does
		// not exist. Absent (older Directory) means systemd, which is what
		// every pre-subtype resource is.
		subtype, _ := msg.Payload["subtype"].(string)
		if serviceName == "" {
			sendResponse("error", "service name required")
			return
		}
		if action == "" {
			action = "status"
		}
		if action != "status" && !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		log.Printf("Executing %s %s (%s)...", action, serviceName, subtypeOrSystemd(subtype))
		out, err := controlService(defaultPlatformOps, subtype, serviceName, action)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		respMap := map[string]interface{}{
			"status":  "ok",
			"service": serviceName,
			"subtype": subtypeOrSystemd(subtype),
			"action":  action,
			"output":  string(out),
			"error":   errMsg,
		}
		respPayload, _ := json.Marshal(respMap)
		c.WriteMessage(websocket.TextMessage, respPayload)
		return
	case "service_restart":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		serviceName, ok := msg.Payload["service"].(string)
		if !ok || !cfg.Capabilities.CanManageService(serviceName) {
			log.Printf("Service restart rejected for '%s': not in allowed service list", serviceName)
			sendResponse("error", "service restart rejected")
			return
		}
		log.Printf("Restarting service %s...", serviceName)
		if _, err := defaultPlatformOps.ServiceControl(serviceName, "restart"); err != nil {
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

		debugf("configure_ldap payload (full): %s", configData)
		log.Printf("Applying LDAP configuration: %d bytes", len(configData))
		if err := defaultPlatformOps.ConfigureLDAP(configData); err != nil {
			log.Printf("LDAP configuration failed: %v", err)
			sendResponse("error", err.Error())
			return
		}

		sendResponse("ok", "LDAP configuration updated")
	case "render_secrets":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.Secrets {
			log.Println("Secrets render rejected: capability disabled in agent.yml")
			sendResponse("error", "secrets capability disabled")
			return
		}
		log.Println("Rendering secret templates...")
		if err := renderSecrets(cfg, exec); err != nil {
			log.Printf("Secrets render failed: %v", err)
			sendResponse("error", fmt.Sprintf("secrets render failed: %v", err))
			return
		}
		sendResponse("ok", "secrets rendered")
	case "iam_apply":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.IAM {
			log.Println("IAM apply rejected: capability disabled in agent.yml")
			sendResponse("error", "iam capability disabled")
			return
		}
		payload, err := parseIAMPayload(msg.Payload)
		if err != nil {
			log.Printf("IAM apply: bad payload: %v", err)
			sendResponse("error", "invalid IAM payload")
			return
		}
		log.Printf("Applying IAM revision %d for node %s...", payload.Revision, payload.NodeID)
		if err := defaultPlatformOps.ApplyIAM(payload); err != nil {
			log.Printf("IAM apply failed: %v", err)
			sendResponse("error", fmt.Sprintf("iam apply failed: %v", err))
			return
		}
		sendResponse("ok", "iam applied")
	case "register_service":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.ServiceRegistration {
			log.Println("Service registration rejected: capability disabled in agent.yml")
			sendResponse("error", "service registration capability disabled")
			return
		}
		name, _ := msg.Payload["service"].(string)
		subtype, _ := msg.Payload["subtype"].(string)
		if name == "" {
			sendResponse("error", "missing service name")
			return
		}
		if subtype == "" {
			subtype = "systemd"
		}
		log.Printf("Registering %s service %s...", subtype, name)
		if err := cm.PersistService(name, subtype, false); err != nil {
			log.Printf("Service registration failed: %v", err)
			sendResponse("error", err.Error())
			return
		}
		sendResponse("ok", "service registered")
	case "unregister_service":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.ServiceRegistration {
			log.Println("Service unregistration rejected: capability disabled in agent.yml")
			sendResponse("error", "service registration capability disabled")
			return
		}
		name, _ := msg.Payload["service"].(string)
		if name == "" {
			sendResponse("error", "missing service name")
			return
		}
		log.Printf("Unregistering service %s...", name)
		if err := cm.PersistService(name, "systemd", true); err != nil {
			log.Printf("Service unregistration failed: %v", err)
			sendResponse("error", err.Error())
			return
		}
		sendResponse("ok", "service unregistered")
	case "wireguard_apply":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.WireGuardEnabled() {
			log.Println("WireGuard apply rejected: capability disabled in agent.yml")
			sendResponse("error", "wireguard capability disabled")
			return
		}
		conf, _ := msg.Payload["config"].(string)
		if conf == "" {
			sendResponse("error", "missing wireguard config")
			return
		}
		// The Directory renders an agent-owned device's config with a
		// placeholder where the private key goes -- it has no private key to
		// put there, by design. Substitute the one this host generated at
		// enrolment; without this the placeholder reaches wg-quick verbatim and
		// the interface cannot come up.
		conf, cerr := fillPrivateKeyFromHost(conf)
		if cerr != nil {
			log.Printf("WireGuard apply failed: %v", cerr)
			sendResponse("error", cerr.Error())
			return
		}
		// The directory says which site this device belongs to and which one
		// it exits through; both decide whether the tunnel should be running.
		// Sent with the config so the agent never has to ask -- see
		// SetMeshIdentity.
		SetMeshIdentity(intFromPayload(msg.Payload, "siteId"), optIntFromPayload(msg.Payload, "exitSiteId"))

		// Receiving a config and running it are two different decisions.
		// Applying unconditionally meant a push to a host sitting at home
		// brought the tunnel up and the next home-monitor tick tore it back
		// down -- a flap on every exit change, and the reason a config could
		// not be delivered ahead of the moment it is needed.
		if err := defaultPlatformOps.PersistWireGuard(conf); err != nil {
			log.Printf("WireGuard apply failed: %v", err)
			sendResponse("error", fmt.Sprintf("wireguard apply failed: %v", err))
			return
		}
		if !wantWireGuardUp() {
			log.Printf("[mesh] peer config stored; leaving the tunnel down (at home, no remote exit selected)")
			SetVPNActive(defaultPlatformOps.WireGuardState())
			sendResponse("ok", "wireguard config stored")
			return
		}
		log.Printf("Applying WireGuard peer config...")
		if err := defaultPlatformOps.ApplyWireGuard(conf); err != nil {
			log.Printf("WireGuard apply failed: %v", err)
			sendResponse("error", fmt.Sprintf("wireguard apply failed: %v", err))
			return
		}
		SetVPNActive(true)
		sendResponse("ok", "wireguard applied")
	case "wireguard_remove":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.WireGuardEnabled() {
			log.Println("WireGuard remove rejected: capability disabled in agent.yml")
			sendResponse("error", "wireguard capability disabled")
			return
		}
		log.Printf("Removing WireGuard tunnel...")
		if err := defaultPlatformOps.RemoveWireGuard(); err != nil {
			log.Printf("WireGuard remove failed: %v", err)
			sendResponse("error", fmt.Sprintf("wireguard remove failed: %v", err))
			return
		}
		SetVPNActive(false)
		sendResponse("ok", "wireguard removed")
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

		debugf("Executing remote script (full): %s", script)
		log.Printf("Executing remote script: %d bytes", len(script))
		out, err := defaultPlatformOps.RunScript(script)
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
	case "zpool_scrub":
		if !verifySignature(cfg, msg) {
			sendResponse("error", "signature verification failed")
			return
		}
		if !cfg.Capabilities.Storage {
			log.Println("zpool_scrub rejected: storage capability disabled in agent.yml")
			sendResponse("error", "storage capability disabled")
			return
		}
		pool, _ := msg.Payload["pool"].(string)
		if pool == "" {
			sendResponse("error", "missing pool name")
			return
		}
		if err := validateServiceName(pool); err != nil {
			sendResponse("error", fmt.Sprintf("invalid pool name: %v", err))
			return
		}
		log.Printf("Starting zpool scrub on %s...", pool)
		out, err := defaultPlatformOps.ZpoolScrub(pool)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
			log.Printf("zpool scrub failed: %v", err)
			sendResponse("error", fmt.Sprintf("zpool scrub failed: %v", err))
			return
		}
		resp := map[string]string{
			"status": "ok",
			"output": string(out),
		}
		if errMsg != "" {
			resp["error"] = errMsg
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

// pushServiceFrame sends a register_service / unregister_service frame over
// the daemon's own WebSocket connection. Called from the tray IPC server when
// `theta-agent register/unregister` asks the daemon to push the frame for it.
//
// The CLI used to open its own one-shot WebSocket to the directory. The
// directory allows one connection per agent, so the new connection superseded
// the daemon's (4002) and the daemon's immediate reconnect superseded the
// CLI's in turn — the frame was lost and registration reported failure while
// actually succeeding via the telemetry fallback. Pushing over the daemon's
// stable connection removes the race entirely.
func pushServiceFrame(msgType, service, subtype string) error {
	currentWriterMu.RLock()
	w := currentWriter
	currentWriterMu.RUnlock()
	if w == nil {
		return fmt.Errorf("no live WebSocket connection to the directory")
	}
	payload := map[string]interface{}{
		"service": service,
	}
	if subtype != "" {
		payload["subtype"] = subtype
	}
	msg := WSMessage{Type: msgType, Payload: payload}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return w.WriteMessage(websocket.TextMessage, data)
}

// downloadBinary fetches the new binary, verifies its SHA-256, and returns the
// path of a temp file holding it. The temp file is created in dir — the
// destination binary's directory — so the final rename stays on one
// filesystem and remains atomic (a temp file in /tmp, often a tmpfs, made the
// install rename fail with EXDEV on Linux). The platform's ApplyUpdate decides
// how to install it (Linux renames over the running exe; Windows stages a
// `.new` and swaps via the helper once the service stops).
func downloadBinary(downloadURL string, expectedSHA256 string, dir string) (string, error) {
	// Dedicated client with a bounded timeout so a slow or unresponsive server
	// cannot hang the update forever. The cap on CopyN below bounds the body.
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("http fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected http status: %s", resp.Status)
	}

	tmpFile, err := os.CreateTemp(dir, "theta-agent-update-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// The caller OWNS the returned temp file and is expected to move it into
	// place (ApplyUpdate renames it over the running binary, or stages it as
	// <self>.new for the helper swap). It must NOT be removed here: a deferred
	// os.Remove once deleted the verified download before ApplyUpdate could
	// install it, silently breaking self-update on every platform.

	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	// Cap the download at 256 MiB — a theta-agent binary is a few tens of MiB.
	// Without a cap, a malicious or misbehaving server returning an unbounded
	// body could fill local disk before the SHA check ever runs.
	const maxBinarySize = 256 << 20
	written, err := io.CopyN(writer, resp.Body, maxBinarySize)
	if err != nil && err != io.EOF {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to save binary: %w", err)
	}
	if written == maxBinarySize {
		// We hit the cap; the body was larger than allowed.
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("binary exceeds maximum allowed size (%d bytes)", maxBinarySize)
	}
	tmpFile.Close()

	actualSHA256 := fmt.Sprintf("%x", hasher.Sum(nil))
	if !strings.EqualFold(actualSHA256, strings.TrimSpace(expectedSHA256)) {
		os.Remove(tmpPath)
		return "", fmt.Errorf("sha256 mismatch: expected %s, got %s", expectedSHA256, actualSHA256)
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to set executable permissions: %w", err)
	}

	return tmpPath, nil
}
