package main

// Home detection: compares this agent's current public IP with the home
// site's public IP as reported by the directory.
//
// "Home" is site-relative: each theta-suite deployment has a site name and a
// public-facing IP. When this agent's egress IP matches, the user is on that
// site's LAN (or behind its NAT). The directory reports each site's public IP
// through its telemetry data; we get it on the WebSocket config push.

import (
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

var homeState struct {
	mu            sync.RWMutex
	agentPublicIP string
	homePublicIP  string // set by directory config push
	lanEndpoint   string // LAN-only endpoint pushed by the directory, if any
	vpnActive     bool
	autoVPN       bool
	exits         []TrayExit // exits this device may choose (from the directory)
	currentExit   *int       // nil = local breakout
}

// publicIPProviders are tried in order until one succeeds.
var publicIPProviders = []string{
	"https://api4.my-ip.io/ip",
	"https://ipv4.icanhazip.com",
	"https://api.ipify.org",
}

// fetchPublicIP tries each provider and returns the first clean response.
func fetchPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, url := range publicIPProviders {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if ip != "" && !strings.Contains(ip, "<") { // skip HTML error pages
			return ip
		}
	}
	return ""
}

// SetHomePublicIP is called when the directory pushes its site's public IP.
func SetHomePublicIP(ip string) {
	homeState.mu.Lock()
	homeState.homePublicIP = ip
	homeState.mu.Unlock()
}

// SetHomeLanEndpoint records a host:port that only resolves or routes on the
// home LAN. Reaching it is the strongest available "I am home" signal.
func SetHomeLanEndpoint(ep string) {
	homeState.mu.Lock()
	homeState.lanEndpoint = ep
	homeState.mu.Unlock()
}

// SetMeshExits records the exit choices and the current selection, so the tray
// can render the picker without talking to the directory itself.
func SetMeshExits(exits []TrayExit, current *int) {
	homeState.mu.Lock()
	homeState.exits = exits
	homeState.currentExit = current
	homeState.mu.Unlock()
}

// MeshExits returns the cached exit choices and current selection.
func MeshExits() ([]TrayExit, *int) {
	homeState.mu.RLock()
	defer homeState.mu.RUnlock()
	return homeState.exits, homeState.currentExit
}

// SetVPNActive is called when WireGuard tunnel state changes.
func SetVPNActive(active bool) {
	homeState.mu.Lock()
	homeState.vpnActive = active
	homeState.mu.Unlock()
}

// SetAutoVPN records the auto-connect preference (initialized from agent.yml,
// updated by the tray checkbox).
func SetAutoVPN(v bool) {
	homeState.mu.Lock()
	homeState.autoVPN = v
	homeState.mu.Unlock()
}

// AutoVPN returns the current auto-connect preference.
func AutoVPN() bool {
	homeState.mu.RLock()
	defer homeState.mu.RUnlock()
	return homeState.autoVPN
}

// StartHomeMonitor periodically refreshes the agent's public IP and pushes
// updated tray status. Call as a goroutine from main().
func StartHomeMonitor(cfg *Config, connectedFn func() bool) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Run immediately on start.
	checkAndPush(cfg, connectedFn)

	for range ticker.C {
		checkAndPush(cfg, connectedFn)
	}
}

func checkAndPush(cfg *Config, connectedFn func() bool) {
	// An air-gapped host cannot reach the public-IP providers; when
	// public_ip_detect is false we skip the network calls entirely and report
	// no public IP rather than flap the home/away state (DESIGN-WINDOWS.md §10).
	var ip string
	if cfg.DetectPublicIP() {
		ip = fetchPublicIP()
	}
	if ip == "" {
		log.Println("[home-detect] could not determine public IP")
	}

	homeState.mu.Lock()
	homeState.agentPublicIP = ip
	agentIP := homeState.agentPublicIP
	homeIP := homeState.homePublicIP
	lanEP := homeState.lanEndpoint
	vpn := homeState.vpnActive
	autoVPN := homeState.autoVPN
	homeState.mu.Unlock()

	connected := connectedFn()
	siteName := cfg.Location
	if siteName == "" {
		siteName = "home"
	}

	// Computed once, here, and passed on. UpdateTrayStatus used to derive
	// "am I home" a second time from its own copy of the rule, so the tray icon
	// and the auto-VPN decision could disagree -- and both carried the same
	// `|| homePublicIP == ""` clause that pinned every agent to "home".
	isHome := detectHome(cfg, agentIP, homeIP, lanEP, connected)

	// WireGuard state + auto-VPN (DESIGN-WINDOWS.md §5). The tunnel can be
	// driven by the SSO (wireguard_apply/remove) or by the tray; polling keeps
	// the tray icon blue and lets auto-VPN react to home/away changes.
	if cfg.Capabilities.WireGuardEnabled() {
		vpn = defaultPlatformOps.WireGuardState()
		SetVPNActive(vpn)
		handleAutoVPN(cfg, isHome, vpn, autoVPN, connected)
	}

	UpdateTrayStatus(connected, isHome, agentIP, homeIP, vpn, autoVPN, siteName)
}

// lastAutoVPNChange gates auto-VPN so the home monitor (60s tick) does not
// hammer connect/disconnect on every poll.
var lastAutoVPNChange time.Time

// handleAutoVPN connects the tunnel when away from home and auto-connect is on,
// and drops it again once back on the home LAN.
func handleAutoVPN(cfg *Config, isHome, vpn, autoVPN, connected bool) {
	if !autoVPN || !connected {
		return
	}
	now := time.Now()
	if now.Sub(lastAutoVPNChange) < 2*time.Minute {
		return
	}

	if isHome && vpn {
		log.Println("[home-detect] back home; disconnecting WireGuard (auto-vpn)")
		if err := defaultPlatformOps.DisconnectWireGuard(); err != nil {
			log.Printf("[home-detect] disconnect failed: %v", err)
		}
		lastAutoVPNChange = now
		return
	}
	if !isHome && !vpn {
		log.Println("[home-detect] away from home; connecting WireGuard (auto-vpn)")
		if err := defaultPlatformOps.ConnectWireGuard(); err != nil {
			log.Printf("[home-detect] connect failed: %v", err)
		}
		lastAutoVPNChange = now
	}
}
