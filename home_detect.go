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
	vpnActive     bool
	autoVPN       bool
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

// SetVPNActive is called when WireGuard tunnel state changes.
func SetVPNActive(active bool) {
	homeState.mu.Lock()
	homeState.vpnActive = active
	homeState.mu.Unlock()
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
	vpn := homeState.vpnActive
	autoVPN := homeState.autoVPN
	homeState.mu.Unlock()

	connected := connectedFn()
	siteName := cfg.Location
	if siteName == "" {
		siteName = "home"
	}

	UpdateTrayStatus(connected, agentIP, homeIP, vpn, autoVPN, siteName, cfg.ServerURL)
}
