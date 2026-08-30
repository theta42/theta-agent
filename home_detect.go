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
	mu               sync.RWMutex
	agentPublicIP    string
	homePublicIP     string // set by directory config push
	lanEndpoint      string // LAN-only endpoint pushed by the directory, if any
	siteName         string // site name pushed by the directory
	vpnActive        bool
	autoVPN          bool
	exits            []TrayExit // exits this device may choose (from the directory)
	currentExit      *int       // nil = local breakout
	homeSiteID       int        // this device's own site, from enrolment
	isHome           bool       // last answer from detectHome
	homeKnown        bool       // whether isHome has been computed even once
	organizationName string     // white-label name pushed by the directory
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

// SetMeshIdentity records what the directory says about this device: which
// site it belongs to, and which site (if any) it currently exits through.
//
// Both arrive on enrolment and on every config push, so the agent does not
// have to go and ask -- which matters because the answer is what decides
// whether the tunnel should be up, and a decision that needs a round trip is a
// decision that is sometimes made on stale information.
func SetMeshIdentity(homeSiteID int, exitSiteID *int) {
	homeState.mu.Lock()
	if homeSiteID > 0 {
		homeState.homeSiteID = homeSiteID
	}
	homeState.currentExit = exitSiteID
	homeState.mu.Unlock()
}

// SetHomeState records the last home/away answer so callers outside the
// monitor loop (a pushed config, the tray) can act on the same one rather
// than deriving their own.
func SetHomeState(isHome bool) {
	homeState.mu.Lock()
	homeState.isHome = isHome
	homeState.homeKnown = true
	homeState.mu.Unlock()
}

// HomeState returns the last answer and whether one has been computed yet.
func HomeState() (isHome, known bool) {
	homeState.mu.RLock()
	defer homeState.mu.RUnlock()
	return homeState.isHome, homeState.homeKnown
}

// remoteExitSelected reports whether this device is routed through a site
// other than its own.
//
// Selecting your OWN site as the exit means "egress where I normally would",
// which is what a device sitting at home is already doing -- so it is not a
// reason to hold a tunnel up. Selecting somebody else's site is: that is the
// geolocation case, and it is wanted at home as much as away.
func remoteExitSelected() bool {
	homeState.mu.RLock()
	defer homeState.mu.RUnlock()
	if homeState.currentExit == nil {
		return false
	}
	if homeState.homeSiteID > 0 {
		return *homeState.currentExit != homeState.homeSiteID
	}
	// No site identity yet: fall back to the exit list, which flags the
	// device's own site as local.
	for _, e := range homeState.exits {
		if e.SiteID == *homeState.currentExit {
			return !e.IsLocal
		}
	}
	// An exit we know nothing about is, by construction, not this device's own
	// site -- and a deliberate selection is better honoured than ignored.
	return true
}

// tunnelShouldBeUp is the whole policy, in one place.
//
//	away          -> up. The point of the mesh on a laptop: leave the house,
//	                 the tunnel comes up, traffic is carried by the site.
//	home + remote exit -> up. The user picked another site's egress on
//	                 purpose (geolocation); being at home does not undo that.
//	home + own site / no exit -> down. Nothing to gain from hairpinning your
//	                 own LAN through your own gateway.
func tunnelShouldBeUp(isHome bool) bool {
	return !isHome || remoteExitSelected()
}

// SetSiteName records the site name pushed by the directory.
func SetSiteName(name string) {
	homeState.mu.Lock()
	homeState.siteName = name
	homeState.mu.Unlock()
}

func siteName() string {
	homeState.mu.RLock()
	defer homeState.mu.RUnlock()
	if homeState.siteName != "" {
		return homeState.siteName
	}
	if currentCM != nil {
		cfg := currentCM.Get()
		if cfg != nil && cfg.Location != "" {
			return cfg.Location
		}
	}
	return "home"
}

// TriggerTrayStatusPush gathers current state and updates the tray status.
func TriggerTrayStatusPush() {
	homeState.mu.RLock()
	agentIP := homeState.agentPublicIP
	homeIP := homeState.homePublicIP
	vpn := homeState.vpnActive
	autoVPN := homeState.autoVPN
	isHome := homeState.isHome
	homeState.mu.RUnlock()

	UpdateTrayStatus(true, isHome, agentIP, homeIP, vpn, autoVPN, siteName())
}

// wantWireGuardUp answers "should the tunnel be running right now" for callers
// that are not the monitor loop -- chiefly a pushed peer config.
func wantWireGuardUp() bool {
	// A remote exit explicitly selected by the user means the tunnel should be running.
	if remoteExitSelected() {
		return true
	}
	// Auto-VPN off means the user drives the tunnel by hand. Refresh one that
	// is already up so a new exit takes effect, but never raise one they have
	// deliberately left down.
	if !AutoVPN() {
		return defaultPlatformOps.WireGuardState()
	}
	isHome, known := HomeState()
	if !known {
		// Nothing has been measured yet. Staying down is the recoverable
		// error: the monitor runs within the minute and will bring it up.
		return false
	}
	return tunnelShouldBeUp(isHome)
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

// SetOrganizationName records the white-label name pushed by the directory.
func SetOrganizationName(name string) {
	homeState.mu.Lock()
	homeState.organizationName = name
	homeState.mu.Unlock()
}

// organizationName returns the cached white-label name (empty if unset).
func organizationName() string {
	homeState.mu.RLock()
	defer homeState.mu.RUnlock()
	return homeState.organizationName
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
	SetHomeState(isHome)

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

// handleAutoVPN drives the tunnel towards the state tunnelShouldBeUp() asks
// for. It used to test home/away alone, which meant an exit chosen for
// geolocation was torn down the moment the device came home -- the one place
// the user had explicitly said what they wanted, and the only place it was
// ignored.
func handleAutoVPN(cfg *Config, isHome, vpn, autoVPN, connected bool) {
	if !autoVPN || !connected {
		return
	}
	now := time.Now()
	if now.Sub(lastAutoVPNChange) < 2*time.Minute {
		return
	}

	want := tunnelShouldBeUp(isHome)
	if want == vpn {
		return
	}

	if !want {
		log.Println("[home-detect] back home and no remote exit selected; disconnecting WireGuard (auto-vpn)")
		if err := defaultPlatformOps.DisconnectWireGuard(); err != nil {
			log.Printf("[home-detect] disconnect failed: %v", err)
		}
		lastAutoVPNChange = now
		return
	}

	if isHome {
		log.Println("[home-detect] remote exit selected; connecting WireGuard (auto-vpn)")
	} else {
		log.Println("[home-detect] away from home; connecting WireGuard (auto-vpn)")
	}
	if err := defaultPlatformOps.ConnectWireGuard(); err != nil {
		log.Printf("[home-detect] connect failed: %v", err)
	}
	lastAutoVPNChange = now
}
