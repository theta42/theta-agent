package main

import (
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

// mDNS local-discovery (AGENT_LOCAL_DISCOVERY_SPEC.md): when a
// theta-gateway/theta-proxy on the local network segment announces itself
// as fronting this agent's own server hostname, skip the relay/WAN path and
// talk to it directly. Opt-in via Config.PreferLocalDirectory.
//
// HARD RULE (non-negotiable): this changes WHERE we connect (DNS
// resolution via /etc/hosts), never WHETHER we trust what answers. Nothing
// here touches TLS/certificate validation -- the agent's normal TLS client
// code path is completely untouched, so a spoofed rogue mDNS announcement
// just produces a TLS handshake failure against the real hostname's cert,
// not a silent MITM. Do not "fix" a discovery-related connection failure by
// loosening cert checks; that would defeat the entire point of this rule.

const mdnsServiceName = "_theta-suite._tcp"
const mdnsPollInterval = 30 * time.Second
const mdnsLookupTimeout = 3 * time.Second

// StartLocalDiscovery runs until the process exits. No-op (logs once, then
// returns) if the feature isn't enabled or the target host can't be
// determined -- callers just `go StartLocalDiscovery(cm)` unconditionally.
func StartLocalDiscovery(cm *ConfigManager) {
	cfg := cm.Get()
	if !cfg.PreferLocalDirectory {
		return
	}
	targetHost := hostFromURL(cfg.ServerURL)
	if targetHost == "" {
		log.Printf("[local-discovery] could not parse a hostname out of server_url %q -- disabled", cfg.ServerURL)
		return
	}

	log.Printf("[local-discovery] enabled, watching for a local announcement fronting %s", targetHost)
	currentlyOverridden := false
	lastIP := ""

	for {
		ip := findLocalAnnouncement(targetHost)
		switch {
		case ip != "" && !currentlyOverridden:
			if err := applyHostsOverride(map[string]string{targetHost: ip}); err != nil {
				log.Printf("[local-discovery] found %s locally at %s but failed to apply hosts override: %v", targetHost, ip, err)
			} else {
				// Pin the packet path too: the hosts override only fixes name
				// resolution, the route table decides where the packets go.
				// If the WireGuard mesh tunnel is up with AllowedIPs covering
				// this LAN subnet, it would swallow the direct connection.
				if err := applyLocalRoute(ip); err != nil {
					log.Printf("[local-discovery] found %s locally at %s but failed to pin a direct host route (a WireGuard tunnel may override it): %v", targetHost, ip, err)
				}
				log.Printf("[local-discovery] %s announced locally at %s -- routing directly, skipping the relay/WAN path", targetHost, ip)
				lastIP = ip
				currentlyOverridden = true
				notifyDiscoveryChange()
			}
		case ip == "" && currentlyOverridden:
			if err := applyHostsOverride(map[string]string{}); err != nil {
				log.Printf("[local-discovery] lost local announcement for %s but failed to clear hosts override: %v", targetHost, err)
			} else {
				if lastIP != "" {
					removeLocalRoute(lastIP)
				}
				log.Printf("[local-discovery] %s no longer announced locally -- reverting to normal resolution", targetHost)
				currentlyOverridden = false
				lastIP = ""
				notifyDiscoveryChange()
			}
		}
		time.Sleep(mdnsPollInterval)
	}
}

// discoveryChangedCh is signaled (non-blocking) whenever a local-discovery
// apply/revert changes name resolution or routing, so the WebSocket loop can
// reconnect promptly and pick up the new path instead of waiting out its
// reconnect backoff.
var discoveryChangedCh = make(chan struct{}, 1)

func notifyDiscoveryChange() {
	select {
	case discoveryChangedCh <- struct{}{}:
	default:
	}
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return u.Hostname()
}

// findLocalAnnouncement browses for _theta-suite._tcp on the local segment
// and returns the announcing host's IP if its TXT "hosts" field lists
// targetHost, or "" if nothing matching is currently visible. mDNS is
// inherently link-local (multicast doesn't cross routers/VLANs), so "found
// vs not found" naturally tracks "on this LAN vs not" with no separate
// network-detection logic needed.
func findLocalAnnouncement(targetHost string) string {
	entriesCh := make(chan *mdns.ServiceEntry, 8)
	done := make(chan struct{})
	var found string

	go func() {
		for entry := range entriesCh {
			if entryAnnouncesHost(entry, targetHost) && found == "" {
				if entry.AddrV4 != nil {
					found = entry.AddrV4.String()
				} else if entry.AddrV6 != nil {
					found = entry.AddrV6.String()
				}
			}
		}
		close(done)
	}()

	// NOT mdns.Lookup() -- its DefaultParams() requests both IPv4 and IPv6,
	// and the underlying client sends the v4 query, THEN the v6 query, and
	// returns whatever error the v6 send produced -- aborting the entire
	// Query() synchronously if IPv6 isn't available, even though the v4
	// query it already sent may have already gotten (or will get) a valid
	// response. Confirmed with a packet capture: the v4 query and its
	// response both went out/came back fine, but Query() still returned
	// "network is unreachable" (from the v6 send) before the response-
	// listening loop ever started, so the entry was silently discarded.
	// IPv6 multicast isn't guaranteed present on every host this runs on
	// (many servers/containers are v4-only) -- disable it explicitly rather
	// than depend on IPv6 being configured for IPv4 discovery to work at all.
	params := mdns.DefaultParams(mdnsServiceName)
	params.Entries = entriesCh
	params.Timeout = mdnsLookupTimeout
	params.DisableIPv6 = true

	err := mdns.Query(params)
	close(entriesCh)
	<-done
	if err != nil {
		// Transient lookup errors (e.g. no multicast-capable interface at
		// the moment) are expected on some networks -- treat as "not found
		// right now", not a fatal condition.
		return ""
	}
	return found
}

func entryAnnouncesHost(entry *mdns.ServiceEntry, targetHost string) bool {
	for _, field := range entry.InfoFields {
		// TXT format: "hosts=sso.example.com,proxy.example.com"
		if !strings.HasPrefix(field, "hosts=") {
			continue
		}
		hosts := strings.Split(strings.TrimPrefix(field, "hosts="), ",")
		for _, h := range hosts {
			if strings.TrimSpace(h) == targetHost {
				return true
			}
		}
	}
	return false
}
