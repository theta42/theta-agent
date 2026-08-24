package main

import (
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

// mDNS local-discovery (AGENT_LOCAL_DISCOVERY_SPEC.md): when a
// theta-gateway/theta-proxy on the local network segment announces itself
// as fronting this agent's own server hostname, skip the relay/WAN path and
// talk to it directly. Always on: a local announcement is only ever acted on
// when it fronts this agent's own server_url host, so an absent announcement
// changes nothing about the agent's behavior.
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
// returns) if the target host can't be determined -- callers just
// `go StartLocalDiscovery(cm)` unconditionally.
func localDiscoveryEnabled(cfg *Config) bool {
	if cfg.LocalDiscovery != nil {
		return *cfg.LocalDiscovery
	}
	return true
}

func StartLocalDiscovery(cm *ConfigManager) {
	cfg := cm.Get()
	if !localDiscoveryEnabled(cfg) {
		log.Printf("[local-discovery] disabled in agent.yml")
		return
	}
	targetHost := hostFromURL(cfg.ServerURL)
	if targetHost == "" {
		log.Printf("[local-discovery] could not parse a hostname out of server_url %q -- disabled", cfg.ServerURL)
		return
	}

	log.Printf("[local-discovery] enabled, watching for a local announcement fronting %s", targetHost)

	// Start from the machine's real DNS truth. A managed block left behind by a
	// previous run is our own state, not the operator's, and we have no reason
	// yet to believe it is still correct -- the address may have moved, the
	// certificate may have changed, or (the case that produced this) a previous
	// version may have written a block that breaks TLS for the whole host.
	//
	// Clearing it also un-fools the "already resolves to the discovered IP, no
	// override needed" shortcut below, which reads /etc/hosts through the
	// resolver: with a stale block still in place that check compares our own
	// previous answer against itself, concludes there is nothing to do, and
	// leaves the block there permanently.
	if err := applyHostsOverride(map[string]string{}); err != nil {
		log.Printf("[local-discovery] could not clear a previous hosts override: %v", err)
	}

	currentlyOverridden := false
	lastIP := ""

	for {
		ip := findLocalAnnouncement(targetHost)

		// Record the sighting for home detection before deciding anything about
		// the hosts file. mDNS is link-local by construction -- multicast does
		// not cross routers or VLANs -- so "this site answered" is direct proof
		// of being on that site's LAN, and it holds whether or not an override
		// ends up being applied or is even wanted. home_reach.go consumes it.
		setLocalSiteSeen(ip != "")

		switch {
		case ip != "" && !currentlyOverridden:
			// Only apply an override if the discovered IP actually differs from
			// normal resolution. If DNS already answers with the LAN IP (e.g.
			// the host is on the same LAN and the router/local DNS returns the
			// local address), overriding /etc/hosts is unnecessary and hides
			// the real state from the operator. It also avoids clobbering an
			// existing /etc/hosts entry that may be intentionally managed.
			if currentIP := resolveHost(targetHost); currentIP == ip {
				log.Printf("[local-discovery] %s already resolves to %s -- no hosts override needed", targetHost, ip)
			} else if !overrideIsSafe(cfg.ServerURL, targetHost, ip) {
				// The LAN address is reachable but does not serve a usable
				// certificate for this name, so committing the override would
				// break TLS for every client on this machine, not just the
				// agent (/etc/hosts is system-wide). The public path already
				// works; leave it alone. See discovery_verify.go.
				log.Printf("[local-discovery] NOT overriding %s -> %s: it would break TLS for this whole host; leaving normal resolution in place", targetHost, ip)
			} else if err := applyHostsOverride(map[string]string{targetHost: ip}); err != nil {
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

		case ip != "" && currentlyOverridden:
			// Still announced, but keep checking that the address we pinned is
			// still serving a good certificate. A cert can expire, be rotated,
			// or the announcing address can move to a host that has none --
			// and an override left in place after that breaks the whole machine
			// rather than degrading quietly.
			if ip != lastIP {
				log.Printf("[local-discovery] %s now announced at %s (was %s) -- re-evaluating", targetHost, ip, lastIP)
				revertOverride(targetHost, &lastIP, &currentlyOverridden)
			} else if !overrideIsSafe(cfg.ServerURL, targetHost, ip) {
				log.Printf("[local-discovery] %s at %s stopped serving a usable certificate -- reverting to normal resolution", targetHost, ip)
				revertOverride(targetHost, &lastIP, &currentlyOverridden)
			}

		case ip == "" && currentlyOverridden:
			log.Printf("[local-discovery] %s no longer announced locally -- reverting to normal resolution", targetHost)
			revertOverride(targetHost, &lastIP, &currentlyOverridden)
		}
		time.Sleep(mdnsPollInterval)
	}
}

// revertOverride removes the managed hosts block and the pinned host route,
// returning the machine to ordinary DNS resolution. Shared by every path that
// gives up an override (announcement lost, address moved, certificate no
// longer usable) so none of them can forget half of the teardown.
func revertOverride(targetHost string, lastIP *string, overridden *bool) {
	if err := applyHostsOverride(map[string]string{}); err != nil {
		log.Printf("[local-discovery] failed to clear the hosts override for %s: %v", targetHost, err)
		return
	}
	if *lastIP != "" {
		removeLocalRoute(*lastIP)
	}
	*lastIP = ""
	*overridden = false
	notifyDiscoveryChange()
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

// resolveHost performs a normal DNS lookup of host and returns the first IPv4
// address, or "" if none. Used by local-discovery to skip an /etc/hosts
// override when normal resolution already yields the discovered LAN IP.
func resolveHost(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
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
			if !entryAnnouncesHost(entry, targetHost) || found != "" {
				continue
			}
			// Prefer the announcer's explicit directoryAddr TXT field
			// ("<lan-ip>:<port>") over the raw mDNS response address when it
			// names THIS targetHost as its directoryHost: the announcer
			// computes that address itself from its real (non-virtual)
			// interfaces (see jump-host's mdns_announce.js), so it is
			// correct even on a host where the underlying mDNS library would
			// otherwise happily answer from a Docker bridge interface. Only
			// trust it for the directory host specifically -- an
			// announcement fronting some OTHER hostname in `hosts` (proxy,
			// jump) has no directoryAddr of its own.
			if txtField(entry, "directoryHost") == targetHost {
				if addr := txtField(entry, "directoryAddr"); addr != "" {
					if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
						found = host
						if site := txtField(entry, "site"); site != "" {
							log.Printf("[local-discovery] %s is site %q (version %s)", targetHost, site, txtField(entry, "version"))
						}
						continue
					}
				}
			}
			if entry.AddrV4 != nil {
				found = entry.AddrV4.String()
			} else if entry.AddrV6 != nil {
				found = entry.AddrV6.String()
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

// Announcement is one distinct site seen on the local segment, used by the
// interactive `theta-agent discover` command (cli.go) -- an admin-driven,
// one-time lookup to find a site's directory hostname without having to
// already know it. Unlike findLocalAnnouncement (the passive loop above),
// this is never acted on automatically: it only ever prints candidates for
// a human (or install.sh, when there's exactly one) to choose from. See
// AGENT_LOCAL_DISCOVERY_SPEC.md's "fresh/unenrolled agent" case -- the
// already-enrolled "roaming to a different site" case is deliberately NOT
// built: mDNS is unauthenticated, and auto-switching which directory an
// already-trusted agent talks to is a materially bigger blast radius than
// this always-explicit, always-human-in-the-loop lookup.
type Announcement struct {
	Site          string `json:"site"`
	DirectoryHost string `json:"directoryHost"`
	DirectoryAddr string `json:"directoryAddr"`
	Version       string `json:"version"`
}

// browseAnnouncements does one mDNS query cycle and returns every distinct
// site seen (deduped by directoryHost), regardless of whether it fronts any
// hostname this agent already knows about.
func browseAnnouncements(timeout time.Duration) []Announcement {
	entriesCh := make(chan *mdns.ServiceEntry, 16)
	done := make(chan struct{})
	seen := make(map[string]bool)
	var found []Announcement

	go func() {
		for entry := range entriesCh {
			dhost := txtField(entry, "directoryHost")
			if dhost == "" || seen[dhost] {
				continue
			}
			seen[dhost] = true
			found = append(found, Announcement{
				Site:          txtField(entry, "site"),
				DirectoryHost: dhost,
				DirectoryAddr: txtField(entry, "directoryAddr"),
				Version:       txtField(entry, "version"),
			})
		}
		close(done)
	}()

	params := mdns.DefaultParams(mdnsServiceName)
	params.Entries = entriesCh
	params.Timeout = timeout
	params.DisableIPv6 = true

	// Same reasoning as findLocalAnnouncement's Query() call: a transient
	// lookup error (e.g. no multicast-capable interface right now) just
	// means "nothing found this time", not a fatal condition -- whatever
	// partial results already arrived on entriesCh are still valid.
	_ = mdns.Query(params)
	close(entriesCh)
	<-done
	return found
}

func entryAnnouncesHost(entry *mdns.ServiceEntry, targetHost string) bool {
	hosts := txtField(entry, "hosts")
	for _, h := range strings.Split(hosts, ",") {
		if strings.TrimSpace(h) == targetHost {
			return true
		}
	}
	return false
}

// txtField returns the value of a "key=value" TXT field (mdns_announce.js's
// hosts/site/directoryHost/directoryAddr/version), or "" if absent.
func txtField(entry *mdns.ServiceEntry, key string) string {
	prefix := key + "="
	for _, field := range entry.InfoFields {
		if strings.HasPrefix(field, prefix) {
			return strings.TrimPrefix(field, prefix)
		}
	}
	return ""
}
