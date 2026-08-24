package main

// Reachability-based home detection.
//
// Comparing this host's public IP against the site's public IP is a weak test
// and, as shipped, a broken one: nothing in the suite ever sent
// `site_public_ip`, so homePublicIP was permanently empty and computeIsHome's
// `|| homePublicIP == ""` clause made every agent believe it was always home.
// Auto-VPN therefore never fired even with the capability enabled.
//
// Public-IP comparison is also wrong in cases that are common rather than
// exotic: CGNAT gives many unrelated sites the same egress address, a
// multi-WAN site egresses from several, and an IPv6-only client shares no
// address family with a v4 site record.
//
// So the primary signal is "can I reach something that only exists on the home
// LAN". The site's public IP is kept as a corroborating hint for the case where
// no private endpoint is known.

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// homeReachTimeout bounds a single probe. Short: this runs on the 60s home
// monitor tick, and a hung probe would stall the tray's status updates.
const homeReachTimeout = 2 * time.Second

// ── The mDNS sighting: the one signal that is proof rather than inference ───
//
// local_discovery.go already browses for the site's _theta-suite._tcp
// announcement every 30s, and multicast DNS does not cross routers or VLANs.
// So "the site answered on this link" IS "I am on the site's LAN" -- no
// address comparison, no probe, no assumption about how the site is addressed.
// The first release of reachability-based detection computed this every 30
// seconds, logged it, and then threw it away: on a host whose directory is
// named by a public FQDN and whose site has no dnsHost recorded, every other
// signal is unavailable, so the agent sat on the home LAN announcing
// "assuming away" once a minute forever.
//
// Treated as valid only while fresh. If the discovery loop is disabled, has
// not run yet, or has wedged, a stale "seen" must not pin the agent to home
// the way the old `homePublicIP == ""` clause did -- staleness falls through
// to the weaker signals below rather than answering.
var localSite struct {
	mu     sync.RWMutex
	seen   bool
	polled time.Time
}

// localSiteSeenTTL is how long a sighting stays authoritative. Two poll
// intervals plus slack: one missed poll is normal jitter, a longer gap means
// the loop is not running and its answer should not be trusted.
const localSiteSeenTTL = 3 * mdnsPollInterval

// setLocalSiteSeen records the result of one discovery poll. Called by
// StartLocalDiscovery on every cycle, whether or not it acts on the result.
func setLocalSiteSeen(seen bool) {
	localSite.mu.Lock()
	localSite.seen = seen
	localSite.polled = time.Now()
	localSite.mu.Unlock()
}

// localSiteSeen reports whether the site answered on this link recently.
// The second return distinguishes "polled, and it was absent" from "no fresh
// poll to go on", which the caller needs in order to keep falling through.
func localSiteSeen() (seen, fresh bool) {
	localSite.mu.RLock()
	defer localSite.mu.RUnlock()
	if localSite.polled.IsZero() || time.Since(localSite.polled) > localSiteSeenTTL {
		return false, false
	}
	return localSite.seen, true
}

// resolvesPrivate reports whether a hostname currently resolves to an
// RFC1918/ULA/link-local address.
//
// isPrivateHost below only inspects the literal, so it answers "no" for every
// endpoint addressed by name -- which is every normal deployment, since the
// directory is configured as an FQDN. But a public hostname answering with a
// private address is precisely the home case: split-horizon DNS, or the hosts
// override local discovery may have applied. Resolving closes that gap.
func resolvesPrivate(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateHost(host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// homeEndpoints returns the host:port pairs whose reachability implies we are
// on the home LAN, most specific first.
//
// The directory's own host is the natural probe: on the home LAN it resolves
// and answers privately. A LAN-only endpoint pushed by the directory takes
// precedence when present, since the directory may legitimately be reachable
// from anywhere.
func homeEndpoints(cfg *Config, lanEndpoint string) []string {
	var out []string
	if lanEndpoint != "" {
		out = append(out, withDefaultPort(lanEndpoint, "443"))
	}
	// hostFromURL (local_discovery.go) returns the bare hostname; the port
	// is supplied below.
	if host := hostFromURL(cfg.ServerURL); host != "" {
		out = append(out, withDefaultPort(host, "443"))
	}
	return out
}

// withDefaultPort appends a port when the endpoint carries none. Bare IPv6 is
// bracketed so net.Dial parses it.
func withDefaultPort(hostport, def string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	if strings.Count(hostport, ":") >= 2 && !strings.HasPrefix(hostport, "[") {
		return "[" + hostport + "]:" + def
	}
	return hostport + ":" + def
}

// isPrivateHost reports whether a host literal is an RFC1918/ULA/link-local
// address. A directory reachable only at a private address is by definition
// on a network we consider home.
func isPrivateHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// probeReachable reports whether a TCP connection to the endpoint completes.
// A refused connection still proves the host is there, which is what we are
// asking -- only a timeout or an unresolvable name counts as "not home".
func probeReachable(endpoint string) bool {
	d := net.Dialer{Timeout: homeReachTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), homeReachTimeout)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", endpoint)
	if err == nil {
		conn.Close()
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	// Connection refused/reset means something answered: we reached the network.
	return strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "reset")
}

// detectHome decides whether this host is on the home network.
//
// Signals in order of strength, strongest first, and the order matters: a
// positive answer from a stronger signal is trusted outright rather than
// second-guessed by a weaker one.
//
//  1. The site answered mDNS on this link. Proof: multicast is link-local.
//  2. A home-only endpoint is reachable -- one the directory pushed as
//     LAN-only, or one that resolves to a private address (split-horizon DNS,
//     or local discovery's own hosts override). Reaching it means being on
//     the network it lives on.
//  3. Public-IP equality, when both sides are actually known. Kept last: it is
//     wrong under CGNAT and at multi-WAN sites.
//
// With none of them available the answer is AWAY, not home. A false "home"
// silently disables auto-VPN, which is the failure the user cannot see; a
// false "away" merely brings up a tunnel that costs little.
func detectHome(cfg *Config, agentPublicIP, homePublicIP, lanEndpoint string, connected bool) bool {
	if !connected {
		return false
	}

	if seen, fresh := localSiteSeen(); fresh && seen {
		return true
	}

	for _, ep := range homeEndpoints(cfg, lanEndpoint) {
		// A pushed LAN endpoint is home-only by definition. Anything else has
		// to demonstrate it: a private address, whether written literally or
		// arrived at by resolution.
		homeOnly := (lanEndpoint != "" && ep == withDefaultPort(lanEndpoint, "443")) ||
			isPrivateHost(ep) || resolvesPrivate(ep)
		if homeOnly && probeReachable(ep) {
			return true
		}
	}

	if homePublicIP != "" && agentPublicIP != "" {
		return agentPublicIP == homePublicIP
	}

	log.Println("[home-detect] no home signal available (site not seen on this link, no LAN-only endpoint reachable, no site public IP); assuming away")
	return false
}
