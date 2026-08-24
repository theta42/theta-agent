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
	"time"
)

// homeReachTimeout bounds a single probe. Short: this runs on the 60s home
// monitor tick, and a hung probe would stall the tray's status updates.
const homeReachTimeout = 2 * time.Second

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
// Order matters: a positive reachability result is strong evidence and is
// trusted outright. Only when no endpoint is reachable do we fall back to the
// public-IP hint, and an unknown hint no longer means "home" -- that was the
// bug that pinned every agent to home forever.
func detectHome(cfg *Config, agentPublicIP, homePublicIP, lanEndpoint string, connected bool) bool {
	if !connected {
		return false
	}
	for _, ep := range homeEndpoints(cfg, lanEndpoint) {
		if isPrivateHost(ep) {
			// A private directory address only resolves/routes on the home
			// network, so reaching it at all settles the question.
			if probeReachable(ep) {
				return true
			}
			continue
		}
		if lanEndpoint != "" && probeReachable(ep) {
			return true
		}
	}
	// Fall back to the public-IP comparison when both sides are known.
	if homePublicIP != "" && agentPublicIP != "" {
		return agentPublicIP == homePublicIP
	}
	// Nothing to go on. Assume AWAY: a false "home" silently disables auto-VPN,
	// while a false "away" merely brings up a tunnel that costs little.
	log.Println("[home-detect] no home signal available (no LAN endpoint, no site public IP); assuming away")
	return false
}
