package main

import (
	"net"
	"testing"
	"time"
)

// listenLocal starts a throwaway TCP listener and returns its host:port.
func listenLocal(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestProbeReachableTrueForLiveListener(t *testing.T) {
	addr, stop := listenLocal(t)
	defer stop()
	if !probeReachable(addr) {
		t.Fatalf("live listener at %s reported unreachable", addr)
	}
}

func TestProbeReachableFalseForUnroutableAddress(t *testing.T) {
	// TEST-NET-1 (RFC 5737): guaranteed not routed, so this times out rather
	// than being refused.
	if probeReachable("192.0.2.1:9") {
		t.Fatalf("unroutable address reported reachable")
	}
}

// The bug this replaces: computeIsHome returned true whenever homePublicIP was
// empty, and nothing in the suite ever set it -- so every agent believed it was
// permanently home and auto-VPN could never fire.
func TestDetectHomeUnknownSignalsMeansAway(t *testing.T) {
	cfg := &Config{ServerURL: "wss://sso.example.com"}
	if detectHome(cfg, "", "", "", true) {
		t.Fatalf("with no signals at all the agent must assume AWAY, not home")
	}
}

func TestDetectHomeDisconnectedIsAway(t *testing.T) {
	cfg := &Config{ServerURL: "wss://sso.example.com"}
	if detectHome(cfg, "1.2.3.4", "1.2.3.4", "", false) {
		t.Fatalf("a disconnected agent cannot be home")
	}
}

func TestDetectHomeReachableLanEndpointWins(t *testing.T) {
	addr, stop := listenLocal(t)
	defer stop()
	cfg := &Config{ServerURL: "wss://sso.example.com"}
	// Public IPs disagree -- reachability of the LAN endpoint still settles it.
	if !detectHome(cfg, "9.9.9.9", "1.2.3.4", addr, true) {
		t.Fatalf("a reachable LAN endpoint should mean home")
	}
}

func TestDetectHomeUnreachableLanEndpointFallsBackToPublicIP(t *testing.T) {
	cfg := &Config{ServerURL: "wss://sso.example.com"}
	if !detectHome(cfg, "1.2.3.4", "1.2.3.4", "192.0.2.1:9", true) {
		t.Fatalf("matching public IPs should mean home when the LAN probe fails")
	}
	if detectHome(cfg, "9.9.9.9", "1.2.3.4", "192.0.2.1:9", true) {
		t.Fatalf("differing public IPs should mean away")
	}
}

func TestIsPrivateHost(t *testing.T) {
	cases := map[string]bool{
		"192.168.1.10:443":    true,
		"10.4.0.1:443":        true,
		"172.16.5.5:443":      true,
		"127.0.0.1:443":       true,
		"[fd00::1]:443":       true,
		"8.8.8.8:443":         false,
		"sso.example.com:443": false,
	}
	for in, want := range cases {
		if got := isPrivateHost(in); got != want {
			t.Fatalf("isPrivateHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestWithDefaultPort(t *testing.T) {
	cases := map[string]string{
		"sso.example.com":      "sso.example.com:443",
		"sso.example.com:8443": "sso.example.com:8443",
		"10.0.0.1":             "10.0.0.1:443",
		"fd00::1":              "[fd00::1]:443",
		"[fd00::1]:53":         "[fd00::1]:53",
	}
	for in, want := range cases {
		if got := withDefaultPort(in, "443"); got != want {
			t.Fatalf("withDefaultPort(%q) = %q, want %q", in, got, want)
		}
	}
}

// A directory that only exists at a private address is by definition on a
// network we consider home.
func TestDetectHomePrivateDirectoryAddress(t *testing.T) {
	addr, stop := listenLocal(t)
	defer stop()
	host, port, _ := net.SplitHostPort(addr)
	_ = host
	cfg := &Config{ServerURL: "https://127.0.0.1:" + port}
	if !detectHome(cfg, "", "", "", true) {
		t.Fatalf("a reachable private directory address should mean home")
	}
}

// resetLocalSiteSeen clears the mDNS sighting so a test that does not care
// about it is not influenced by one that does. Tests in this file run in the
// same process and share the package-level state.
func resetLocalSiteSeen(t *testing.T) {
	t.Helper()
	localSite.mu.Lock()
	localSite.seen = false
	localSite.polled = time.Time{}
	localSite.mu.Unlock()
}

// The regression this exists for: on a laptop sitting on its own site's LAN,
// with the directory named by a public FQDN and the site carrying no dnsHost,
// every other signal is unavailable -- so the agent logged "assuming away"
// once a minute while local discovery, three lines earlier in the same log,
// reported seeing that exact site on the link.
func TestDetectHomeMdnsSightingIsConclusive(t *testing.T) {
	resetLocalSiteSeen(t)
	setLocalSiteSeen(true)
	defer resetLocalSiteSeen(t)

	cfg := &Config{ServerURL: "wss://sso.example.com"}
	// No LAN endpoint, no public IPs on either side: exactly the shipped
	// configuration that produced "assuming away" forever.
	if !detectHome(cfg, "", "", "", true) {
		t.Fatalf("the site answered mDNS on this link; that is proof of being home")
	}
}

func TestDetectHomeMdnsAbsenceDoesNotForceHome(t *testing.T) {
	resetLocalSiteSeen(t)
	setLocalSiteSeen(false)
	defer resetLocalSiteSeen(t)

	cfg := &Config{ServerURL: "wss://sso.example.com"}
	if detectHome(cfg, "9.9.9.9", "1.2.3.4", "", true) {
		t.Fatalf("mismatched public IPs with no sighting must read as away")
	}
}

// A wedged or disabled discovery loop must not answer the question. Its last
// reading goes stale and detection falls through to the weaker signals, rather
// than pinning the agent to whatever it happened to see hours ago -- the same
// failure mode as the old `homePublicIP == ""` clause.
func TestDetectHomeStaleMdnsSightingIsIgnored(t *testing.T) {
	resetLocalSiteSeen(t)
	defer resetLocalSiteSeen(t)

	localSite.mu.Lock()
	localSite.seen = true
	localSite.polled = time.Now().Add(-2 * localSiteSeenTTL)
	localSite.mu.Unlock()

	if seen, fresh := localSiteSeen(); fresh || seen {
		t.Fatalf("a sighting older than the TTL must not be reported fresh (seen=%v fresh=%v)", seen, fresh)
	}
	cfg := &Config{ServerURL: "wss://sso.example.com"}
	if detectHome(cfg, "9.9.9.9", "1.2.3.4", "", true) {
		t.Fatalf("a stale sighting must not decide the answer")
	}
}

// isPrivateHost only ever inspected the literal, so every deployment that names
// its directory by FQDN -- which is all of them -- skipped the probe entirely.
func TestResolvesPrivateFollowsNamesNotJustLiterals(t *testing.T) {
	if !resolvesPrivate("10.1.2.3:443") {
		t.Fatalf("a private literal must still count")
	}
	if !resolvesPrivate("localhost:443") {
		t.Fatalf("localhost resolves to a loopback address and must count")
	}
	if resolvesPrivate("8.8.8.8:443") {
		t.Fatalf("a public literal must not count")
	}
	if resolvesPrivate("no-such-host.invalid:443") {
		t.Fatalf("an unresolvable name must not count")
	}
}
