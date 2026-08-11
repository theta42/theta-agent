//go:build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// Windows host-route pinning: add a /32 route for the discovered IP via the
// owning interface with metric 1. WireGuard's tunnel service adds routes for
// its AllowedIPs with a low metric; a /32 host route at metric 1 wins for the
// exact discovered IP, keeping the discovery path direct even with the tunnel
// up. `route.exe` is used rather than the wireguard.exe client because the
// tunnel is owned by a service we shouldn't rip down just to adjust one route.

func addHostRoute(ip string, ifaceIndex int, _ string) error {
	out, err := routeExec("route.exe",
		"add", ip,
		"mask", "255.255.255.255",
		"0.0.0.0", // on-link gateway; the interface index pins the interface
		"metric", "1",
		"IF", strconv.Itoa(ifaceIndex),
	)
	if err != nil {
		// Already present (previous apply never reverted, or route.exe
		// re-add) is the expected steady-state case -- treat as success.
		if strings.Contains(strings.ToLower(string(out)), "already exists") {
			return nil
		}
		return fmt.Errorf("route add %s: %v: %s", ip, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func delHostRoute(ip string) error {
	out, err := routeExec("route.exe", "delete", ip, "mask", "255.255.255.255")
	if err != nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "route not found") || strings.Contains(lower, "cannot find") {
			return nil // nothing to drop; not an error
		}
		return fmt.Errorf("route delete %s: %v: %s", ip, err, strings.TrimSpace(string(out)))
	}
	return nil
}
