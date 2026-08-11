//go:build !windows

package main

import (
	"fmt"
	"strings"
)

// Unix host-route pinning via `ip route`. The discovered IP is on-link, so a
// /32 route straight out the owning interface is enough; `ip route replace`
// is idempotent (re-adds instead of failing when the route is already there).
// The /32 wins by longest-prefix-match over any broader tunnel route, even a
// full-tunnel 0.0.0.0/0 -- no metric games needed on Linux.

func addHostRoute(ip string, _ int, ifaceName string) error {
	out, err := routeExec("ip", "route", "replace", ip+"/32", "dev", ifaceName)
	if err != nil {
		// `ip route replace` is idempotent in real usage -- it re-adds
		// rather than erroring when the route already exists -- but tolerate
		// an "already exists" error anyway (defensive, and matches
		// local_route_windows.go's addHostRoute, which route.exe genuinely
		// does return for a duplicate `route add`; the shared test suite
		// exercises both platforms' tolerance for the same fixture text).
		if strings.Contains(strings.ToLower(string(out)), "already exists") {
			return nil
		}
		return fmt.Errorf("ip route replace %s via %s: %v: %s", ip, ifaceName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func delHostRoute(ip string) error {
	out, err := routeExec("ip", "route", "del", ip+"/32")
	if err != nil {
		// A missing route isn't an error -- nothing to drop. Covers both the
		// RTNETLINK/iproute2 phrasing ("No such process", "Cannot find
		// device") and "route not found", which the shared cross-platform
		// test suite (local_route_test.go) also exercises against
		// local_route_windows.go's delHostRoute.
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "no such process") || strings.Contains(lower, "cannot find") || strings.Contains(lower, "route not found") {
			return nil
		}
		return fmt.Errorf("ip route del %s: %v: %s", ip, err, strings.TrimSpace(string(out)))
	}
	return nil
}
