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
		return fmt.Errorf("ip route replace %s via %s: %v: %s", ip, ifaceName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func delHostRoute(ip string) error {
	out, err := routeExec("ip", "route", "del", ip+"/32")
	if err != nil {
		// "No such process" / RTNETLINK errors mean the route isn't there;
		// nothing to drop, not an error.
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "no such process") || strings.Contains(lower, "cannot find") {
			return nil
		}
		return fmt.Errorf("ip route del %s: %v: %s", ip, err, strings.TrimSpace(string(out)))
	}
	return nil
}
