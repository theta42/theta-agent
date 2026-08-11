package main

import (
	"fmt"
	"log"
	"net"
)

// Local-route pinning for local-discovery (AGENT_LOCAL_DISCOVERY_SPEC.md).
//
// The hosts override redirects NAME resolution of the server hostname to the
// discovered LAN IP, but the packet path is decided by the routing table, not
// by DNS. If the agent's WireGuard mesh tunnel is up with AllowedIPs covering
// the LAN subnet (or a full-tunnel 0.0.0.0/0), that tunnel route will swallow
// the direct connection to the discovered IP -- the discovery optimization
// silently stops working, and worse, the LAN IP may not even be reachable
// through the tunnel. So when an override is applied, also pin a /32 host
// route for the discovered IP on the owning local interface (it is on-link by
// definition -- mDNS never crosses routers), with priority over the tunnel's
// routes; and drop that route again when the override is reverted.
//
// HARD RULE unchanged: this only changes where packets go. Nothing here
// touches TLS/certificate validation; a spoofed announcement still produces a
// TLS handshake failure against the real hostname's cert, not a silent MITM.

// routeExec is injectable so tests can assert on the commands instead of
// mutating the real routing table.
var routeExec = func(name string, args ...string) ([]byte, error) {
	return (&SystemExecutor{}).Execute(name, args...)
}

// localIface is a minimal view of a local network interface for route
// pinning: its index, name, and the subnets configured on it.
type localIface struct {
	index int
	name  string
	nets  []*net.IPNet
}

// localInterfaces lists up, non-loopback interfaces and their subnets.
// Injectable so tests can fake the machine's network layout.
var localInterfaces = func() ([]localIface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]localIface, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		li := localIface{index: iface.Index, name: iface.Name}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				li.nets = append(li.nets, ipn)
			}
		}
		out = append(out, li)
	}
	return out, nil
}

// interfaceForIP returns the local interface whose subnet contains ip, which
// is the one the discovered (on-link) IP must route through.
func interfaceForIP(ip string) (index int, name string, ok bool) {
	target := net.ParseIP(ip)
	if target == nil {
		return 0, "", false
	}
	ifaces, err := localInterfaces()
	if err != nil {
		return 0, "", false
	}
	for _, iface := range ifaces {
		for _, n := range iface.nets {
			if n.Contains(target) {
				return iface.index, iface.name, true
			}
		}
	}
	return 0, "", false
}

// applyLocalRoute pins the discovered IP on the owning local interface so the
// packet path stays direct even with the WireGuard tunnel up.
func applyLocalRoute(ip string) error {
	index, name, ok := interfaceForIP(ip)
	if !ok {
		return fmt.Errorf("no local interface contains %s (cannot pin a direct route)", ip)
	}
	return addHostRoute(ip, index, name)
}

// removeLocalRoute drops the host route added by applyLocalRoute. Best-effort
// by design: a leftover /32 is harmless and a failed delete should not fail
// the discovery revert itself.
func removeLocalRoute(ip string) {
	if err := delHostRoute(ip); err != nil {
		log.Printf("[local-discovery] failed to remove host route for %s: %v", ip, err)
	}
}
