package main

import (
	"errors"
	"net"
	"strings"
	"testing"
)

var (
	errAlreadyExists = errors.New("already exists")
	errRouteOp       = errors.New("route op failed")
)

func withFakeInterfaces(nets []*net.IPNet) func() {
	orig := localInterfaces
	localInterfaces = func() ([]localIface, error) {
		return []localIface{{index: 7, name: "fake0", nets: nets}}, nil
	}
	return func() { localInterfaces = orig }
}

func TestInterfaceForIP_FindsOwningInterface(t *testing.T) {
	restore := withFakeInterfaces([]*net.IPNet{ipNet("192.168.1.0/24")})
	defer restore()

	idx, name, ok := interfaceForIP("192.168.1.50")
	if !ok || idx != 7 || name != "fake0" {
		t.Fatalf("interfaceForIP(192.168.1.50) = (%d, %q, %v), want (7, fake0, true)", idx, name, ok)
	}
}

func TestInterfaceForIP_NotOnLocalSegment(t *testing.T) {
	restore := withFakeInterfaces([]*net.IPNet{ipNet("192.168.1.0/24")})
	defer restore()

	if _, _, ok := interfaceForIP("10.99.99.99"); ok {
		t.Fatal("interfaceForIP should not claim a non-local IP")
	}
}

func TestInterfaceForIP_InvalidIP(t *testing.T) {
	restore := withFakeInterfaces([]*net.IPNet{ipNet("192.168.1.0/24")})
	defer restore()

	if _, _, ok := interfaceForIP("not-an-ip"); ok {
		t.Fatal("interfaceForIP should reject garbage input")
	}
}

func TestInterfaceForIP_TakesFirstMatchAcrossInterfaces(t *testing.T) {
	orig := localInterfaces
	defer func() { localInterfaces = orig }()
	localInterfaces = func() ([]localIface, error) {
		return []localIface{
			{index: 1, name: "eth0", nets: []*net.IPNet{ipNet("10.0.0.0/24")}},
			{index: 2, name: "wlan0", nets: []*net.IPNet{ipNet("192.168.50.0/24")}},
		}, nil
	}

	idx, name, ok := interfaceForIP("192.168.50.9")
	if !ok || idx != 2 || name != "wlan0" {
		t.Fatalf("expected wlan0 (idx 2) to own 192.168.50.9, got (%d, %q, %v)", idx, name, ok)
	}
}

func TestAddHostRoute_IgnoresAlreadyExists(t *testing.T) {
	orig := routeExec
	defer func() { routeExec = orig }()
	routeExec = func(name string, args ...string) ([]byte, error) {
		return []byte("The object already exists."), errAlreadyExists
	}

	if err := addHostRoute("192.168.1.50", 7, "fake0"); err != nil {
		t.Fatalf("addHostRoute should treat an already-present route as success, got %v", err)
	}
}

func TestAddHostRoute_ReturnsOtherErrors(t *testing.T) {
	orig := routeExec
	defer func() { routeExec = orig }()
	routeExec = func(name string, args ...string) ([]byte, error) {
		return []byte("The parameter is incorrect."), errRouteOp
	}

	if err := addHostRoute("192.168.1.50", 7, "fake0"); err == nil {
		t.Fatal("addHostRoute should surface non-already-exists errors")
	}
}

func TestDelHostRoute_IgnoresMissingRoute(t *testing.T) {
	orig := routeExec
	defer func() { routeExec = orig }()
	routeExec = func(name string, args ...string) ([]byte, error) {
		return []byte("route not found"), errRouteOp
	}

	if err := delHostRoute("192.168.1.50"); err != nil {
		t.Fatalf("delHostRoute should treat a missing route as success, got %v", err)
	}
}

func TestApplyLocalRoute_FailsWhenNoOwningInterface(t *testing.T) {
	restore := withFakeInterfaces([]*net.IPNet{ipNet("192.168.1.0/24")})
	defer restore()

	if err := applyLocalRoute("172.16.0.9"); err == nil || !strings.Contains(err.Error(), "no local interface") {
		t.Fatalf("applyLocalRoute should fail with a clear error for a non-local IP, got %v", err)
	}
}

func ipNet(cidr string) *net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return n
}
