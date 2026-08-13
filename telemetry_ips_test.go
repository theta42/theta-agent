package main

import "testing"

func TestIsVirtualInterfaceName(t *testing.T) {
	virtual := []string{
		"docker0", "docker_gwbridge", "br-4f2a9c1e8b7d", "veth1234abcd",
		"cni0", "cni-podman0", "flannel.1", "virbr0", "podman0", "tun0",
		"tap0", "lxcbr0", "vnet0",
	}
	for _, name := range virtual {
		if !isVirtualInterfaceName(name) {
			t.Errorf("expected %q to be treated as virtual", name)
		}
	}

	real := []string{"eth0", "ens18", "enp3s0", "wlan0", "bond0", "eno1"}
	for _, name := range real {
		if isVirtualInterfaceName(name) {
			t.Errorf("expected %q to NOT be treated as virtual", name)
		}
	}
}
