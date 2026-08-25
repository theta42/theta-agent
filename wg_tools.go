package main

// Preflight for the WireGuard userspace tools.
//
// The kernel module ships with every modern Linux, but `wg` and `wg-quick`
// come from a separate package (wireguard-tools) that is NOT installed by
// default on a Debian/Ubuntu desktop image -- and install.sh never installed
// or checked for it.
//
// The result was a failure that looked like nothing at all. The host enrolled
// into the mesh, was allocated an address, had its peer added at the gateway,
// received its pushed config and wrote it to /etc/wireguard/theta-mesh.conf.
// Home detection worked; auto-VPN fired on the first away network. Every layer
// reported success. Then the last step said
//
//	wg-quick up theta-mesh: exec: "wg-quick": executable file not found in $PATH
//
// once, into the journal, and the tunnel simply never existed. The tray showed
// the same raw exec error, which names no package and suggests no fix.
//
// So: check for the tools explicitly, fail with a sentence an operator can act
// on, and report readiness in discovery so the directory can show that a host
// is enrolled in the mesh but cannot actually bring it up.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// wgLookPath is exec.LookPath, indirected so a test can describe a host with
// or without the tools rather than depending on what the CI image happens to
// have installed.
var wgLookPath = exec.LookPath

// wgOSReleasePath is indirected for the same reason.
var wgOSReleasePath = "/etc/os-release"

// ErrWireGuardToolsMissing is the sentinel callers match on to distinguish
// "this host cannot run WireGuard at all" from "this particular tunnel failed".
var ErrWireGuardToolsMissing = errors.New("wireguard tools are not installed")

// wgRequiredBinaries are both needed: wg-quick is what brings the tunnel up,
// and it shells out to wg to set the peers.
var wgRequiredBinaries = []string{"wg", "wg-quick"}

// checkWireGuardTools reports whether this host can bring a tunnel up.
//
// Windows drives wireguard.exe through its own service installer rather than
// wg-quick, so it is not covered here.
func checkWireGuardTools() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	var missing []string
	for _, bin := range wgRequiredBinaries {
		if _, err := wgLookPath(bin); err != nil {
			missing = append(missing, bin)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s not found in PATH. The WireGuard kernel module ships with the OS but the userspace tools are a separate package -- install them with: %s",
		ErrWireGuardToolsMissing, strings.Join(missing, " and "), wireguardInstallHint())
}

// WireGuardToolsReady is the boolean form, for the discovery payload.
func WireGuardToolsReady() bool { return checkWireGuardTools() == nil }

// wireguardInstallHint names the command that installs the tools on this host.
// Guessing wrong is harmless -- it is advice in an error string -- so an
// unrecognised distro gets a generic line rather than no help at all.
func wireguardInstallHint() string {
	switch distroFamily() {
	case "debian":
		return "apt-get install -y wireguard-tools"
	case "rhel":
		return "dnf install -y wireguard-tools"
	case "suse":
		return "zypper install -y wireguard-tools"
	case "arch":
		return "pacman -S --noconfirm wireguard-tools"
	case "alpine":
		return "apk add wireguard-tools"
	}
	return "your distribution's wireguard-tools package"
}

// distroFamily reduces /etc/os-release to one of the families above. ID_LIKE
// is consulted after ID so that a derivative (Linux Mint, Rocky, Manjaro)
// resolves to its parent instead of falling through to the generic hint.
func distroFamily() string {
	data, err := os.ReadFile(wgOSReleasePath)
	if err != nil {
		return ""
	}
	var id, idLike string
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "ID_LIKE":
			idLike = v
		}
	}
	for _, token := range append([]string{id}, strings.Fields(idLike)...) {
		switch token {
		case "debian", "ubuntu", "raspbian", "linuxmint", "pop":
			return "debian"
		case "rhel", "fedora", "centos", "rocky", "almalinux":
			return "rhel"
		case "suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles":
			return "suse"
		case "arch", "manjaro", "archarm":
			return "arch"
		case "alpine":
			return "alpine"
		}
	}
	return ""
}

// ── Payload helpers for the mesh identity fields ────────────────────────────
//
// JSON numbers arrive as float64 through a map[string]interface{}, and the
// directory sends exitSiteId as null when the device has no exit. Both need
// stating once rather than at each use site.

// intFromPayload reads a numeric field, returning 0 when it is absent or not a
// number.
func intFromPayload(payload map[string]interface{}, key string) int {
	switch v := payload[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// optIntFromPayload distinguishes "no exit" (null, or absent) from a site id.
func optIntFromPayload(payload map[string]interface{}, key string) *int {
	raw, ok := payload[key]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case float64:
		n := int(v)
		return &n
	case int:
		return &v
	}
	return nil
}
