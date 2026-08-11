//go:build !windows

package main

// Unix hosts override (Linux today; macOS slots in here later with its own
// dscacheutil -flushcache flush -- see AGENT_LOCAL_DISCOVERY_SPEC.md).

// hostsFilePathUnix is a var, not a const, so tests can point it at a temp
// file instead of touching the real /etc/hosts.
var hostsFilePathUnix = "/etc/hosts"

func hostsFilePath() string { return hostsFilePathUnix }

func hostsEOL() string { return "\n" }

// flushDNSOnHostsChange is a no-op on Linux: resolvers read /etc/hosts per
// lookup, and nscd/systemd-resolved -- where present -- pick up hosts edits
// without an explicit flush. (macOS will need dscacheutil -flushcache here.)
func flushDNSOnHostsChange() {}

// setTestHostsPath points hostsFilePath() at a temp file for tests and
// returns a restore func. Exists in both platform files so the shared test
// code can compile everywhere.
func setTestHostsPath(path string) (restore func()) {
	prev := hostsFilePathUnix
	hostsFilePathUnix = path
	return func() { hostsFilePathUnix = prev }
}
