//go:build windows

package main

import (
	"log"
	"os"
	"strings"
)

// Windows hosts override (AGENT_LOCAL_DISCOVERY_SPEC.md):
//  - The hosts file lives at %SystemRoot%\System32\drivers\etc\hosts. The
//    theta-agent runs as a SYSTEM service (DESIGN-WINDOWS.md), so elevation
//    is not a blocker here -- SYSTEM can write it directly.
//  - Windows caches DNS in the DNS Client service. An edit to the hosts file
//    does not immediately change resolution until the cache is flushed, so
//    every successful change runs `ipconfig /flushdns`.
//  - Windows hosts files conventionally use CRLF line endings; the shared
//    rewrite normalizes on read and writes back with hostsEOL().

// hostsFilePathWindows, when set (tests only), redirects hostsFilePath() at a
// temp file so unit tests never touch the real system hosts file.
var hostsFilePathWindows string

// systemHostsPath resolves the real system hosts file.
func systemHostsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return root + `\System32\drivers\etc\hosts`
}

func hostsFilePath() string {
	if hostsFilePathWindows != "" {
		return hostsFilePathWindows
	}
	return systemHostsPath()
}

func hostsEOL() string { return "\r\n" }

// flushDNSOnHostsChange invalidates the Windows DNS cache after a hosts edit.
// No-op when a test redirected the path to a temp file -- a temp file has no
// cached entries and running ipconfig here would just slow the tests down.
func flushDNSOnHostsChange() {
	if hostsFilePathWindows != "" {
		return
	}
	out, err := (&SystemExecutor{}).Execute("ipconfig", "/flushdns")
	if err != nil {
		log.Printf("[local-discovery] ipconfig /flushdns failed (hosts override may not take effect immediately): %v: %s", err, strings.TrimSpace(string(out)))
	}
}

// setTestHostsPath points hostsFilePath() at a temp file for tests and
// returns a restore func. Exists in both platform files so the shared test
// code can compile everywhere.
func setTestHostsPath(path string) (restore func()) {
	prev := hostsFilePathWindows
	hostsFilePathWindows = path
	return func() { hostsFilePathWindows = prev }
}
