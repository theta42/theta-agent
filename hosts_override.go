package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Local-discovery hosts override (AGENT_LOCAL_DISCOVERY_SPEC.md):
// applyHostsOverride replaces the managed block in the platform hosts file
// with exactly `entries` (hostname -> IP). Passing an empty map removes the
// block entirely rather than leaving an empty marker pair, so a host that
// never discovers anything -- or stops discovering something it used to --
// leaves the hosts file with no discovery trace at all.
//
// Platform specifics live in hosts_override_windows.go / hosts_override_unix.go:
// the file path, line-ending convention, and any DNS-cache flush needed for a
// hosts edit to take effect promptly (ipconfig /flushdns on Windows).
//
// NOT write-tmp-then-rename: on a real host that's the safer, atomic way to
// update a file, but the hosts file is frequently a bind mount (every
// container runtime does this, Docker included) -- confirmed the hard way on
// Linux: rename() onto a bind-mounted /etc/hosts fails with EBUSY ("device
// or resource busy"), since you cannot atomically replace a mountpoint.
// Truncate-and-rewrite in place instead; hostsMu already serializes calls
// from this process, which is the only writer of the managed block, so the
// lost atomicity is a real but small tradeoff against a confirmed hard
// failure. On Windows the same in-place write preserves the file's ACLs,
// which a rename onto the system hosts file would not.

const hostsBlockBegin = "# BEGIN theta-agent-local-discovery (managed, do not edit by hand)"
const hostsBlockEnd = "# END theta-agent-local-discovery"

var hostsMu sync.Mutex

// applyHostsOverride replaces the managed block in the platform hosts file.
func applyHostsOverride(entries map[string]string) error {
	hostsMu.Lock()
	defer hostsMu.Unlock()

	path := hostsFilePath()
	eol := hostsEOL()

	existing, err := readLines(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	kept := make([]string, 0, len(existing))
	inBlock := false
	for _, line := range existing {
		// Normalize CRLF away so marker comparison is platform-agnostic and
		// a CRLF file written back out with hostsEOL() doesn't double up \r.
		normalized := strings.TrimSuffix(line, "\r")
		trimmed := strings.TrimSpace(normalized)
		if trimmed == hostsBlockBegin {
			inBlock = true
			continue
		}
		if trimmed == hostsBlockEnd {
			inBlock = false
			continue
		}
		if inBlock {
			continue // drop old managed lines unconditionally; rebuilt below
		}
		kept = append(kept, normalized)
	}

	// Trim any trailing blank lines the block removal left, then rebuild.
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}

	var out strings.Builder
	out.WriteString(strings.Join(kept, eol))
	if len(entries) > 0 {
		out.WriteString(eol + hostsBlockBegin + eol)
		for host, ip := range entries {
			out.WriteString(fmt.Sprintf("%s\t%s%s", ip, host, eol))
		}
		out.WriteString(hostsBlockEnd + eol)
	} else {
		out.WriteString(eol)
	}

	if err := os.WriteFile(path, []byte(out.String()), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	flushDNSOnHostsChange()
	return nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
