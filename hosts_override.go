package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
)

// Linux-only for now (AGENT_LOCAL_DISCOVERY_SPEC.md §3) -- Windows/macOS
// hosts-file semantics (elevation, DNS caching, whether mDNSResponder should
// be used instead of hand-rolled hosts edits) need their own platform-native
// investigation before this mechanism is trusted there.
//
// var, not const, so tests can point it at a temp file instead of touching
// the real /etc/hosts.
var hostsFilePathLinux = "/etc/hosts"

const hostsBlockBegin = "# BEGIN theta-agent-local-discovery (managed, do not edit by hand)"
const hostsBlockEnd = "# END theta-agent-local-discovery"

var hostsMu sync.Mutex

// applyHostsOverride replaces the managed block in /etc/hosts with exactly
// `entries` (hostname -> IP). Passing an empty map removes the block
// entirely rather than leaving an empty marker pair, so a host that never
// discovers anything -- or stops discovering something it used to -- leaves
// hosts file with no discovery trace at all.
func applyHostsOverride(entries map[string]string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("hosts-file override is Linux-only for now (see AGENT_LOCAL_DISCOVERY_SPEC.md §3)")
	}
	hostsMu.Lock()
	defer hostsMu.Unlock()

	existing, err := readLines(hostsFilePathLinux)
	if err != nil {
		return fmt.Errorf("reading %s: %w", hostsFilePathLinux, err)
	}

	kept := make([]string, 0, len(existing))
	inBlock := false
	for _, line := range existing {
		trimmed := strings.TrimSpace(line)
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
		kept = append(kept, line)
	}

	// Trim any trailing blank lines the block removal left, then rebuild.
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}

	out := strings.Join(kept, "\n")
	if len(entries) > 0 {
		out += "\n" + hostsBlockBegin + "\n"
		for host, ip := range entries {
			out += fmt.Sprintf("%s\t%s\n", ip, host)
		}
		out += hostsBlockEnd + "\n"
	} else {
		out += "\n"
	}

	// NOT write-tmp-then-rename: on a real host that's the safer, atomic
	// way to update a file, but /etc/hosts is frequently a bind mount
	// (every container runtime does this, Docker included) -- confirmed the
	// hard way: rename() onto a bind-mounted /etc/hosts fails with EBUSY
	// ("device or resource busy"), since you cannot atomically replace a
	// mountpoint. Truncate-and-rewrite in place instead; hostsMu already
	// serializes calls from this process, which is the only writer of the
	// managed block, so the lost atomicity is a real but small tradeoff
	// against a confirmed hard failure.
	if err := os.WriteFile(hostsFilePathLinux, []byte(out), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", hostsFilePathLinux, err)
	}
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
