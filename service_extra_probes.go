package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// probePodmanContainer mirrors probeDockerContainer but shells out to podman.
// podman has no root daemon, so `podman stats` also needs a live poll and is
// only meaningful for running containers.
func probePodmanContainer(exec Executor, name string) ServiceMetric {
	svc := ServiceMetric{Name: name, SubType: "podman", LoadState: "not-found"}

	out, err := exec.Execute("podman", "inspect", name, "--format", "{{.State.Running}}|{{.State.Status}}|{{.RestartCount}}|{{.State.StartedAt}}")
	if err != nil {
		return svc
	}
	fields := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(fields) >= 4 {
		svc.Active = strings.TrimSpace(fields[0]) == "true"
		svc.SubState = strings.TrimSpace(fields[1])
		svc.LoadState = "loaded"
		if n, perr := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 64); perr == nil {
			svc.NRestarts = n
		}
		if t, terr := time.Parse(time.RFC3339Nano, strings.TrimSpace(fields[3])); terr == nil {
			if u := time.Since(t); u > 0 {
				svc.UptimeSeconds = int64(u.Seconds())
			}
		}
	}

	if svc.Active {
		stats, serr := exec.Execute("podman", "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", name)
		if serr == nil {
			sparts := strings.Split(strings.TrimSpace(string(stats)), "|")
			if len(sparts) >= 2 {
				if cpu := parsePercent(strings.TrimSpace(sparts[0])); cpu >= 0 {
					svc.CPUUsagePercent = cpu
				}
				if mem := parseMemUsage(strings.TrimSpace(sparts[1])); mem > 0 {
					svc.MemoryCurrent = mem
				}
			}
		}
	}
	return svc
}

// probeProcess reports on a bare process matched by name (or numeric PID). It
// reads /proc directly, so no external command is required and it works for any
// process, not just ones under an init system. For a name, the most recently
// started matching process is chosen.
func probeProcess(exec Executor, name string) ServiceMetric {
	svc := ServiceMetric{Name: name, SubType: "process", LoadState: "not-found"}

	pid := ""
	if n, err := strconv.Atoi(name); err == nil {
		pid = strconv.Itoa(n)
	} else {
		pid = findProcessByComm(exec, name)
	}
	if pid == "" {
		return svc
	}

	svc.LoadState = "loaded"
	svc.SubState = "running"
	svc.Active = true
	svc.NRestarts = processRestartCount(exec, pid)
	if u := processUptime(exec, pid); u > 0 {
		svc.UptimeSeconds = u
	}
	svc.CPUUsagePercent = processCPUPercent(exec, pid)
	svc.MemoryCurrent = processMemory(exec, pid)
	return svc
}

// findProcessByComm scans /proc/*/comm for a name match, returning the pid of
// the most recently started match (highest starttime), or "" if none. Comm is
// truncated to 15 chars by the kernel, so we match an exact comm or a
// name-prefix-of-comm (so a 20-char process name still finds its truncated
// comm).
func findProcessByComm(exec Executor, name string) string {
	procEntries, _ := os.ReadDir("/proc")
	best := ""
	var bestStart uint64
	for _, e := range procEntries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
		if err != nil {
			continue
		}
		commName := strings.TrimSpace(string(comm))
		if commName != name && !strings.HasPrefix(commName, name) {
			continue
		}
		start := processStart(pid)
		if start >= bestStart {
			bestStart = start
			best = pid
		}
	}
	return best
}

// processStart reads a process's starttime from /proc/<pid>/stat (field 22).
func processStart(pid string) uint64 {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "stat"))
	if err != nil {
		return 0
	}
	return statField(data, 22)
}

// statField extracts a field from /proc/<pid>/stat. After the leading
// "(comm)" (which may contain spaces/parens) the fields array starts at field
// 3 (state), so /proc stat field N maps to index N-3.
func statField(data []byte, field int) uint64 {
	s := string(data)
	// Skip the leading "(comm)" which may contain spaces/parens.
	idx := strings.LastIndexByte(s, ')')
	if idx < 0 {
		return 0
	}
	fields := strings.Fields(s[idx+1:])
	if field >= 3 && field-3 < len(fields) {
		v, _ := strconv.ParseUint(fields[field-3], 10, 64)
		return v
	}
	return 0
}

// processRestartCount approximates restarts for a bare process: there is no
// init-managed counter, so it reports 0 (meaningless for /proc processes). Kept
// for interface parity.
func processRestartCount(exec Executor, pid string) uint64 {
	return 0
}

// processUptime returns the process's elapsed wall time in seconds.
func processUptime(exec Executor, pid string) int64 {
	stat, err := os.ReadFile(filepath.Join("/proc", pid, "stat"))
	if err != nil {
		return 0
	}
	// Field 22 is starttime in clock ticks since boot.
	startTicks := statField(stat, 22)
	if startTicks == 0 {
		return 0
	}
	// Clock ticks per second (typically 100) and boot time.
	hz := clockTicksPerSecond()
	boot := bootTimeUnix()
	if hz == 0 || boot == 0 {
		return 0
	}
	startUnix := boot + int64(startTicks/hz)
	now := time.Now().Unix()
	if startUnix > 0 && now > startUnix {
		return now - startUnix
	}
	return 0
}

// clockTicksPerSecond returns HZ from getconf, falling back to 100.
func clockTicksPerSecond() uint64 {
	out, err := execGetconf("CLK_TCK")
	if err == nil {
		if v, perr := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64); perr == nil && v > 0 {
			return v
		}
	}
	return 100
}

// bootTimeUnix returns the system boot time in unix seconds, from /proc/stat
// "btime".
func bootTimeUnix() int64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			v, _ := strconv.ParseInt(strings.TrimSpace(line[len("btime "):]), 10, 64)
			return v
		}
	}
	return 0
}

// processCPUPercent reads utime+stime from /proc/<pid>/stat and reports the
// process's CPU time as a percent of one core over the last tick window, using
// the same cpuRateFor cache (keyed by pid).
func processCPUPercent(exec Executor, pid string) float64 {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "stat"))
	if err != nil {
		return -1
	}
	// Fields 14 (utime) and 15 (stime) are clock ticks.
	utime := statField(data, 14)
	stime := statField(data, 15)
	hz := clockTicksPerSecond()
	if hz == 0 {
		return -1
	}
	totalNS := int64((utime + stime) * 1e9 / hz)
	return cpuRateFor("proc:"+pid, totalNS)
}

// processMemory returns the process RSS in bytes from /proc/<pid>/status.
func processMemory(exec Executor, pid string) uint64 {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, perr := strconv.ParseUint(fields[1], 10, 64)
				if perr == nil {
					return kb * 1024
				}
			}
		}
	}
	return 0
}

// probeSystemdTimer reports a systemd timer's schedule (next/last run). The
// metric model differs from a service: active means the timer is armed.
func probeSystemdTimer(exec Executor, name string) ServiceMetric {
	svc := ServiceMetric{Name: name, SubType: "systemd-timer", LoadState: "not-found"}
	if !strings.HasSuffix(name, ".timer") {
		name += ".timer"
	}

	out, err := exec.Execute("systemctl", "show", name, "--property=ActiveState,NextElapseUSecMonotonic,LastTriggerUSec,TriggeredBy,NextElapseRealtime")
	if err != nil {
		return svc
	}
	parsed := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		parsed[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
	}

	svc.Active = parsed["ActiveState"] == "active"
	svc.SubState = parsed["ActiveState"]
	svc.LoadState = "loaded"
	svc.SubType = "systemd-timer"
	svc.NRestarts = 0
	if parsed["NextElapseRealtime"] != "" && parsed["NextElapseRealtime"] != "n/a" {
		if t, terr := time.Parse(time.RFC3339, parsed["NextElapseRealtime"]); terr == nil {
			svc.NextRun = t.UTC().Format(time.RFC3339)
		}
	}
	if parsed["LastTriggerUSec"] != "" && parsed["LastTriggerUSec"] != "n/a" && parsed["LastTriggerUSec"] != "0" {
		if us, perr := strconv.ParseInt(parsed["LastTriggerUSec"], 10, 64); perr == nil {
			svc.LastRun = time.Unix(us/1e6, 0).UTC().Format(time.RFC3339)
		}
	}
	return svc
}

// probeCron reports a cron job by name. The name identifies a crontab entry:
// either an /etc/cron.d/<name> file, the whole system crontab, or a user's
// /var/spool/cron/<user> table. Each job line's 5-field schedule is parsed to
// compute the next and last fire times. When multiple matching entries exist,
// the nearest next_run and most recent last_run across them are reported.
func probeCron(exec Executor, name string) ServiceMetric {
	svc := ServiceMetric{Name: name, SubType: "cron", LoadState: "loaded"}

	lines := cronConfigLines(name)
	if len(lines) == 0 {
		svc.Active = false
		svc.SubState = "not-found"
		svc.LoadState = "not-found"
		return svc
	}

	now := time.Now()
	var next, last time.Time
	active := false
	for _, l := range lines {
		expr := cronExprOf(l)
		if expr == "" {
			continue
		}
		active = true
		sched, err := parseCronSchedule(expr)
		if err != nil {
			continue
		}
		if n := sched.next(now); !n.IsZero() && (next.IsZero() || n.Before(next)) {
			next = n
		}
		if p := sched.prev(now); !p.IsZero() && (last.IsZero() || p.After(last)) {
			last = p
		}
	}

	svc.Active = active
	svc.SubState = "configured"
	if active {
		svc.Status = "scheduled"
	}
	if !next.IsZero() {
		svc.NextRun = next.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		svc.LastRun = last.UTC().Format(time.RFC3339)
		svc.Triggered = cronTriggeredCount(name, last)
	}
	return svc
}

// cronConfigLines returns the job lines relevant to a named cron entry: the
// /etc/cron.d/<name> file if present, plus any matching lines from the system
// crontab and the named user's spool. A comment-only file yields no lines.
func cronConfigLines(name string) []string {
	var lines []string
	seen := map[string]bool{}

	addFile := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		for _, l := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(l)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if !seen[trimmed] {
				seen[trimmed] = true
				lines = append(lines, trimmed)
			}
		}
	}

	addFile("/etc/cron.d/" + name)
	addFile("/etc/crontab")
	addFile("/var/spool/cron/" + name)
	return lines
}

// cronExprOf extracts the 5-field cron schedule from the front of a job line.
// A crontab job line is: <min> <hour> <dom> <month> <dow> <user> <command>.
// /etc/crontab requires a user field; user crontabs do not. We take the first
// five tokens and verify they parse as a schedule.
func cronExprOf(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return ""
	}
	expr := strings.Join(fields[0:5], " ")
	if _, err := parseCronSchedule(expr); err == nil {
		return expr
	}
	// Maybe the line is an @-shortcut (e.g. @daily), which has no schedule.
	return ""
}

// cronTriggeredCount reports how many times a cron entry has fired, by watching
// for the last_run timestamp to advance between telemetry ticks. The first time
// a given last_run is seen it seeds the counter at 1 (it has run at least
// once); a subsequent tick whose last_run changed bumps the count. Guarded so
// concurrent telemetry loops cannot race.
func cronTriggeredCount(name string, last time.Time) uint64 {
	cronMu.Lock()
	defer cronMu.Unlock()
	lastUnix := last.Unix()
	prev, seen := cronCountCache[name]
	if !seen {
		// Seed: no prior observation. Report 1.
		cronCountCache[name] = lastUnix
		cronCounts[name] = 1
		return 1
	}
	if prev == lastUnix {
		// No new firing; return the running count.
		return cronCounts[name]
	}
	if lastUnix > prev {
		cronCounts[name]++
	}
	cronCountCache[name] = lastUnix
	return cronCounts[name]
}

var (
	cronMu         sync.Mutex
	cronCountCache = map[string]int64{}
	cronCounts     = map[string]uint64{}
)

// probeLXC reports an LXC container. Uses `lxc-info` or `lxc-ls` when present.
func probeLXC(exec Executor, name string) ServiceMetric {
	svc := ServiceMetric{Name: name, SubType: "lxc", LoadState: "not-found"}

	// lxc-info -n <name> prints State, PID.
	out, err := exec.Execute("lxc-info", "-n", name, "-s", "-H", "-p", "-H")
	if err != nil {
		return svc
	}
	svc.LoadState = "loaded"
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, l := range lines {
		parts := strings.SplitN(l, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "State":
			svc.Active = val == "RUNNING"
			svc.SubState = strings.ToLower(val)
			svc.Status = val
		}
	}
	return svc
}

// probeKVM reports a libvirt/KVM domain via virsh.
func probeKVM(exec Executor, name string) ServiceMetric {
	svc := ServiceMetric{Name: name, SubType: "kvm", LoadState: "not-found"}

	out, err := exec.Execute("virsh", "domstate", name)
	if err != nil {
		return svc
	}
	state := strings.TrimSpace(string(out))
	svc.LoadState = "loaded"
	svc.Active = strings.EqualFold(state, "running")
	svc.SubState = strings.ToLower(state)
	svc.Status = state
	return svc
}

// execGetconf runs `getconf <key>`, returning an error if unavailable. Kept as
// a small helper so probeProcess doesn't depend on a specific Executor.
func execGetconf(key string) ([]byte, error) {
	return (&SystemExecutor{}).Execute("getconf", key)
}
