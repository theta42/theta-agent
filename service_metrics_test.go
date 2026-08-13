package main

import (
	"os"
	"strings"
	"testing"
)

// stubExecutor returns canned systemctl show output per service, matching the
// shape the collector parses.
type stubExecutor struct {
	show          map[string]string // service name -> systemctl show output
	dockerInspect map[string]string
	dockerStats   map[string]string
}

func (s *stubExecutor) Execute(command string, args ...string) ([]byte, error) {
	if command == "systemctl" && len(args) > 1 && args[0] == "show" {
		out, ok := s.show[args[1]]
		if !ok {
			return nil, errServiceNotFound
		}
		return []byte(out), nil
	}
	if command == "docker" && len(args) > 0 {
		return s.docker(args)
	}
	return []byte(""), nil
}

func (s *stubExecutor) docker(args []string) ([]byte, error) {
	if len(args) < 2 {
		return nil, errServiceNotFound
	}
	switch args[0] {
	case "inspect":
		out, ok := s.dockerInspect[args[1]]
		if !ok {
			return nil, errServiceNotFound
		}
		return []byte(out), nil
	case "stats":
		out, ok := s.dockerStats[args[len(args)-1]]
		if !ok {
			return nil, errServiceNotFound
		}
		return []byte(out), nil
	}
	return []byte(""), nil
}
func (s *stubExecutor) WriteFile(path string, data []byte, perm os.FileMode) error { return nil }
func (s *stubExecutor) ReadFile(path string) ([]byte, error)                       { return []byte(""), nil }

var errServiceNotFound = &errNotFound{}

type errNotFound struct{}

func (e *errNotFound) Error() string { return "service not found" }

// buildShowOutput assembles a systemctl show listing.
func buildShowOutput(pairs ...string) string {
	return strings.Join(pairs, "\n")
}

func TestCollectServiceMetricsRich(t *testing.T) {
	// Reset the CPU-rate cache so tests are deterministic.
	cpuNSCacheMu.Lock()
	cpuNSCache = map[string]int64{}
	cpuNSCacheMu.Unlock()

	show := buildShowOutput(
		"ActiveState=active",
		"SubState=running",
		"LoadState=loaded",
		"CPUUsageNS=1000000000",
		"MemoryCurrent=536870912",
		"NRestarts=3",
		"ActiveEnterTimestamp=Wed 2026-08-12 14:03:22 UTC",
	)
	stub := &stubExecutor{show: map[string]string{"nginx": show}}

	metrics := collectServiceMetrics(stub, []RegisteredService{{Name: "nginx"}})
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
	m := metrics[0]
	if m.Name != "nginx" || !m.Active {
		t.Fatalf("unexpected basic state: %+v", m)
	}
	if m.SubState != "running" || m.LoadState != "loaded" {
		t.Fatalf("unexpected states: %+v", m)
	}
	if m.CPUUsageNS != 1000000000 {
		t.Fatalf("cpu ns = %d, want 1000000000", m.CPUUsageNS)
	}
	if m.MemoryCurrent != 536870912 {
		t.Fatalf("memory = %d, want 536870912", m.MemoryCurrent)
	}
	if m.NRestarts != 3 {
		t.Fatalf("restarts = %d, want 3", m.NRestarts)
	}
	// First sample: no rate yet.
	if m.CPUUsagePercent != -1 {
		t.Fatalf("cpu %% on first sample = %f, want -1", m.CPUUsagePercent)
	}
	if m.UptimeSeconds <= 0 {
		t.Fatalf("uptime = %d, want >0", m.UptimeSeconds)
	}
}

func TestCollectServiceMetricsCPUWindow(t *testing.T) {
	cpuNSCacheMu.Lock()
	cpuNSCache = map[string]int64{}
	cpuNSCacheMu.Unlock()

	stub := &stubExecutor{show: map[string]string{
		"app": buildShowOutput(
			"ActiveState=active", "SubState=running", "LoadState=loaded",
			"CPUUsageNS=0", "MemoryCurrent=0", "NRestarts=0", "ActiveEnterTimestamp=",
		),
	}}

	// First tick: base sample.
	first := collectServiceMetrics(stub, []RegisteredService{{Name: "app"}})[0]
	if first.CPUUsagePercent != -1 {
		t.Fatalf("first tick cpu %% = %f, want -1", first.CPUUsagePercent)
	}

	// Second tick: 15 CPU-seconds over the ~30s window -> ~50%.
	stub.show["app"] = buildShowOutput(
		"ActiveState=active", "SubState=running", "LoadState=loaded",
		"CPUUsageNS=15000000000", "MemoryCurrent=0", "NRestarts=0", "ActiveEnterTimestamp=",
	)
	second := collectServiceMetrics(stub, []RegisteredService{{Name: "app"}})[0]
	// 15e9 ns / (30 * 1e9) * 100 = 50
	if second.CPUUsagePercent < 49.9 || second.CPUUsagePercent > 50.1 {
		t.Fatalf("second tick cpu %% = %f, want ~50", second.CPUUsagePercent)
	}
}

func TestCollectServiceMetricsMissing(t *testing.T) {
	stub := &stubExecutor{show: map[string]string{}}
	m := collectServiceMetrics(stub, []RegisteredService{{Name: "ghost"}})[0]
	if m.Active {
		t.Fatalf("missing service reported active: %+v", m)
	}
	if m.LoadState != "not-found" {
		t.Fatalf("load state = %q, want not-found", m.LoadState)
	}
}

func TestParseSystemdTimestamp(t *testing.T) {
	ts, err := parseSystemdTimestamp("Wed 2026-08-12 14:03:22 UTC")
	if err != nil {
		t.Fatal(err)
	}
	expected := "2026-08-12T14:03:22Z"
	if got := ts.UTC().Format("2006-01-02T15:04:05Z"); got != expected {
		t.Fatalf("got %s, want %s", got, expected)
	}
}

func TestCollectDockerMetrics(t *testing.T) {
	stub := &stubExecutor{
		dockerInspect: map[string]string{
			"web": "true|running|2|2026-08-12T14:00:00Z",
		},
		dockerStats: map[string]string{
			"web": "3.25%|1.5GiB / 7.8GiB",
		},
	}

	metrics := collectServiceMetrics(stub, []RegisteredService{{Name: "web", SubType: "docker"}})
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
	m := metrics[0]
	if m.Name != "web" || !m.Active || m.SubType != "docker" {
		t.Fatalf("unexpected basic state: %+v", m)
	}
	if m.SubState != "running" || m.LoadState != "loaded" {
		t.Fatalf("unexpected states: %+v", m)
	}
	if m.NRestarts != 2 {
		t.Fatalf("restarts = %d, want 2", m.NRestarts)
	}
	if m.CPUUsagePercent < 3.2 || m.CPUUsagePercent > 3.3 {
		t.Fatalf("cpu %% = %f, want ~3.25", m.CPUUsagePercent)
	}
	// 1.5 GiB = 1610612736 bytes
	if m.MemoryCurrent != 1610612736 {
		t.Fatalf("memory = %d, want 1610612736", m.MemoryCurrent)
	}
	if m.UptimeSeconds <= 0 {
		t.Fatalf("uptime = %d, want >0", m.UptimeSeconds)
	}
}

func TestCollectDockerMetricsMissing(t *testing.T) {
	stub := &stubExecutor{}
	m := collectServiceMetrics(stub, []RegisteredService{{Name: "ghost", SubType: "docker"}})[0]
	if m.Active {
		t.Fatalf("missing container reported active: %+v", m)
	}
	if m.LoadState != "not-found" {
		t.Fatalf("load state = %q, want not-found", m.LoadState)
	}
}

func TestParseSizeBytes(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"1.5GiB", 1610612736},
		{"512MiB", 536870912},
		{"1.5GB", 1500000000},
		{"1.2kB", 1200},
		{"1024B", 1024},
		{"2KiB", 2048},
	}
	for _, c := range cases {
		if got := parseSizeBytes(c.in); got != c.want {
			t.Fatalf("parseSizeBytes(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParsePercent(t *testing.T) {
	if got := parsePercent("3.25%"); got != 3.25 {
		t.Fatalf("parsePercent = %f, want 3.25", got)
	}
	if got := parsePercent("junk"); got != -1 {
		t.Fatalf("parsePercent(junk) = %f, want -1", got)
	}
}
