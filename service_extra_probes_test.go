package main

import (
	"os"
	"strings"
	"testing"
)

// stubCommandExecutor responds to commands with canned output per command string.
type stubCommandExecutor struct {
	responses map[string]string
	errs      map[string]bool
}

func (s *stubCommandExecutor) Execute(command string, args ...string) ([]byte, error) {
	key := command + " " + strings.Join(args, " ")
	if s.errs != nil && s.errs[key] {
		return []byte(""), errServiceNotFound
	}
	if resp, ok := s.responses[key]; ok {
		return []byte(resp), nil
	}
	return []byte(""), nil
}
func (s *stubCommandExecutor) WriteFile(path string, data []byte, perm os.FileMode) error {
	return nil
}
func (s *stubCommandExecutor) ReadFile(path string) ([]byte, error) {
	return []byte(""), nil
}

func TestProbePodman(t *testing.T) {
	stub := &stubCommandExecutor{responses: map[string]string{
		"podman inspect web --format {{.State.Running}}|{{.State.Status}}|{{.RestartCount}}|{{.State.StartedAt}}": "true|running|1|2026-08-12T10:00:00Z",
		"podman stats --no-stream --format {{.CPUPerc}}|{{.MemUsage}} web":                                        "4.5%|256MiB / 1GiB",
	}}
	svc := probePodmanContainer(stub, "web")
	if !svc.Active || svc.SubState != "running" {
		t.Fatalf("unexpected podman state: %+v", svc)
	}
	if svc.CPUUsagePercent != 4.5 {
		t.Fatalf("cpu = %f, want 4.5", svc.CPUUsagePercent)
	}
	if svc.MemoryCurrent != 256*1024*1024 {
		t.Fatalf("mem = %d, want 256MiB", svc.MemoryCurrent)
	}
	if svc.NRestarts != 1 {
		t.Fatalf("restarts = %d, want 1", svc.NRestarts)
	}
	if svc.UptimeSeconds <= 0 {
		t.Fatalf("uptime = %d, want >0", svc.UptimeSeconds)
	}
}

func TestProbeSystemdTimer(t *testing.T) {
	stub := &stubCommandExecutor{responses: map[string]string{
		"systemctl show backup.timer --property=ActiveState,NextElapseUSecMonotonic,LastTriggerUSec,TriggeredBy,NextElapseRealtime": strings.Join([]string{
			"ActiveState=active",
			"NextElapseUSecMonotonic=1234567890",
			"LastTriggerUSec=1752000000000000",
			"TriggeredBy=backup.service",
			"NextElapseRealtime=2026-08-13 02:00:00 UTC",
		}, "\n"),
	}}
	svc := probeSystemdTimer(stub, "backup")
	if !svc.Active {
		t.Fatalf("timer not active: %+v", svc)
	}
	if svc.LastRun == "" {
		t.Fatalf("last run missing: %+v", svc)
	}
	// 1752000000000000 microseconds = 1752000000 seconds = 2025-07-08
	if !strings.Contains(svc.LastRun, "2025") {
		t.Fatalf("unexpected last run: %s", svc.LastRun)
	}
	if svc.SubType != "systemd-timer" {
		t.Fatalf("unexpected subtype: %+v", svc)
	}
}

func TestProbeProcess(t *testing.T) {
	// Skip on non-Linux (relies on /proc).
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("/proc not available")
	}
	// Use the current process by PID.
	svc := probeProcess(&stubCommandExecutor{}, "self")
	_ = svc // just ensure no panic; findProcessByComm("self") may not match
	// Probe by our own PID for reliable results.
	pid := os.Getpid()
	svc = probeProcess(&stubCommandExecutor{}, itoa(pid))
	if !svc.Active {
		t.Fatalf("self process should be active: %+v", svc)
	}
	if svc.LoadState != "loaded" {
		t.Fatalf("load state = %q, want loaded", svc.LoadState)
	}
	if svc.UptimeSeconds <= 0 {
		t.Fatalf("uptime = %d, want >0", svc.UptimeSeconds)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestProbeKVM(t *testing.T) {
	stub := &stubCommandExecutor{responses: map[string]string{
		"virsh domstate webserver": "running",
	}}
	svc := probeKVM(stub, "webserver")
	if !svc.Active || svc.Status != "running" {
		t.Fatalf("unexpected kvm state: %+v", svc)
	}
	if svc.SubType != "kvm" {
		t.Fatalf("subtype = %q, want kvm", svc.SubType)
	}
}

func TestProbeLXC(t *testing.T) {
	stub := &stubCommandExecutor{responses: map[string]string{
		"lxc-info -n app -s -H -p -H": "State: RUNNING\nPID: 1234",
	}}
	svc := probeLXC(stub, "app")
	if !svc.Active || svc.Status != "RUNNING" {
		t.Fatalf("unexpected lxc state: %+v", svc)
	}
}
