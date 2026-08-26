package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

type CPUDetails struct {
	Model   string  `json:"model"`
	Cores   int     `json:"cores"`
	Threads int     `json:"threads"`
	MHz     float64 `json:"mhz"`
}

type RAMDetails struct {
	TotalBytes          uint64  `json:"total_bytes"`
	UsedBytes           uint64  `json:"used_bytes"`
	BuffersCacheBytes   uint64  `json:"buffers_cache_bytes"`
	FreeBytes           uint64  `json:"free_bytes"`
	UsedPercent         float64 `json:"used_percent"`
	BuffersCachePercent float64 `json:"buffers_cache_percent"`
	FreePercent         float64 `json:"free_percent"`
}

type DiskItem struct {
	Mountpoint   string  `json:"mountpoint"`
	Device       string  `json:"device"`
	FSType       string  `json:"fstype"`
	DriveType    string  `json:"drivetype"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	FreeBytes    uint64  `json:"free_bytes"`
	UsagePercent float64 `json:"usage_percent"`
}

type LoggedUser struct {
	User     string `json:"user"`
	Terminal string `json:"terminal"`
	Host     string `json:"host"`
	Started  int64  `json:"started"`
}

type HostDetails struct {
	StaticHostname  string `json:"static_hostname"`
	IconName        string `json:"icon_name"`
	Chassis         string `json:"chassis"`
	MachineID       string `json:"machine_id"`
	BootID          string `json:"boot_id"`
	OS              string `json:"os"`
	Kernel          string `json:"kernel"`
	Arch            string `json:"arch"`
	HardwareVendor  string `json:"hardware_vendor"`
	HardwareModel   string `json:"hardware_model"`
	FirmwareVersion string `json:"firmware_version"`
	FirmwareDate    string `json:"firmware_date"`
}

type DiscoveryData struct {
	Hostname     string                 `json:"hostname"`
	IPs          []string               `json:"ip_addresses"`
	PublicIP     string                 `json:"public_ip"`
	OS           string                 `json:"os"`
	Kernel       string                 `json:"kernel"`
	CPUModel     string                 `json:"cpu"`
	CPUDetails   CPUDetails             `json:"cpu_details"`
	RAMTotalGB   float64                `json:"ram_total_gb"`
	RAMDetails   RAMDetails             `json:"ram_details"`
	DiskTotalGB  float64                `json:"disk_total_gb"`
	Disks        []DiskItem             `json:"disks"`
	LoggedUsers  []LoggedUser           `json:"logged_users"`
	HostDetails  HostDetails            `json:"host_details"`
	Version      string                 `json:"version"`
	Location     string                 `json:"location"`
	Capabilities map[string]interface{} `json:"capabilities"`
}

type TelemetryData struct {
	CPUUsagePercent  float64         `json:"cpu_usage_percent"`
	CPUDetails       CPUDetails      `json:"cpu_details"`
	RAMUsagePercent  float64         `json:"ram_usage_percent"`
	RAMDetails       RAMDetails      `json:"ram_details"`
	DiskUsagePercent float64         `json:"disk_usage_percent"`
	Disks            []DiskItem      `json:"disks"`
	LoggedUsers      []LoggedUser    `json:"logged_users"`
	HostDetails      HostDetails     `json:"host_details"`
	Version          string          `json:"version"`
	ZFSHealth        string          `json:"zfs_health,omitempty"`
	GPUUsage         float64         `json:"gpu_usage_percent,omitempty"`
	Services         []ServiceMetric `json:"services,omitempty"`
	Timestamp        string          `json:"timestamp"`
}

// ServiceMetric is the per-service status and resource usage reported for each
// name in the `services:` list of agent.yml. The directory uses it to surface
// each registered systemd service as a child resource, its health, and its live
// CPU/RAM footprint.
//
// cpu_usage_percent is a rate derived by the agent from two consecutive
// `systemctl show` CPUUsageNS samples (a raw counter has no meaning without a
// window). It is -1 until a second sample is available.
type ServiceMetric struct {
	Name            string  `json:"name"`
	Active          bool    `json:"active"`
	SubState        string  `json:"substate,omitempty"`
	LoadState       string  `json:"load_state,omitempty"`
	SubType         string  `json:"subtype,omitempty"`
	CPUUsagePercent float64 `json:"cpu_usage_percent,omitempty"`
	CPUUsageNS      int64   `json:"cpu_ns,omitempty"`
	MemoryCurrent   uint64  `json:"memory_bytes,omitempty"`
	NRestarts       uint64  `json:"n_restarts,omitempty"`
	UptimeSeconds   int64   `json:"uptime_seconds,omitempty"`
	// Schedule semantics used by systemd-timer and cron subtypes.
	NextRun   string `json:"next_run,omitempty"` // RFC3339, when next scheduled
	LastRun   string `json:"last_run,omitempty"` // RFC3339, when last ran
	Triggered uint64 `json:"triggered_count,omitempty"`
	// VM semantics used by lxc/kvm/libvirt subtypes.
	Status string `json:"status,omitempty"`
}

func getPublicIP() string {
	client := &http.Client{Timeout: 3 * time.Second}
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	for _, ep := range endpoints {
		resp, err := client.Get(ep)
		if err == nil && resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				ip := strings.TrimSpace(string(body))
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
	}
	return ""
}

func collectCPUDetails() CPUDetails {
	cpuInfo, _ := cpu.Info()
	model := "Unknown"
	cores := 0
	mhz := 0.0
	if len(cpuInfo) > 0 {
		model = cpuInfo[0].ModelName
		if model == "" || strings.TrimSpace(model) == "154" || len(model) < 4 {
			if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(line, "model name") {
						parts := strings.Split(line, ":")
						if len(parts) > 1 {
							model = strings.TrimSpace(parts[1])
							break
						}
					}
				}
			}
		}
		if model == "" {
			model = cpuInfo[0].Model
		}
		cores = int(cpuInfo[0].Cores)
		mhz = cpuInfo[0].Mhz
	}
	threads := runtime.NumCPU()
	if t, err := cpu.Counts(true); err == nil && t > 0 {
		threads = t
	}
	if cores <= 0 {
		if c, err := cpu.Counts(false); err == nil && c > 0 {
			cores = c
		} else {
			cores = threads
		}
	}
	return CPUDetails{
		Model:   model,
		Cores:   cores,
		Threads: threads,
		MHz:     mhz,
	}
}

func collectRAMDetails() RAMDetails {
	vm, err := mem.VirtualMemory()
	if err != nil || vm == nil {
		return RAMDetails{}
	}
	bufCache := vm.Buffers + vm.Cached
	total := float64(vm.Total)
	usedPct := 0.0
	bufPct := 0.0
	freePct := 0.0
	if total > 0 {
		usedPct = (float64(vm.Used) / total) * 100.0
		bufPct = (float64(bufCache) / total) * 100.0
		freePct = (float64(vm.Free) / total) * 100.0
	}
	return RAMDetails{
		TotalBytes:          vm.Total,
		UsedBytes:           vm.Used,
		BuffersCacheBytes:   bufCache,
		FreeBytes:           vm.Free,
		UsedPercent:         usedPct,
		BuffersCachePercent: bufPct,
		FreePercent:         freePct,
	}
}

func getDriveType(device string) string {
	devName := filepath.Base(device)
	devName = strings.TrimRight(devName, "0123456789p")
	if strings.HasPrefix(devName, "nvme") {
		return "NVMe"
	}
	rotPath := filepath.Join("/sys/block", devName, "queue/rotational")
	data, err := os.ReadFile(rotPath)
	if err == nil {
		val := strings.TrimSpace(string(data))
		if val == "0" {
			return "SSD"
		} else if val == "1" {
			return "HDD"
		}
	}
	return "SSD/HDD"
}

func collectHostDetails() HostDetails {
	details := HostDetails{}
	exec := SystemExecutor{}
	out, err := exec.Execute("hostnamectl")
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				switch key {
				case "Static hostname":
					details.StaticHostname = val
				case "Icon name":
					details.IconName = val
				case "Chassis":
					details.Chassis = val
				case "Machine ID":
					details.MachineID = val
				case "Boot ID":
					details.BootID = val
				case "Operating System":
					details.OS = val
				case "Kernel":
					details.Kernel = val
				case "Architecture":
					details.Arch = val
				case "Hardware Vendor":
					details.HardwareVendor = val
				case "Hardware Model":
					details.HardwareModel = val
				case "Firmware Version":
					details.FirmwareVersion = val
				case "Firmware Date":
					details.FirmwareDate = val
				}
			}
		}
	}
	if details.HardwareVendor == "" {
		if d, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
			details.HardwareVendor = strings.TrimSpace(string(d))
		}
	}
	if details.HardwareModel == "" {
		if d, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
			details.HardwareModel = strings.TrimSpace(string(d))
		}
	}
	if details.FirmwareVersion == "" {
		if d, err := os.ReadFile("/sys/class/dmi/id/bios_version"); err == nil {
			details.FirmwareVersion = strings.TrimSpace(string(d))
		}
	}
	if details.FirmwareDate == "" {
		if d, err := os.ReadFile("/sys/class/dmi/id/bios_date"); err == nil {
			details.FirmwareDate = strings.TrimSpace(string(d))
		}
	}
	return details
}

const AgentVersion = "v2.16.0"

// CollectDiscoveryData gathers static host information.
func CollectDiscoveryData(cfg *Config) DiscoveryData {
	h, _ := host.Info()

	ips := collectIPs()

	vm := collectRAMDetails()
	disks := collectDiskItems()
	cpuDet := collectCPUDetails()
	loggedUsers := collectLoggedUsers()

	pubIP := ""
	if cfg.DetectPublicIP() {
		pubIP = getPublicIP()
	}

	diskTotalGB := 0.0
	for _, d := range disks {
		if d.Mountpoint == "/" {
			diskTotalGB = float64(d.TotalBytes) / (1024 * 1024 * 1024)
			break
		}
	}
	if diskTotalGB == 0 && len(disks) > 0 {
		diskTotalGB = float64(disks[0].TotalBytes) / (1024 * 1024 * 1024)
	}

	hostDet := collectHostDetails()

	return DiscoveryData{
		Hostname:    h.Hostname,
		IPs:         ips,
		PublicIP:    pubIP,
		OS:          fmt.Sprintf("%s %s", h.OS, h.Platform),
		Kernel:      h.KernelVersion,
		CPUModel:    cpuDet.Model,
		CPUDetails:  cpuDet,
		RAMTotalGB:  float64(vm.TotalBytes) / (1024 * 1024 * 1024),
		RAMDetails:  vm,
		DiskTotalGB: diskTotalGB,
		Disks:       disks,
		LoggedUsers: loggedUsers,
		HostDetails: hostDet,
		Version:     AgentVersion,
		Location:    cfg.Location,
		Capabilities: map[string]interface{}{
			"telemetry":            cfg.Capabilities.Telemetry,
			"configure_ldap":       cfg.Capabilities.ConfigureLDAP,
			"ldap_tunnel":          cfg.Capabilities.LdapTunnel,
			"secrets":              cfg.Capabilities.Secrets,
			"iam":                  cfg.Capabilities.IAM,
			"reboot":               cfg.Capabilities.Reboot,
			"shutdown":             true,
			"desktop_controls":     true,
			"service_control":      cfg.Capabilities.ServiceControl,
			"service_registration": cfg.Capabilities.ServiceRegistration,
			"arbitrary_bash":       cfg.Capabilities.ArbitraryBash,
			"wireguard":            cfg.Capabilities.WireGuardEnabled(),
			// Enabled is a policy setting; ready is whether wg-quick is
			// actually installed. They came apart silently before: a host
			// could be enrolled in the mesh, with a peer at the gateway, and
			// still have no way to bring the interface up.
			"wireguard_ready": WireGuardToolsReady(),
		},
	}
}

// CollectTelemetryData gathers real-time performance metrics including ZFS and GPU.
func CollectTelemetryData(exec Executor, services []RegisteredService) TelemetryData {
	cpuPerc, _ := cpu.Percent(time.Second, false)
	vm := collectRAMDetails()
	disks := collectDiskItems()
	cpuDet := collectCPUDetails()
	loggedUsers := collectLoggedUsers()
	hostDet := collectHostDetails()

	cpuVal := 0.0
	if len(cpuPerc) > 0 {
		cpuVal = cpuPerc[0]
	}

	diskVal := 0.0
	for _, d := range disks {
		if d.Mountpoint == "/" {
			diskVal = d.UsagePercent
			break
		}
	}
	if diskVal == 0 && len(disks) > 0 {
		diskVal = disks[0].UsagePercent
	}

	return TelemetryData{
		CPUUsagePercent:  cpuVal,
		CPUDetails:       cpuDet,
		RAMUsagePercent:  vm.UsedPercent,
		RAMDetails:       vm,
		DiskUsagePercent: diskVal,
		Disks:            disks,
		LoggedUsers:      loggedUsers,
		HostDetails:      hostDet,
		Version:          AgentVersion,
		ZFSHealth:        collectZFSHealth(exec),
		GPUUsage:         collectGPUUsage(exec),
		Services:         collectServiceMetrics(exec, services),
		Timestamp:        time.Now().Format(time.RFC3339),
	}
}

// collectServiceMetrics probes each registered service and reports its status
// plus resource usage. Dispatch is per subtype. A probe failure (service
// removed, tool error) reports the service as inactive.
func collectServiceMetrics(exec Executor, services []RegisteredService) []ServiceMetric {
	if len(services) == 0 {
		return nil
	}
	metrics := make([]ServiceMetric, 0, len(services))
	for _, rs := range services {
		if rs.Name == "" {
			continue
		}
		metrics = append(metrics, probeRegistered(exec, rs))
	}
	return metrics
}

// probeRegistered dispatches to the right probe for a registered service's
// subtype.
func probeRegistered(exec Executor, rs RegisteredService) ServiceMetric {
	switch rs.SubTypeOr("systemd") {
	case "docker":
		return probeDockerContainer(exec, rs.Name)
	case "podman":
		return probePodmanContainer(exec, rs.Name)
	case "process":
		return probeProcess(exec, rs.Name)
	case "systemd-timer":
		return probeSystemdTimer(exec, rs.Name)
	case "cron":
		return probeCron(exec, rs.Name)
	case "lxc":
		return probeLXC(exec, rs.Name)
	case "kvm", "libvirt":
		return probeKVM(exec, rs.Name)
	default: // systemd
		return probeService(exec, rs.Name)
	}
}

// probeService collects one service's status + resource usage via
// `systemctl show <name> --property=...`. The CPU percentage is a per-tick rate
// computed against the previous sample (see cpuNSCache).
func probeService(exec Executor, name string) ServiceMetric {
	svc := ServiceMetric{Name: name}

	out, err := exec.Execute("systemctl", "show", name, "--property="+systemdStatusFields)
	if err != nil {
		// Service unknown/removed. systemctl show exits non-zero; treat as
		// inactive and don't cache a stale CPU base.
		svc.Active = false
		svc.SubState = "dead"
		svc.LoadState = "not-found"
		return svc
	}

	parsed := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		parsed[key] = val
	}

	svc.Active = parsed["ActiveState"] == "active"
	svc.SubState = parsed["SubState"]
	svc.LoadState = parsed["LoadState"]

	if v, ok := parsed["MemoryCurrent"]; ok && v != "[not set]" {
		if n, perr := strconv.ParseUint(v, 10, 64); perr == nil {
			svc.MemoryCurrent = n
		}
	}
	if v, ok := parsed["NRestarts"]; ok {
		if n, perr := strconv.ParseUint(v, 10, 64); perr == nil {
			svc.NRestarts = n
		}
	}
	if v, ok := parsed["CPUUsageNS"]; ok && v != "[not set]" {
		if n, perr := strconv.ParseInt(v, 10, 64); perr == nil {
			svc.CPUUsageNS = n
			svc.CPUUsagePercent = cpuRateFor(name, n)
		}
	}
	if ts, ok := parsed["ActiveEnterTimestamp"]; ok && ts != "" {
		if t, terr := parseSystemdTimestamp(ts); terr == nil {
			uptime := time.Since(t)
			if uptime > 0 {
				svc.UptimeSeconds = int64(uptime.Seconds())
			}
		}
	}
	return svc
}

// cpuNSCache remembers the previous CPUUsageNS sample per service so the agent
// can compute a CPU-per-second rate between two telemetry ticks (30s apart).
// Guarded so concurrent telemetry loops cannot race.
var (
	cpuNSCacheMu sync.Mutex
	cpuNSCache   = map[string]int64{}
)

// cpuRateFor computes a CPU percentage from two CPUUsageNS samples and caches
// the latest one. Returns -1 until two samples exist.
func cpuRateFor(name string, currentNS int64) float64 {
	if currentNS < 0 {
		return -1
	}
	cpuNSCacheMu.Lock()
	defer cpuNSCacheMu.Unlock()
	prev, ok := cpuNSCache[name]
	cpuNSCache[name] = currentNS
	if !ok || currentNS < prev {
		// First sample, or the counter reset (service restarted): no rate yet.
		return -1
	}
	// The sampling window is the wall time between ticks. We don't track the
	// previous wall clock here, so approximate with a 30s window. This keeps
	// the collector stateless per call and close enough for telemetry.
	const windowSeconds = 30.0
	deltaNS := currentNS - prev
	return (float64(deltaNS) / float64(windowSeconds*1e9)) * 100.0
}

// parseSystemdTimestamp parses a systemd timestamp of the form
// "Wed 2026-08-12 14:03:22 UTC".
func parseSystemdTimestamp(s string) (time.Time, error) {
	return time.Parse("Mon 2006-01-02 15:04:05 MST", s)
}

// systemdStatusFields lists the systemctl show properties used by probeService,
// kept in one place for tests.
const systemdStatusFields = "ActiveState,SubState,LoadState,CPUUsageNS,MemoryCurrent,NRestarts,ActiveEnterTimestamp"

// probeDockerContainer collects one container's status + resource usage. CPU and
// memory come from a single `docker stats --no-stream` row (a live snapshot);
// restart count and uptime come from `docker inspect`. A missing container
// reports inactive.
func probeDockerContainer(exec Executor, name string) ServiceMetric {
	svc := ServiceMetric{Name: name, SubType: "docker", LoadState: "not-found"}

	// Inspect gives state, restarts and started time in one call.
	out, err := exec.Execute("docker", "inspect", name, "--format", "{{.State.Running}}|{{.State.Status}}|{{.RestartCount}}|{{.State.StartedAt}}")
	if err != nil {
		return svc // container not found -> inactive
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

	// Live CPU% and memory from a single --no-stream stats snapshot.
	stats, serr := exec.Execute("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", name)
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
	return svc
}

// parsePercent parses a value like "2.35%" into a float percent, or -1 on
// failure.
func parsePercent(s string) float64 {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "%")
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1
	}
	return f
}

// parseMemUsage parses docker stats MemUsage values like "1.234MiB / 7.8GiB"
// into the first (used) quantity in bytes. Returns 0 on failure.
func parseMemUsage(s string) uint64 {
	used := strings.SplitN(s, "/", 2)[0]
	used = strings.TrimSpace(used)
	return parseSizeBytes(used)
}

// parseSizeBytes parses a docker/human size like "1.5GiB" or "512MiB" or
// "1.2kB" into bytes. Supports B, KB/kB, MB/MiB, GB/GiB, TB/TiB suffixes.
func parseSizeBytes(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := 1.0
	upper := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(upper, "TIB"):
		mult, s = 1<<40, strings.TrimSpace(s[:len(s)-3])
	case strings.HasSuffix(upper, "GIB"):
		mult, s = 1<<30, strings.TrimSpace(s[:len(s)-3])
	case strings.HasSuffix(upper, "MIB"):
		mult, s = 1<<20, strings.TrimSpace(s[:len(s)-3])
	case strings.HasSuffix(upper, "KIB"):
		mult, s = 1<<10, strings.TrimSpace(s[:len(s)-3])
	case strings.HasSuffix(upper, "TB"):
		mult, s = 1e12, strings.TrimSpace(s[:len(s)-2])
	case strings.HasSuffix(upper, "GB"):
		mult, s = 1e9, strings.TrimSpace(s[:len(s)-2])
	case strings.HasSuffix(upper, "MB"):
		mult, s = 1e6, strings.TrimSpace(s[:len(s)-2])
	case strings.HasSuffix(upper, "KB"):
		mult, s = 1e3, strings.TrimSpace(s[:len(s)-2])
	case strings.HasSuffix(upper, "B"):
		mult, s = 1, strings.TrimSpace(s[:len(s)-1])
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return uint64(f * mult)
}

func collectZFSHealth(exec Executor) string {
	out, err := exec.Execute("zpool", "list", "-H", "-o", "health")
	if err != nil {
		return "unknown"
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 0 {
		return lines[0]
	}
	return "unknown"
}

func collectGPUUsage(exec Executor) float64 {
	out, err := exec.Execute("nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits")
	if err != nil {
		return -1.0
	}
	var usage float64
	fmt.Sscanf(strings.TrimSpace(string(out)), "%f", &usage)
	return usage
}

// StartTelemetryLoop manages the initial discovery push and the periodic telemetry stream.
func StartTelemetryLoop(c MessageWriter, cm *ConfigManager, exec Executor, stopCh <-chan struct{}) {
	// Establish the on-disk baseline before the first tick, so the first
	// ReloadIfChanged reports a real edit rather than "the file exists".
	_, _ = cm.ReloadIfChanged()
	cfg := cm.Get()

	// 1. Immediate Discovery Push & Initial Telemetry Frame
	pushDiscovery(c, cfg)
	pushTelemetry(c, exec, cfg.Services)

	// If telemetry capability is disabled in agent.yml, return early after discovery
	if !cfg.Capabilities.Telemetry {
		log.Println("Telemetry capability is disabled in agent.yml; skipping telemetry stream.")
		return
	}

	// 2. Periodic Telemetry Stream
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		var lastIPs []string
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				// Pick up agent.yml edits made by another process. `theta-agent
				// register` writes the file and notifies the Directory from its
				// own short-lived process; without this the daemon kept
				// reporting the service list it started with, so a
				// just-registered service produced a resource in the Directory
				// that never received a single status sample.
				if changed, rerr := cm.ReloadIfChanged(); rerr != nil {
					log.Printf("[config] could not reload %s: %v", cm.configPath, rerr)
				} else if changed {
					log.Println("[config] agent.yml changed on disk -- reloaded")
				}
				currentCFG := cm.Get()
				if !currentCFG.Capabilities.Telemetry {
					continue
				}

				// Network Change Detection
				currentIPs := collectIPs()
				if !equalSlices(lastIPs, currentIPs) {
					log.Println("Network change detected. Pushing discovery update...")
					pushDiscovery(c, currentCFG)
					lastIPs = currentIPs
				}

				pushTelemetry(c, exec, currentCFG.Services)
			}
		}
	}()
}

func pushTelemetry(c MessageWriter, exec Executor, services []RegisteredService) {
	telemetry := CollectTelemetryData(exec, services)
	payload, _ := json.Marshal(WSMessage{
		Type: "telemetry",
		Payload: map[string]interface{}{
			"cpu_usage_percent":  telemetry.CPUUsagePercent,
			"cpu_details":        telemetry.CPUDetails,
			"ram_usage_percent":  telemetry.RAMUsagePercent,
			"ram_details":        telemetry.RAMDetails,
			"disk_usage_percent": telemetry.DiskUsagePercent,
			"disks":              telemetry.Disks,
			"logged_users":       telemetry.LoggedUsers,
			"host_details":       telemetry.HostDetails,
			"zfs_health":         telemetry.ZFSHealth,
			"gpu_usage_percent":  telemetry.GPUUsage,
			"services":           telemetry.Services,
			"timestamp":          telemetry.Timestamp,
		},
	})
	_ = c.WriteMessage(websocket.TextMessage, payload)
}

// virtualInterfacePrefixes are container/VM bridge and veth interfaces that
// never represent how another machine reaches this host. Without this
// filter, net.InterfaceAddrs() mixes docker0/br-*'s bridge-gateway address
// in with the real LAN IP with no ordering guarantee, and the directory
// (which just takes ip_addresses[0]) can end up displaying an unreachable
// 172.17/172.18.x.x Docker bridge address instead of the host's real IP.
var virtualInterfacePrefixes = []string{
	"docker", "br-", "veth", "cni", "flannel", "virbr", "podman", "tun", "tap", "lxcbr", "vnet",
}

func isVirtualInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range virtualInterfacePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// collectIPs returns this host's non-loopback IPv4 addresses, skipping
// container/VM bridge interfaces (see isVirtualInterfaceName) so the
// directory never sees an internal Docker/Podman bridge IP where it expects
// the host's real, reachable address.
func collectIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		if isVirtualInterfaceName(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}
	return ips
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func pushDiscovery(c MessageWriter, cfg *Config) {
	discovery := CollectDiscoveryData(cfg)
	discoveryPayload, _ := json.Marshal(discovery)

	var discoveryMap map[string]interface{}
	json.Unmarshal(discoveryPayload, &discoveryMap)

	msg := WSMessage{
		Type:    "discovery",
		Payload: discoveryMap,
	}

	payload, _ := json.Marshal(msg)
	if err := c.WriteMessage(websocket.TextMessage, payload); err != nil {
		log.Printf("Failed to send discovery data: %v", err)
	} else {
		log.Println("Discovery data pushed to Theta Directory.")
	}
}
