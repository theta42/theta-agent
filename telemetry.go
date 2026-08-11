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
	"strings"
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
	CPUUsagePercent  float64      `json:"cpu_usage_percent"`
	CPUDetails       CPUDetails   `json:"cpu_details"`
	RAMUsagePercent  float64      `json:"ram_usage_percent"`
	RAMDetails       RAMDetails   `json:"ram_details"`
	DiskUsagePercent float64      `json:"disk_usage_percent"`
	Disks            []DiskItem   `json:"disks"`
	LoggedUsers      []LoggedUser `json:"logged_users"`
	HostDetails      HostDetails  `json:"host_details"`
	Version          string       `json:"version"`
	ZFSHealth        string       `json:"zfs_health,omitempty"`
	GPUUsage         float64      `json:"gpu_usage_percent,omitempty"`
	Timestamp        string       `json:"timestamp"`
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

const AgentVersion = "v2.4.0"

// CollectDiscoveryData gathers static host information.
func CollectDiscoveryData(cfg *Config) DiscoveryData {
	h, _ := host.Info()

	var ips []string
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}

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
		Hostname:     h.Hostname,
		IPs:          ips,
		PublicIP:     pubIP,
		OS:           fmt.Sprintf("%s %s", h.OS, h.Platform),
		Kernel:       h.KernelVersion,
		CPUModel:     cpuDet.Model,
		CPUDetails:   cpuDet,
		RAMTotalGB:   float64(vm.TotalBytes) / (1024 * 1024 * 1024),
		RAMDetails:   vm,
		DiskTotalGB:  diskTotalGB,
		Disks:        disks,
		LoggedUsers:  loggedUsers,
		HostDetails:  hostDet,
		Version:      AgentVersion,
		Location:     cfg.Location,
		Capabilities: map[string]interface{}{
			"telemetry":        cfg.Capabilities.Telemetry,
			"configure_ldap":   cfg.Capabilities.ConfigureLDAP,
			"ldap_tunnel":      cfg.Capabilities.LdapTunnel,
			"secrets":          cfg.Capabilities.Secrets,
			"iam":              cfg.Capabilities.IAM,
			"reboot":           cfg.Capabilities.Reboot,
			"shutdown":         true,
			"desktop_controls": true,
			"service_control":  cfg.Capabilities.ServiceControl,
			"arbitrary_bash":   cfg.Capabilities.ArbitraryBash,
		},
	}
}

// CollectTelemetryData gathers real-time performance metrics including ZFS and GPU.
func CollectTelemetryData(exec Executor) TelemetryData {
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
		Timestamp:        time.Now().Format(time.RFC3339),
	}
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
	cfg := cm.Get()

	// 1. Immediate Discovery Push & Initial Telemetry Frame
	pushDiscovery(c, cfg)
	pushTelemetry(c, exec)

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

				pushTelemetry(c, exec)
			}
		}
	}()
}

func pushTelemetry(c MessageWriter, exec Executor) {
	telemetry := CollectTelemetryData(exec)
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
			"timestamp":          telemetry.Timestamp,
		},
	})
	_ = c.WriteMessage(websocket.TextMessage, payload)
}

func collectIPs() []string {
	var ips []string
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
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
