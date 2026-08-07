package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

type DiscoveryData struct {
	Hostname     string                 `json:"hostname"`
	IPs          []string               `json:"ip_addresses"`
	OS           string                 `json:"os"`
	Kernel       string                 `json:"kernel"`
	CPUModel     string                 `json:"cpu"`
	RAMTotalGB   float64                `json:"ram_total_gb"`
	DiskTotalGB  float64                `json:"disk_total_gb"`
	Location     string                 `json:"location"`
	Capabilities map[string]interface{} `json:"capabilities"`
}

type TelemetryData struct {
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	RAMUsagePercent float64 `json:"ram_usage_percent"`
	DiskUsagePercent float64 `json:"disk_usage_percent"`
	ZFSHealth       string  `json:"zfs_health,omitempty"`
	GPUUsage        float64  `json:"gpu_usage_percent,omitempty"`
	Timestamp       string  `json:"timestamp"`
}

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

	vm, _ := mem.VirtualMemory()
	d, _ := disk.Usage("/")

	cpuInfo, _ := cpu.Info()
	cpuModel := "Unknown"
	if len(cpuInfo) > 0 {
		cpuModel = cpuInfo[0].Model
	}

	return DiscoveryData{
		Hostname:    h.Hostname,
		IPs:         ips,
		OS:          fmt.Sprintf("%s %s", h.OS, h.Platform),
		Kernel:      h.KernelVersion,
		CPUModel:    cpuModel,
		RAMTotalGB:  float64(vm.Total) / (1024 * 1024 * 1024),
		DiskTotalGB: float64(d.Total) / (1024 * 1024 * 1024),
		Location:    cfg.Location,
		Capabilities: map[string]interface{}{
			"telemetry":       cfg.Capabilities.Telemetry,
			"configure_ldap":  cfg.Capabilities.ConfigureLDAP,
			"ldap_tunnel":     cfg.Capabilities.LdapTunnel,
			"secrets":         cfg.Capabilities.Secrets,
			"iam":             cfg.Capabilities.IAM,
			"reboot":          cfg.Capabilities.Reboot,
			"service_control": cfg.Capabilities.ServiceControl,
			"arbitrary_bash":  cfg.Capabilities.ArbitraryBash,
		},
	}
}

// CollectTelemetryData gathers real-time performance metrics including ZFS and GPU.
func CollectTelemetryData(exec Executor) TelemetryData {
	cpuPerc, _ := cpu.Percent(time.Second, false)
	vm, _ := mem.VirtualMemory()
	d, _ := disk.Usage("/")

	cpuVal := 0.0
	if len(cpuPerc) > 0 {
		cpuVal = cpuPerc[0]
	}

	return TelemetryData{
		CPUUsagePercent:  cpuVal,
		RAMUsagePercent:  vm.UsedPercent,
		DiskUsagePercent: d.UsedPercent,
		ZFSHealth:       collectZFSHealth(exec),
		GPUUsage:        collectGPUUsage(exec),
		Timestamp:       time.Now().Format(time.RFC3339),
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

	// 1. Immediate Discovery Push
	pushDiscovery(c, cfg)

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

				telemetry := CollectTelemetryData(exec)
				payload, _ := json.Marshal(WSMessage{
					Type: "telemetry",
					Payload: map[string]interface{}{
						"cpu_usage_percent":  telemetry.CPUUsagePercent,
						"ram_usage_percent":  telemetry.RAMUsagePercent,
						"disk_usage_percent": telemetry.DiskUsagePercent,
						"zfs_health":         telemetry.ZFSHealth,
						"gpu_usage_percent":   telemetry.GPUUsage,
						"timestamp":          telemetry.Timestamp,
					},
				})
				if err := c.WriteMessage(websocket.TextMessage, payload); err != nil {
					log.Printf("Failed to stream telemetry: %v", err)
					return
				}
			}
		}
	}()
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
		log.Println("Discovery data pushed to SSO Manager.")
	}
}
