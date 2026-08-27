package main

// Tray IPC server — runs inside the root daemon.
//
// Listens on /run/theta/tray.sock. Whenever the tray connects, it immediately
// gets the current status and then receives a push on every state change.
// Commands from the tray (auto-VPN toggle, connect/disconnect) come back over
// the same connection.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
)

type trayServer struct {
	mu      sync.RWMutex
	status  TrayStatus
	clients map[net.Conn]struct{}
}

var globalTrayServer = &trayServer{
	clients: make(map[net.Conn]struct{}),
}

// Start begins listening on the tray socket. Call from main() as a goroutine.
func (ts *trayServer) Start() {
	var l net.Listener
	var boundPath string
	var err error

	for _, p := range TraySocketPaths {
		os.Remove(p)
		os.MkdirAll(filepath.Dir(p), 0755) //nolint:errcheck
		l, err = net.Listen("unix", p)
		if err == nil {
			boundPath = p
			os.Chmod(p, 0666) //nolint:errcheck
			break
		}
	}

	if err != nil || boundPath == "" {
		log.Printf("[tray-ipc] cannot listen on tray socket: %v (tray icon disabled)", err)
		return
	}

	log.Printf("[tray-ipc] listening on %s", boundPath)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("[tray-ipc] accept error: %v", err)
			return
		}
		go ts.handleConn(conn)
	}
}

func (ts *trayServer) handleConn(conn net.Conn) {
	ts.mu.Lock()
	ts.clients[conn] = struct{}{}
	// Send current status immediately on connect.
	b, _ := encodeTrayStatus(ts.status)
	conn.Write(b) //nolint:errcheck
	ts.mu.Unlock()

	defer func() {
		ts.mu.Lock()
		delete(ts.clients, conn)
		ts.mu.Unlock()
		conn.Close()
	}()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Bytes()
		cmd, err := decodeTrayCommand(line)
		if err != nil {
			continue
		}
		ts.handleCommand(cmd)
	}
}

func (ts *trayServer) handleCommand(cmd TrayCommand) {
	switch cmd.Command {
	case "set_auto_vpn":
		ts.mu.Lock()
		ts.status.AutoVPN = cmd.Value
		ts.mu.Unlock()
		SetAutoVPN(cmd.Value)
		if currentCM != nil {
			if err := currentCM.PersistAutoVPN(cmd.Value); err != nil {
				log.Printf("[tray-ipc] could not persist auto_vpn: %v", err)
			}
		}
		log.Printf("[tray-ipc] auto_vpn set to %v", cmd.Value)
	case "vpn_connect":
		log.Printf("[tray-ipc] VPN connect requested")
		if err := defaultPlatformOps.ConnectWireGuard(); err != nil {
			log.Printf("[tray-ipc] VPN connect failed: %v", err)
		}
	case "vpn_disconnect":
		log.Printf("[tray-ipc] VPN disconnect requested")
		if err := defaultPlatformOps.DisconnectWireGuard(); err != nil {
			log.Printf("[tray-ipc] VPN disconnect failed: %v", err)
		}
	case "reinit":
		log.Printf("[tray-ipc] clearing enrollment (re-enroll requested)")
		if currentCM != nil {
			if err := currentCM.ClearEnrollment(); err != nil {
				log.Printf("[tray-ipc] could not clear enrollment: %v", err)
			}
		}
	case "set_exit":
		// The tray only ever steers its OWN device: the daemon calls the
		// agent-scoped endpoint with its own credential, so there is no device
		// id on the wire that could name someone else's host.
		where := "local breakout"
		if cmd.SiteID != nil {
			where = fmt.Sprintf("site %d", *cmd.SiteID)
		}
		log.Printf("[tray-ipc] routing this device through %s", where)
		if currentCM == nil {
			log.Printf("[tray-ipc] cannot set exit: no config loaded")
			break
		}
		cfg := currentCM.Get()
		if err := setMeshExit(cfg, cmd.SiteID); err != nil {
			log.Printf("[tray-ipc] could not set exit: %v", err)
			break
		}
		// Refresh so the tray's checkmark reflects what the directory now
		// holds, rather than what we optimistically assumed.
		refreshMeshExits(cfg)
	case "open_config":
		// Kept only for trays older than the ConfigPath field. This process
		// cannot open a window: on Linux it is a root systemd service with no
		// DISPLAY or session bus, and on Windows a SYSTEM service in session 0,
		// which is isolated from the interactive desktop. Current trays open
		// the file themselves from TrayStatus.ConfigPath.
		log.Printf("[tray-ipc] open_config from a legacy tray; the daemon cannot "+
			"open a window from a service context. Config is at %s -- upgrade the "+
			"tray to open it from the desktop session.", defaultConfigPath())
	default:
		log.Printf("[tray-ipc] unknown command: %q", cmd.Command)
	}
}

// Push broadcasts an updated status to all connected tray clients.
func (ts *trayServer) Push(status TrayStatus) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.status = status
	if len(ts.clients) == 0 {
		return
	}
	b, err := encodeTrayStatus(status)
	if err != nil {
		return
	}
	for conn := range ts.clients {
		_, err := conn.Write(b)
		if err != nil {
			// Dead connection; handleConn will clean it up.
			conn.Close()
		}
	}
}

// UpdateTrayStatus computes the current TrayColor from the known state
// and pushes it to all connected tray clients.
// UpdateTrayStatus pushes the current state to the tray.
//
// isHome is computed by the caller (home_detect.checkAndPush) rather than
// re-derived here. This function used to carry its own copy of the rule --
// including the `|| homePublicIP == ""` clause that made every agent report
// "Home" forever, since nothing ever supplied a home public IP -- so the icon
// and the auto-VPN decision could disagree about the same moment.
func UpdateTrayStatus(connected, isHome bool, agentPublicIP, homePublicIP string, vpnActive, autoVPN bool, siteName string) {
	color := ColorRed
	statusText := "Not connected to directory"

	if connected {
		if vpnActive {
			color = ColorBlue
			statusText = fmt.Sprintf("VPN active → %s", siteName)
		} else if isHome {
			color = ColorGreen
			statusText = fmt.Sprintf("Home — %s", siteName)
		} else {
			color = ColorYellow
			statusText = "Connected (away from home)"
		}
	}

	exits, currentExit := MeshExits()

	globalTrayServer.Push(TrayStatus{
		Color:            color,
		Connected:        connected,
		IsHome:           isHome,
		VPNActive:        vpnActive,
		AutoVPN:          autoVPN,
		SiteName:         siteName,
		AgentPublicIP:    agentPublicIP,
		HomePublicIP:     homePublicIP,
		OrganizationName: organizationName(),
		StatusText:       statusText,
		ConfigPath:       defaultConfigPath(),

		Exits:             exits,
		CurrentExitSiteID: currentExit,
	})
}

// sendTrayCommand sends a single JSON command to the daemon from the tray process.
func sendTrayCommand(cmd TrayCommand) error {
	conn, err := net.Dial("unix", TraySocket)
	if err != nil {
		return fmt.Errorf("cannot connect to daemon IPC socket: %w", err)
	}
	defer conn.Close()
	return json.NewEncoder(conn).Encode(cmd)
}

// receiveTrayStatus opens a persistent connection and calls cb on every status
// update. Blocks until the connection is lost. Call in a goroutine.
func receiveTrayStatus(cb func(TrayStatus)) error {
	conn, err := net.Dial("unix", TraySocket)
	if err != nil {
		return fmt.Errorf("cannot connect to daemon IPC socket: %w", err)
	}
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		s, err := decodeTrayStatus(scanner.Bytes())
		if err == nil {
			cb(s)
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}
