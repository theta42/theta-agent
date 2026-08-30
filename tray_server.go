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
	var listeners []net.Listener
	var boundPaths []string

	for _, p := range TraySocketPaths {
		os.Remove(p)
		os.MkdirAll(filepath.Dir(p), 0755) //nolint:errcheck
		l, err := net.Listen("unix", p)
		if err != nil {
			log.Printf("[tray-ipc] cannot listen on %s: %v", p, err)
			continue
		}
		if err := os.Chmod(p, 0666); err != nil { //nolint:errcheck
			log.Printf("[tray-ipc] cannot chmod %s: %v", p, err)
		}
		boundPaths = append(boundPaths, p)
		listeners = append(listeners, l)
	}

	if len(listeners) == 0 {
		log.Printf("[tray-ipc] cannot listen on any tray socket: tray icon disabled")
		return
	}

	log.Printf("[tray-ipc] listening on %v", boundPaths)

	// Accept on every bound listener. A goroutine per listener; each exits
	// when its listener errors (e.g. on Close).
	var wg sync.WaitGroup
	for _, l := range listeners {
		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				go ts.handleConn(conn)
			}
		}(l)
	}
	wg.Wait()
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
		ts.handleCommand(conn, cmd)
	}
}

// peerEuid lives in tray_peercred_linux.go (SO_PEERCRED) and
// tray_peercred_other.go (fallbacks).

// isPrivilegedAdminCommand reports whether a command modifies root daemon
// credentials or services (CLI operations). These require euid 0 (root).
// User-facing tray operations (set_auto_vpn, vpn_connect, vpn_disconnect, set_exit)
// are allowed from the interactive desktop user session.
func isPrivilegedAdminCommand(cmd string) bool {
	switch cmd {
	case "reinit", "register_service", "unregister_service":
		return true
	}
	return false
}

func (ts *trayServer) handleCommand(conn net.Conn, cmd TrayCommand) {
	if isPrivilegedAdminCommand(cmd.Command) && peerEuid(conn) != 0 {
		log.Printf("[tray-ipc] rejected %s: peer euid %d is not root", cmd.Command, peerEuid(conn))
		return
	}
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
		TriggerTrayStatusPush()
	case "vpn_connect":
		log.Printf("[tray-ipc] VPN connect requested")
		if err := defaultPlatformOps.ConnectWireGuard(); err != nil {
			log.Printf("[tray-ipc] VPN connect failed: %v", err)
		} else {
			SetVPNActive(true)
			TriggerTrayStatusPush()
		}
	case "vpn_disconnect":
		log.Printf("[tray-ipc] VPN disconnect requested")
		if err := defaultPlatformOps.DisconnectWireGuard(); err != nil {
			log.Printf("[tray-ipc] VPN disconnect failed: %v", err)
		} else {
			SetVPNActive(false)
			TriggerTrayStatusPush()
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
		TriggerTrayStatusPush()
	case "register_service", "unregister_service":
		// Sent by `theta-agent register/unregister` (the CLI), not the tray.
		// The CLI writes agent.yml itself and asks the daemon to push the
		// frame over its own stable WebSocket -- opening a second connection
		// from the CLI would supersede the daemon's (4002) and lose the
		// frame, which is exactly the race that made registration report
		// failure while actually succeeding via the telemetry fallback.
		if cmd.Service == "" {
			log.Printf("[tray-ipc] %s: missing service name", cmd.Command)
			return
		}
		if err := pushServiceFrame(cmd.Command, cmd.Service, cmd.Subtype); err != nil {
			log.Printf("[tray-ipc] %s %q failed: %v", cmd.Command, cmd.Service, err)
		}
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

// sendTrayCommand sends a single JSON command to the daemon from the tray
// process. A var so tests can stub it: the CLI's pushServiceRegistration uses
// it to hand register/unregister frames to the daemon, and the fallback path
// must be testable without a real socket.
//
// The daemon may listen on any of TraySocketPaths (M15), so try each in order
// and use the first that connects.
var sendTrayCommand = func(cmd TrayCommand) error {
	var lastErr error
	for _, p := range TraySocketPaths {
		conn, err := net.Dial("unix", p)
		if err != nil {
			lastErr = err
			continue
		}
		defer conn.Close()
		return json.NewEncoder(conn).Encode(cmd)
	}
	if lastErr != nil {
		return fmt.Errorf("cannot connect to daemon IPC socket: %w", lastErr)
	}
	return fmt.Errorf("no tray socket paths configured")
}

// receiveTrayStatus opens a persistent connection and calls cb on every status
// update. Blocks until the connection is lost. Call in a goroutine.
func receiveTrayStatus(cb func(TrayStatus)) error {
	var lastErr error
	for _, p := range TraySocketPaths {
		conn, err := net.Dial("unix", p)
		if err != nil {
			lastErr = err
			continue
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
	if lastErr != nil {
		return fmt.Errorf("cannot connect to daemon IPC socket: %w", lastErr)
	}
	return fmt.Errorf("no tray socket paths configured")
}
