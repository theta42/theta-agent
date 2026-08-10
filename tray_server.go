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
	"strings"
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
		log.Printf("[tray-ipc] auto_vpn set to %v", cmd.Value)
		// TODO: persist to agent.yml
	case "vpn_connect":
		log.Printf("[tray-ipc] VPN connect requested")
		// TODO: invoke WireGuard connect
	case "vpn_disconnect":
		log.Printf("[tray-ipc] VPN disconnect requested")
		// TODO: invoke WireGuard disconnect
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
func UpdateTrayStatus(connected bool, agentPublicIP, homePublicIP string, vpnActive, autoVPN bool, siteName, serverURL string) {
	color := ColorRed
	statusText := "Not connected to directory"
	isHome := false

	if connected {
		// Server URL is local (localhost, 127.0.0.1, LAN IP, or .local)
		isLocalServer := strings.Contains(serverURL, "localhost") ||
			strings.Contains(serverURL, "127.0.0.1") ||
			strings.Contains(serverURL, ".local") ||
			strings.Contains(serverURL, "192.168.") ||
			strings.Contains(serverURL, "10.")

		// On Home LAN if:
		// 1) Both agent & home public IPs are known and match, OR
		// 2) Connecting to a local/LAN SSO server, OR
		// 3) homePublicIP is not yet set by directory (default to local home)
		if (homePublicIP != "" && agentPublicIP != "" && agentPublicIP == homePublicIP) || isLocalServer || homePublicIP == "" {
			isHome = true
		}

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

	globalTrayServer.Push(TrayStatus{
		Color:         color,
		Connected:     connected,
		IsHome:        isHome,
		VPNActive:     vpnActive,
		AutoVPN:       autoVPN,
		SiteName:      siteName,
		AgentPublicIP: agentPublicIP,
		HomePublicIP:  homePublicIP,
		StatusText:    statusText,
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
