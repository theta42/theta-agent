package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ldapTunnel is the agent's local LDAP socket (DESIGN.md §4). It is a pure byte
// pump: bytes from a local LDAP client (SSSD) are forwarded to the SSO over the
// WSS channel as `ldap_tunnel` messages, and the SSO's responses are written
// back to the socket. The agent never parses LDAP — it does not know or care
// what the bytes mean.
//
// Each local connection gets a conn_id. The agent reads the socket and sends
// chunks up; the SSO relays them into its real OpenLDAP and sends the response
// chunks back down; the agent writes them to the socket. `close:true` ends a
// connection.
type ldapTunnel struct {
	mu    sync.Mutex
	conns map[string]net.Conn
	send  func(WSMessage) error
}

func newLdapTunnel(send func(WSMessage) error) *ldapTunnel {
	return &ldapTunnel{
		conns: make(map[string]net.Conn),
		send:  send,
	}
}

// start binds the unix socket and accepts connections until stopCh closes.
func (t *ldapTunnel) start(socketPath string, stopCh <-chan struct{}) {
	// Remove a stale socket left over from a previous run, and make sure the
	// parent directory exists (e.g. /run/theta on a fresh boot).
	os.Remove(socketPath)
	if dir := filepath.Dir(socketPath); dir != "." && dir != "/" {
		os.MkdirAll(dir, 0755)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Printf("LDAP tunnel: cannot bind %s: %v", socketPath, err)
		return
	}
	// root:theta, 0660 — only root and the theta group can connect. A unix
	// socket is preferred over 127.0.0.1:389 because filesystem permissions
	// restrict which local processes can reach it.
	os.Chmod(socketPath, 0660)
	defer ln.Close()
	log.Printf("LDAP tunnel: listening on %s", socketPath)

	go func() {
		<-stopCh
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go t.handleConn(conn)
	}
}

// handleConn pumps one local LDAP connection up to the SSO.
func (t *ldapTunnel) handleConn(conn net.Conn) {
	connID := newConnID()
	t.mu.Lock()
	t.conns[connID] = conn
	t.mu.Unlock()

	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			msg := WSMessage{
				Type: "ldap_tunnel",
				Payload: map[string]interface{}{
					"conn_id": connID,
					"data":    base64.StdEncoding.EncodeToString(buf[:n]),
				},
			}
			if err := t.send(msg); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}

	// Signal end of connection to the SSO so it can close its OpenLDAP relay.
	t.send(WSMessage{
		Type: "ldap_tunnel",
		Payload: map[string]interface{}{
			"conn_id": connID,
			"close":   true,
		},
	})

	t.mu.Lock()
	delete(t.conns, connID)
	t.mu.Unlock()
	conn.Close()
}

// handleMessage writes SSO→agent tunnel bytes to the matching local socket.
// Called from handleCommand when an `ldap_tunnel` message arrives.
func (t *ldapTunnel) handleMessage(payload map[string]interface{}) {
	connID, _ := payload["conn_id"].(string)
	if connID == "" {
		return
	}

	if closeFlag, _ := payload["close"].(bool); closeFlag {
		t.mu.Lock()
		conn := t.conns[connID]
		delete(t.conns, connID)
		t.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		return
	}

	dataStr, _ := payload["data"].(string)
	if dataStr == "" {
		return
	}
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		return
	}

	t.mu.Lock()
	conn := t.conns[connID]
	t.mu.Unlock()
	if conn != nil {
		conn.Write(data)
	}
}

var connCounter uint64

func newConnID() string {
	connCounter++
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), connCounter)
}

// safeWriter serializes writes to the WebSocket. Gorilla allows only one
// concurrent writer, but the agent has several (telemetry, heartbeat, the LDAP
// tunnel, command responses) — without this, concurrent WriteMessage calls
// corrupt the stream.
type safeWriter struct {
	mu sync.Mutex
	c  *websocket.Conn
}

func (w *safeWriter) WriteMessage(messageType int, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.c.WriteMessage(messageType, data)
}

// sendTunnelMessage marshals a WSMessage and writes it as a text frame.
func sendTunnelMessage(w MessageWriter, msg WSMessage) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return w.WriteMessage(websocket.TextMessage, payload)
}
