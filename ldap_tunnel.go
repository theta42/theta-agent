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

// start binds both unix socket and TCP loopback, accepting connections until stopCh closes.
func (t *ldapTunnel) start(socketPath string, stopCh <-chan struct{}) {
	// 1. UNIX Domain Socket Listener. Windows passes an empty path and relies
	// on the TCP loopback listener below.
	if socketPath != "" {
		os.Remove(socketPath)
		if dir := filepath.Dir(socketPath); dir != "." && dir != "/" {
			os.MkdirAll(dir, 0755)
		}

		lnUnix, err := net.Listen("unix", socketPath)
		if err == nil {
			os.Chmod(socketPath, 0666)
			log.Printf("LDAP tunnel: listening on unix socket %s", socketPath)
			go t.acceptLoop(lnUnix, stopCh)
		} else {
			log.Printf("LDAP tunnel: cannot bind unix socket %s: %v", socketPath, err)
		}
	}

	// 2. TCP Loopback Listener (127.0.0.1:389 with fallback to 127.0.0.1:3890)
	lnTcp, errTcp := net.Listen("tcp", "127.0.0.1:389")
	if errTcp != nil {
		lnTcp, errTcp = net.Listen("tcp", "127.0.0.1:3890")
	}

	if errTcp == nil {
		log.Printf("LDAP tunnel: listening on tcp %s", lnTcp.Addr().String())
		go t.acceptLoop(lnTcp, stopCh)
	} else {
		log.Printf("LDAP tunnel: cannot bind tcp loopback: %v", errTcp)
	}
}

func (t *ldapTunnel) acceptLoop(ln net.Listener, stopCh <-chan struct{}) {
	defer ln.Close()
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
