package main

import (
	"encoding/base64"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestLdapTunnelBytePump verifies the agent is a pure byte pump: bytes written
// to the local socket are forwarded up as ldap_tunnel messages, and bytes sent
// back down are written to the socket. No LDAP parsing anywhere.
func TestLdapTunnelBytePump(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "ldap.sock")

	var mu sync.Mutex
	var sent []WSMessage
	tunnel := newLdapTunnel(func(msg WSMessage) error {
		mu.Lock()
		sent = append(sent, msg)
		mu.Unlock()
		return nil
	})

	stopCh := make(chan struct{})
	defer close(stopCh)
	go tunnel.start(socketPath, stopCh)

	// Wait for the socket to exist.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := net.Dial("unix", socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never became reachable")
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Write bytes up to the SSO.
	if _, err := conn.Write([]byte("hello-ldap")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The tunnel should forward them as a base64 ldap_tunnel message.
	var upMsg WSMessage
	deadline = time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		if len(sent) > 0 {
			upMsg = sent[0]
			mu.Unlock()
			break
		}
		mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("no ldap_tunnel message was sent")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if upMsg.Type != "ldap_tunnel" {
		t.Fatalf("expected ldap_tunnel type, got %q", upMsg.Type)
	}
	connID, _ := upMsg.Payload["conn_id"].(string)
	if connID == "" {
		t.Fatal("missing conn_id")
	}
	dataStr, _ := upMsg.Payload["data"].(string)
	decoded, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		t.Fatalf("bad base64: %v", err)
	}
	if string(decoded) != "hello-ldap" {
		t.Fatalf("expected 'hello-ldap', got %q", decoded)
	}

	// Send bytes back down from the SSO; the client should receive them.
	tunnel.handleMessage(map[string]interface{}{
		"conn_id": connID,
		"data":    base64.StdEncoding.EncodeToString([]byte("world-ldap")),
	})

	buf := make([]byte, 32)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf[:n]) != "world-ldap" {
		t.Fatalf("expected 'world-ldap', got %q", buf[:n])
	}

	// Closing the client should emit a close signal up to the SSO.
	conn.Close()
	deadline = time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		closed := false
		for _, m := range sent {
			if m.Type == "ldap_tunnel" {
				if c, _ := m.Payload["close"].(bool); c {
					closed = true
				}
			}
		}
		mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no close signal was sent")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
