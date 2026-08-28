package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// The CLI must hand the frame to the daemon over the tray IPC socket when the
// daemon is up -- never open a competing WebSocket that would supersede the
// daemon's connection (4002) and lose the frame.
func TestPushServiceRegistrationPrefersDaemonIPC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yml")
	if err := os.WriteFile(path, []byte("server_url: \"wss://sso\"\nauth_token: \"t\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}

	var got TrayCommand
	orig := sendTrayCommand
	sendTrayCommand = func(cmd TrayCommand) error {
		got = cmd
		return nil
	}
	defer func() { sendTrayCommand = orig }()

	if err := pushServiceRegistration(cm, "emby-server", "systemd", false); err != nil {
		t.Fatalf("pushServiceRegistration: %v", err)
	}
	if got.Command != "register_service" || got.Service != "emby-server" || got.Subtype != "systemd" {
		t.Fatalf("daemon command = %+v, want register_service emby-server systemd", got)
	}
}

// Unregister must hand the daemon an unregister_service command.
func TestPushServiceRegistrationUnregisterViaIPC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yml")
	if err := os.WriteFile(path, []byte("server_url: \"wss://sso\"\nauth_token: \"t\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}

	var got TrayCommand
	orig := sendTrayCommand
	sendTrayCommand = func(cmd TrayCommand) error {
		got = cmd
		return nil
	}
	defer func() { sendTrayCommand = orig }()

	if err := pushServiceRegistration(cm, "emby-server", "systemd", true); err != nil {
		t.Fatalf("pushServiceRegistration: %v", err)
	}
	if got.Command != "unregister_service" || got.Service != "emby-server" {
		t.Fatalf("daemon command = %+v, want unregister_service emby-server", got)
	}
}

// When the daemon is not running (no IPC socket) the CLI must fall back to a
// one-shot WebSocket so registration still works on a host whose service is
// down. The fallback is exercised by stubbing sendTrayCommand to fail and
// pointing the server_url at a local test server.
func TestPushServiceRegistrationFallsBackToOneShot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yml")
	if err := os.WriteFile(path, []byte("server_url: \"wss://sso\"\nauth_token: \"t\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}

	orig := sendTrayCommand
	sendTrayCommand = func(cmd TrayCommand) error {
		return fmt.Errorf("cannot connect to daemon IPC socket: no such file")
	}
	defer func() { sendTrayCommand = orig }()

	// A server that accepts the upgrade and answers the welcome + response
	// frames the one-shot path expects.
	upgraded := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		upgraded <- struct{}{}
		// welcome frame
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"config","payload":{"message":"hi"}}`))
		// read the register frame, then answer
		_, _, err = conn.ReadMessage()
		if err != nil {
			return
		}
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response","payload":{"status":"ok","message":"service registered"}}`))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	if err := os.WriteFile(path, []byte("server_url: \""+wsURL+"\"\nauth_token: \"t\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cm, err = NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := pushServiceRegistration(cm, "emby-server", "systemd", false); err != nil {
		t.Fatalf("pushServiceRegistration fallback: %v", err)
	}
	select {
	case <-upgraded:
	default:
		t.Fatal("one-shot WebSocket was never opened")
	}
}

func TestAddRemoveYamlListItem(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		key     string
		item    string
		subtype string
		remove  bool
		wantSub string
		wantErr bool
	}{
		{
			name:    "adds to existing empty block",
			doc:     "services: []\ncapabilities:\n  telemetry: true\n",
			key:     "services",
			item:    "nginx",
			wantSub: "services:\n  - nginx\n",
		},
		{
			name:    "appends after existing items",
			doc:     "services:\n  - nginx\ncapabilities:\n  telemetry: true\n",
			key:     "services",
			item:    "gitea",
			wantSub: "services:\n  - nginx\n  - gitea\n",
		},
		{
			name:    "duplicate rejected",
			doc:     "services:\n  - nginx\n",
			key:     "services",
			item:    "nginx",
			wantErr: true,
		},
		{
			name:    "creates block when absent",
			doc:     "server_url: x\n",
			key:     "services",
			item:    "nginx",
			wantSub: "services:\n  - nginx\n",
		},
		{
			name:    "removes existing item",
			doc:     "services:\n  - nginx\n  - gitea\n",
			key:     "services",
			item:    "nginx",
			remove:  true,
			wantSub: "services:\n  - gitea\n",
		},
		{
			name:    "adds object entry with subtype",
			doc:     "services: []\n",
			key:     "services",
			item:    "nginx",
			subtype: "docker",
			wantSub: "services:\n  - name: nginx\n    subtype: docker\n",
		},
		{
			name:    "remove of absent item errors",
			doc:     "services:\n  - gitea\n",
			key:     "services",
			item:    "nginx",
			remove:  true,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				out string
				err error
			)
			if tc.remove {
				out, err = removeYamlListItem(tc.doc, tc.key, tc.item)
			} else {
				out, err = addYamlListItem(tc.doc, tc.key, tc.item, tc.subtype)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none; out=%q", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantSub != "" && !strings.Contains(out, tc.wantSub) {
				t.Fatalf("output missing %q:\n%s", tc.wantSub, out)
			}
		})
	}
}

func TestPersistServiceRoundTrip(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "persist-service")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "agent.yml")
	content := "server_url: \"https://sso.local\"\nauth_token: \"tok\"\npublic_key: \"k\"\nservices: []\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}

	// Add
	if err := cm.PersistService("nginx", "systemd", false); err != nil {
		t.Fatal(err)
	}
	if got := cm.Get().Services; len(got) != 1 || got[0].Name != "nginx" || got[0].SubType != "systemd" {
		t.Fatalf("expected [nginx/systemd], got %v", got)
	}

	// Add second
	if err := cm.PersistService("gitea", "systemd", false); err != nil {
		t.Fatal(err)
	}
	if got := cm.Get().Services; len(got) != 2 {
		t.Fatalf("expected 2 services, got %v", got)
	}

	// Duplicate must fail
	if err := cm.PersistService("nginx", "systemd", false); err == nil {
		t.Fatal("expected duplicate-add error")
	}

	// Remove
	if err := cm.PersistService("nginx", "systemd", true); err != nil {
		t.Fatal(err)
	}
	if got := cm.Get().Services; len(got) != 1 || got[0].Name != "gitea" {
		t.Fatalf("expected [gitea], got %v", got)
	}

	// Add a docker service and verify its subtype round-trips.
	if err := cm.PersistService("nginx-proxy", "docker", false); err != nil {
		t.Fatal(err)
	}
	if got := cm.Get().Services; len(got) != 2 || got[1].Name != "nginx-proxy" || got[1].SubType != "docker" {
		t.Fatalf("expected docker subtype, got %v", got)
	}

	// Comments/other lines preserved
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "public_key: \"k\"") {
		t.Fatalf("unrelated config line was clobbered:\n%s", raw)
	}
}
