package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// A fixed key pair for the tests, standing in for the SSO's persisted signing
// key. High-risk commands must now be genuinely signed: the agent fails closed
// when no public_key is configured, so these tests sign the way the server
// does instead of relying on verification being skipped.
var testPubKey, testPrivKey, _ = ed25519.GenerateKey(nil)

func testPubKeyB64() string {
	return base64.StdEncoding.EncodeToString(testPubKey)
}

// sign mirrors the server's canonicalization (sorted keys, no whitespace, no
// HTML escaping, `signature` omitted) and adds the signature to the payload.
func sign(t *testing.T, payload map[string]interface{}) map[string]interface{} {
	t.Helper()
	if payload == nil {
		payload = map[string]interface{}{}
	}
	canonical, err := canonicalize(payload)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	signed := make(map[string]interface{}, len(payload)+1)
	for k, v := range payload {
		signed[k] = v
	}
	signed["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(testPrivKey, canonical))
	return signed
}

type MockConn struct {
	Messages [][]byte
}

func (m *MockConn) WriteMessage(messageType int, data []byte) error {
	m.Messages = append(m.Messages, data)
	return nil
}

type MockExecutor struct {
	ExecutedCommands [][]string
	WrittenFiles     map[string][]byte
}

func (m *MockExecutor) Execute(command string, args ...string) ([]byte, error) {
	m.ExecutedCommands = append(m.ExecutedCommands, append([]string{command}, args...))
	return []byte("mock output"), nil
}

func (m *MockExecutor) WriteFile(path string, data []byte, perm os.FileMode) error {
	if m.WrittenFiles == nil {
		m.WrittenFiles = make(map[string][]byte)
	}
	m.WrittenFiles[path] = data
	return nil
}

func (m *MockExecutor) ReadFile(path string) ([]byte, error) {
	if m.WrittenFiles != nil {
		if data, ok := m.WrittenFiles[path]; ok {
			return data, nil
		}
	}
	return []byte("mock file content"), nil
}

func TestHandleCommand(t *testing.T) {
	tests := []struct {
		name             string
		cfg              *Config
		msg              WSMessage
		expectedStatus   string
		expectedCmd      []string
		expectedFile     string
		expectedFileCont string
		// sign the payload with the test key before dispatch, the way the SSO
		// signs high-risk commands
		signed bool
		// heartbeat_ack (and any fire-and-forget ack) must be silently ignored —
		// no response message, no command, no log noise.
		expectedNoResponse bool
	}{
		{
			name: "config command success",
			cfg: &Config{
				Capabilities: Capabilities{},
			},
			msg: WSMessage{
				Type:    "config",
				Payload: map[string]interface{}{"key": "value"},
			},
			expectedStatus: "ok",
		},
		{
			name: "reboot command allowed",
			cfg: &Config{
				PublicKey:    testPubKeyB64(),
				Capabilities: Capabilities{Reboot: true},
			},
			msg: WSMessage{
				Type: "reboot",
			},
			signed:         true,
			expectedStatus: "ok",
			expectedCmd:    []string{"reboot"},
		},
		{
			name: "reboot command denied",
			cfg: &Config{
				Capabilities: Capabilities{Reboot: false},
			},
			msg: WSMessage{
				Type: "reboot",
			},
			expectedStatus: "error",
			expectedCmd:    nil,
		},
		{
			name: "service_restart allowed",
			cfg: &Config{
				Capabilities: Capabilities{
					ServiceControl: []string{"nginx"},
				},
			},
			msg: WSMessage{
				Type: "service_restart",
				Payload: map[string]interface{}{
					"service": "nginx",
				},
			},
			expectedStatus: "ok",
			expectedCmd:    []string{"systemctl", "restart", "nginx"},
		},
		{
			name: "service_restart denied",
			cfg: &Config{
				Capabilities: Capabilities{
					ServiceControl: []string{"nginx"},
				},
			},
			msg: WSMessage{
				Type: "service_restart",
				Payload: map[string]interface{}{
					"service": "ssh",
				},
			},
			expectedStatus: "error",
			expectedCmd:    nil,
		},
		{
			name: "configure_ldap allowed",
			cfg: &Config{
				PublicKey:    testPubKeyB64(),
				Capabilities: Capabilities{ConfigureLDAP: true},
			},
			msg: WSMessage{
				Type: "configure_ldap",
				Payload: map[string]interface{}{
					"config": "domain = theta42.local\nserver = sso.local",
				},
			},
			signed:           true,
			expectedStatus:   "ok",
			expectedFile:     "/etc/sssd/sssd.conf",
			expectedFileCont: "domain = theta42.local\nserver = sso.local",
			expectedCmd:      []string{"systemctl", "restart", "sssd"},
		},
		{
			name: "configure_ldap denied",
			cfg: &Config{
				Capabilities: Capabilities{ConfigureLDAP: false},
			},
			msg: WSMessage{
				Type: "configure_ldap",
				Payload: map[string]interface{}{
					"config": "domain = theta42.local",
				},
			},
			expectedStatus: "error",
			expectedCmd:    nil,
		},
		{
			name: "arbitrary_bash allowed",
			cfg: &Config{
				PublicKey:    testPubKeyB64(),
				Capabilities: Capabilities{ArbitraryBash: true},
			},
			msg: WSMessage{
				Type: "arbitrary_bash",
				Payload: map[string]interface{}{
					"script": "uptime",
				},
			},
			signed:         true,
			expectedStatus: "ok",
			expectedCmd:    []string{"bash", "-c", "uptime"},
		},
		{
			name: "arbitrary_bash denied",
			cfg: &Config{
				Capabilities: Capabilities{ArbitraryBash: false},
			},
			msg: WSMessage{
				Type: "arbitrary_bash",
				Payload: map[string]interface{}{
					"script": "rm -rf /",
				},
			},
			expectedStatus: "error",
			expectedCmd:    nil,
		},
		{
			name: "heartbeat_ack is silently ignored",
			cfg: &Config{
				Capabilities: Capabilities{},
			},
			msg: WSMessage{
				Type: "heartbeat_ack",
			},
			expectedNoResponse: true,
		},
		{
			name: "unknown command",
			cfg: &Config{
				Capabilities: Capabilities{},
			},
			msg: WSMessage{
				Type: "mystery_command",
			},
			expectedStatus: "error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockConn := &MockConn{}
			mockExec := &MockExecutor{}
			cm := &ConfigManager{current: tc.cfg}

			// The dispatch tests assert the exact command lines the Linux
			// executor produces; pin the platform ops so they behave the same
			// on any CI host (Windows included).
			prevOps := defaultPlatformOps
			defaultPlatformOps = &linuxPlatformOps{exec: mockExec}
			defer func() { defaultPlatformOps = prevOps }()

			msg := tc.msg
			if tc.signed {
				msg.Payload = sign(t, msg.Payload)
			}
			handleCommand(cm, msg, mockConn, mockExec, nil)

			if tc.expectedNoResponse {
				if len(mockConn.Messages) != 0 {
					t.Fatalf("expected no response message, got %d: %v", len(mockConn.Messages), mockConn.Messages)
				}
				if len(mockExec.ExecutedCommands) > 0 {
					t.Errorf("expected no commands to be executed, but got %v", mockExec.ExecutedCommands)
				}
				return
			}

			if len(mockConn.Messages) != 1 {
				t.Fatalf("expected 1 response message, got %d", len(mockConn.Messages))
			}

			var resp map[string]string
			if err := json.Unmarshal(mockConn.Messages[0], &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if resp["status"] != tc.expectedStatus {
				t.Errorf("expected status %q, got %q", tc.expectedStatus, resp["status"])
			}

			if tc.expectedCmd != nil {
				if len(mockExec.ExecutedCommands) == 0 {
					t.Errorf("expected command to be executed, but none were")
				} else {
					cmd := mockExec.ExecutedCommands[0]
					if len(cmd) != len(tc.expectedCmd) {
						t.Errorf("expected command length %d, got %d", len(tc.expectedCmd), len(cmd))
					}
					for i := range cmd {
						if cmd[i] != tc.expectedCmd[i] {
							t.Errorf("expected arg %d = %q, got %q", i, tc.expectedCmd[i], cmd[i])
						}
					}
				}
			} else if len(mockExec.ExecutedCommands) > 0 {
				t.Errorf("expected no commands to be executed, but got %v", mockExec.ExecutedCommands)
			}

			if tc.expectedFile != "" {
				content, ok := mockExec.WrittenFiles[tc.expectedFile]
				if !ok {
					t.Errorf("expected file %q to be written, but it wasn't", tc.expectedFile)
				} else if string(content) != tc.expectedFileCont {
					t.Errorf("expected file content %q, got %q", tc.expectedFileCont, string(content))
				}
			}
		})
	}
}

// The agent must not execute a high-risk command it cannot verify. This used to
// return true when no public_key was configured, so an agent installed without
// one executed reboot / configure_ldap / arbitrary_bash unverified.
func TestVerifySignatureFailsClosedWithoutPublicKey(t *testing.T) {
	cfg := &Config{} // no PublicKey
	msg := WSMessage{Type: "arbitrary_bash", Payload: sign(t, map[string]interface{}{"script": "uptime"})}
	if verifySignature(cfg, msg) {
		t.Fatal("verifySignature accepted a command with no public_key configured")
	}
}

func TestVerifySignatureRejectsWrongKey(t *testing.T) {
	otherPub, _, _ := ed25519.GenerateKey(nil)
	cfg := &Config{PublicKey: base64.StdEncoding.EncodeToString(otherPub)}
	msg := WSMessage{Type: "arbitrary_bash", Payload: sign(t, map[string]interface{}{"script": "uptime"})}
	if verifySignature(cfg, msg) {
		t.Fatal("verifySignature accepted a signature from a different key")
	}
}

func TestVerifySignatureRejectsTamperedPayload(t *testing.T) {
	cfg := &Config{PublicKey: testPubKeyB64()}
	payload := sign(t, map[string]interface{}{"script": "uptime"})
	payload["script"] = "rm -rf /" // swap the script, keep the signature
	if verifySignature(cfg, WSMessage{Type: "arbitrary_bash", Payload: payload}) {
		t.Fatal("verifySignature accepted a payload modified after signing")
	}
}

// Regression: encoding/json escapes <, > and & by default, but the server's
// JSON.stringify does not. Any script using redirection or && therefore
// canonicalized differently on each side and failed verification -- which is
// most real scripts.
func TestVerifySignatureAcceptsShellMetacharacters(t *testing.T) {
	cfg := &Config{PublicKey: testPubKeyB64()}
	for _, script := range []string{
		"echo hi > /tmp//out.log",
		"systemctl is-active nginx && systemctl reload nginx",
		"grep -c . < /etc/passwd",
		"a=1 && b=2 && echo \"$a<$b\" > /dev/null",
	} {
		msg := WSMessage{Type: "arbitrary_bash", Payload: sign(t, map[string]interface{}{"script": script})}
		if !verifySignature(cfg, msg) {
			t.Errorf("verifySignature rejected a correctly signed script: %q", script)
		}
	}
}

// The canonical form must be byte-identical to the server's: sorted keys, no
// whitespace, no HTML escaping, no trailing newline, signature omitted.
func TestCanonicalizeMatchesServerForm(t *testing.T) {
	got, err := canonicalize(map[string]interface{}{
		"script":  "echo a > b && c",
		"comment": "x&y",
	})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"comment":"x&y","script":"echo a > b && c"}`
	if string(got) != want {
		t.Errorf("canonical form mismatch:\n got: %s\nwant: %s", got, want)
	}
}
