package main

import (
	"encoding/json"
	"os"
	"testing"
)

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

func TestHandleCommand(t *testing.T) {
	tests := []struct {
		name            string
		cfg             *Config
		msg             WSMessage
		expectedStatus  string
		expectedCmd     []string
		expectedFile    string
		expectedFileCont string
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
				Capabilities: Capabilities{Reboot: true},
			},
			msg: WSMessage{
				Type: "reboot",
			},
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
				Capabilities: Capabilities{ConfigureLDAP: true},
			},
			msg: WSMessage{
				Type: "configure_ldap",
				Payload: map[string]interface{}{
					"config": "domain = theta42.local\nserver = sso.local",
				},
			},
			expectedStatus:  "ok",
			expectedFile:    "/etc/sssd/sssd.conf",
			expectedFileCont: "domain = theta42.local\nserver = sso.local",
			expectedCmd:     []string{"systemctl", "restart", "sssd"},
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
				Capabilities: Capabilities{ArbitraryBash: true},
			},
			msg: WSMessage{
				Type: "arbitrary_bash",
				Payload: map[string]interface{}{
					"script": "uptime",
				},
			},
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
			handleCommand(tc.cfg, tc.msg, mockConn, mockExec)

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
