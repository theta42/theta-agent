package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyIAM verifies the agent applies sudo rules, SSH keys, access control,
// and revocation from a signed IAM payload.
func TestApplyIAM(t *testing.T) {
	dir := t.TempDir()
	iamSudoersDir = dir
	iamKeysDir = filepath.Join(dir, "keys")
	iamKeysCommand = filepath.Join(dir, "theta-authorized-keys")
	iamAccessConf = filepath.Join(dir, "access.conf")

	payload := IAMPayload{
		NodeID:   "node-42",
		Revision: 82,
		AccessControl: AccessControl{
			AllowedLoginGroups: []string{"sysadmins", "node-operators"},
			SudoRules: []SudoRule{
				{Group: "sysadmins", RunAs: "ALL", Commands: []string{"ALL"}},
				{Group: "node-operators", RunAs: "ALL", Commands: []string{"ALL"}, Nopasswd: true},
			},
			SSHKeys: []SSHKey{
				{User: "admin", Keys: []string{"ssh-ed25519 AAAA admin@theta"}},
			},
			RevokeUsers: []string{"olduser"},
		},
	}

	exec := &MockExecutor{}
	if err := applyIAM(payload, exec); err != nil {
		t.Fatalf("applyIAM: %v", err)
	}

	// Sudo rules file.
	sudoers, err := os.ReadFile(filepath.Join(dir, "theta-iam-node-42"))
	if err != nil {
		t.Fatalf("read sudoers: %v", err)
	}
	wantSudoers := "%sysadmins ALL=(ALL) ALL\n%node-operators ALL=(ALL) NOPASSWD:ALL\n"
	if string(sudoers) != wantSudoers {
		t.Fatalf("sudoers mismatch:\n got: %q\nwant: %q", sudoers, wantSudoers)
	}

	// SSH key file + AuthorizedKeysCommand script.
	keyFile, err := os.ReadFile(filepath.Join(iamKeysDir, "admin"))
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if string(keyFile) != "ssh-ed25519 AAAA admin@theta\n" {
		t.Fatalf("key file mismatch: %q", keyFile)
	}
	script, err := os.ReadFile(iamKeysCommand)
	if err != nil {
		t.Fatalf("read keys command: %v", err)
	}
	if string(script) != "#!/bin/sh\ncat \""+iamKeysDir+"/$1\" 2>/dev/null\n" {
		t.Fatalf("keys command mismatch: %q", script)
	}

	// Access control.
	access, err := os.ReadFile(iamAccessConf)
	if err != nil {
		t.Fatalf("read access.conf: %v", err)
	}
	wantAccess := "+:sysadmins:ALL\n+:node-operators:ALL\n-:ALL:ALL\n"
	if string(access) != wantAccess {
		t.Fatalf("access.conf mismatch:\n got: %q\nwant: %q", access, wantAccess)
	}

	// Commands: visudo -c -f, sss_cache -E, pkill -u olduser.
	ran := map[string]bool{}
	for _, c := range exec.ExecutedCommands {
		if c[0] == "visudo" {
			ran["visudo"] = true
		}
		if c[0] == "sss_cache" {
			ran["sss_cache"] = true
		}
		if c[0] == "pkill" && len(c) >= 3 && c[2] == "olduser" {
			ran["pkill"] = true
		}
	}
	for _, k := range []string{"visudo", "sss_cache", "pkill"} {
		if !ran[k] {
			t.Errorf("expected %s to run, got commands %v", k, exec.ExecutedCommands)
		}
	}
}

// TestParseIAMPayload verifies the payload parses from a WSMessage payload map.
func TestParseIAMPayload(t *testing.T) {
	payload := map[string]interface{}{
		"node_id":   "node-42",
		"revision":  float64(82),
		"access_control": map[string]interface{}{
			"allowed_login_groups": []interface{}{"sysadmins"},
			"sudo_rules": []interface{}{
				map[string]interface{}{"group": "sysadmins", "run_as": "ALL", "commands": []interface{}{"ALL"}, "nopasswd": true},
			},
			"ssh_keys": []interface{}{
				map[string]interface{}{"user": "admin", "keys": []interface{}{"ssh-ed25519 AAAA"}},
			},
			"revoke_users": []interface{}{"olduser"},
		},
	}
	p, err := parseIAMPayload(payload)
	if err != nil {
		t.Fatalf("parseIAMPayload: %v", err)
	}
	if p.NodeID != "node-42" || p.Revision != 82 {
		t.Fatalf("bad node/revision: %+v", p)
	}
	if len(p.AccessControl.SudoRules) != 1 || p.AccessControl.SudoRules[0].Group != "sysadmins" {
		t.Fatalf("bad sudo rules: %+v", p.AccessControl.SudoRules)
	}
	if len(p.AccessControl.SSHKeys) != 1 || p.AccessControl.SSHKeys[0].User != "admin" {
		t.Fatalf("bad ssh keys: %+v", p.AccessControl.SSHKeys)
	}
	if len(p.AccessControl.RevokeUsers) != 1 || p.AccessControl.RevokeUsers[0] != "olduser" {
		t.Fatalf("bad revoke users: %+v", p.AccessControl.RevokeUsers)
	}
}
