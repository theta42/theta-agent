package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// IAM engine (DESIGN.md §6). The SSO pushes node-scoped identity config down the
// WSS channel as a signed `iam_apply` command; the agent verifies the signature
// (fail-closed) and applies it locally: sudo rules, SSH keys, access control,
// and session revocation.

// Paths are package-level vars so tests can redirect them to temp dirs.
var (
	iamSudoersDir  = "/etc/sudoers.d"
	iamKeysDir     = "/etc/theta/authorized_keys"
	iamKeysCommand = "/usr/local/bin/theta-authorized-keys"
	iamAccessConf  = "/etc/security/access.conf"
)

// IAMPayload is the signed body of an `iam_apply` command.
type IAMPayload struct {
	NodeID        string        `json:"node_id"`
	Revision      int           `json:"revision"`
	AccessControl AccessControl `json:"access_control"`
}

type AccessControl struct {
	AllowedLoginGroups []string   `json:"allowed_login_groups"`
	SudoRules          []SudoRule `json:"sudo_rules"`
	SSHKeys            []SSHKey   `json:"ssh_keys"`
	RevokeUsers        []string   `json:"revoke_users"`
}

type SudoRule struct {
	Group    string   `json:"group"`
	RunAs    string   `json:"run_as"`
	Commands []string `json:"commands"`
	Nopasswd bool     `json:"nopasswd"`
}

type SSHKey struct {
	User string   `json:"user"`
	Keys []string `json:"keys"`
}

// applyIAM applies a verified IAM payload. The caller must have already verified
// the Ed25519 signature.
func applyIAM(payload IAMPayload, exec Executor) error {
	if len(payload.AccessControl.SudoRules) > 0 {
		if err := applySudoRules(payload.AccessControl.SudoRules, payload.NodeID, exec); err != nil {
			return fmt.Errorf("sudo rules: %w", err)
		}
	}
	if len(payload.AccessControl.SSHKeys) > 0 {
		if err := applySSHKeys(payload.AccessControl.SSHKeys, exec); err != nil {
			return fmt.Errorf("ssh keys: %w", err)
		}
	}
	if len(payload.AccessControl.AllowedLoginGroups) > 0 {
		if err := applyAccessControl(payload.AccessControl.AllowedLoginGroups, exec); err != nil {
			return fmt.Errorf("access control: %w", err)
		}
	}
	if len(payload.AccessControl.RevokeUsers) > 0 {
		applyRevocation(payload.AccessControl.RevokeUsers, exec)
	}
	return nil
}

// applySudoRules writes /etc/sudoers.d/theta-iam-<node_id>, verifies with
// `visudo -c`, and atomically swaps it in on success.
func applySudoRules(rules []SudoRule, nodeID string, exec Executor) error {
	var b strings.Builder
	for _, r := range rules {
		if r.Group == "" {
			continue
		}
		runAs := r.RunAs
		if runAs == "" {
			runAs = "ALL"
		}
		cmds := strings.Join(r.Commands, ", ")
		if cmds == "" {
			cmds = "ALL"
		}
		prefix := ""
		if r.Nopasswd {
			prefix = "NOPASSWD:"
		}
		fmt.Fprintf(&b, "%%%s ALL=(%s) %s%s\n", r.Group, runAs, prefix, cmds)
	}
	content := b.String()

	// Make sure the sudoers.d dir exists (a minimal host may not have it).
	if err := os.MkdirAll(iamSudoersDir, 0755); err != nil {
		return err
	}

	// Write to a temp file in the sudoers.d dir, verify, then rename.
	tmp, err := os.CreateTemp(iamSudoersDir, ".theta-iam-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	tmp.Close()
	os.Chmod(tmpName, 0440)

	// visudo -c -f <file> validates a single file without touching the rest.
	if _, err := exec.Execute("visudo", "-c", "-f", tmpName); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("visudo rejected the rules: %w", err)
	}

	target := filepath.Join(iamSudoersDir, "theta-iam-"+nodeID)
	if err := os.Rename(tmpName, target); err != nil {
		os.Remove(tmpName)
		return err
	}
	log.Printf("IAM: wrote %s", target)
	return nil
}

// applySSHKeys stores per-user keys and installs the AuthorizedKeysCommand
// script that sshd calls per login.
func applySSHKeys(keys []SSHKey, exec Executor) error {
	if err := os.MkdirAll(iamKeysDir, 0755); err != nil {
		return err
	}
	for _, k := range keys {
		if k.User == "" {
			continue
		}
		path := filepath.Join(iamKeysDir, k.User)
		content := strings.Join(k.Keys, "\n") + "\n"
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			return err
		}
	}

	// AuthorizedKeysCommand script: cat the user's key file.
	script := "#!/bin/sh\ncat \"" + iamKeysDir + "/$1\" 2>/dev/null\n"
	if err := os.WriteFile(iamKeysCommand, []byte(script), 0755); err != nil {
		return err
	}
	log.Printf("IAM: wrote %d ssh key file(s) + %s", len(keys), iamKeysCommand)
	return nil
}

// applyAccessControl writes /etc/security/access.conf with the allowed login
// groups (PAM access). Format: `+:group:ALL` for each allowed group, then deny
// everything else.
func applyAccessControl(groups []string, exec Executor) error {
	var b strings.Builder
	for _, g := range groups {
		if g != "" {
			fmt.Fprintf(&b, "+:%s:ALL\n", g)
		}
	}
	b.WriteString("-:ALL:ALL\n")
	if err := os.MkdirAll(filepath.Dir(iamAccessConf), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(iamAccessConf, []byte(b.String()), 0644); err != nil {
		return err
	}
	log.Printf("IAM: wrote %s", iamAccessConf)
	return nil
}

// applyRevocation flushes the SSSD cache and drops active sessions for the
// revoked users.
func applyRevocation(users []string, exec Executor) {
	// Flush the whole SSSD cache once — a revoked user must not be resolvable
	// from cache.
	if _, err := exec.Execute("sss_cache", "-E"); err != nil {
		log.Printf("IAM: sss_cache -E failed: %v", err)
	}
	for _, u := range users {
		if u == "" {
			continue
		}
		if _, err := exec.Execute("pkill", "-u", u); err != nil {
			log.Printf("IAM: pkill -u %s failed (no sessions?): %v", u, err)
		}
		log.Printf("IAM: revoked %s", u)
	}
}

// parseIAMPayload extracts an IAMPayload from a WSMessage payload map.
func parseIAMPayload(payload map[string]interface{}) (IAMPayload, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return IAMPayload{}, err
	}
	var p IAMPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return IAMPayload{}, err
	}
	return p, nil
}
