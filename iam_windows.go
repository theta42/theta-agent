//go:build windows

package main

// Windows IAM helpers (DESIGN-WINDOWS.md §4 "IAM on Windows"). The platform
// neutral parts live in iam.go; this file adds the Windows-specific pieces that
// applyIAM cannot express (it is the Linux engine).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// applyWindowsSSHKeys writes each user's authorized_keys into their profile so
// the built-in Windows OpenSSH server picks them up. OpenSSH on Windows reads
// %USERPROFILE%\.ssh\authorized_keys for standard accounts (administrators use
// %ProgramData%\ssh\administrators_authorized_keys; we mirror the key there too
// when the profile belongs to an admin is unknowable here, so we write both
// locations if present).
func applyWindowsSSHKeys(keys []SSHKey) error {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}

	// administrators_authorized_keys covers members of Administrators.
	adminKeys := programDataAdminKeysPath(pd)

	for _, k := range keys {
		if k.User == "" {
			continue
		}
		content := strings.Join(k.Keys, "\n") + "\n"

		profile := filepath.Join(`C:\Users`, k.User)
		if st, err := os.Stat(profile); err == nil && st.IsDir() {
			sshDir := filepath.Join(profile, ".ssh")
			if err := os.MkdirAll(sshDir, 0700); err != nil {
				return fmt.Errorf("mkdir %s: %w", sshDir, err)
			}
			dest := filepath.Join(sshDir, "authorized_keys")
			if err := os.WriteFile(dest, []byte(content), 0600); err != nil {
				return fmt.Errorf("write %s: %w", dest, err)
			}
		}

		// Also mirror into administrators_authorized_keys so admin-keyed logins
		// work through OpenSSH's admin ACL check.
		if err := os.MkdirAll(filepath.Dir(adminKeys), 0700); err == nil {
			_ = os.WriteFile(adminKeys, []byte(content), 0600)
		}
	}
	return nil
}

func programDataAdminKeysPath(pd string) string {
	return filepath.Join(pd, "ssh", "administrators_authorized_keys")
}
