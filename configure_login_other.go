//go:build !windows

package main

import "fmt"

// configureLogin is Windows-only: LDAP logon via the OpenCredential
// credential provider is a Windows concept (DESIGN-WINDOWS.md §6). On Linux
// the equivalent is SSSD, configured by the directory's install flow.
func configureLogin(cm *ConfigManager) error {
	return fmt.Errorf("configure-login is only meaningful on Windows")
}
