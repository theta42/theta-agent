//go:build windows

package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/windows/registry"
)

// configureLogin wires the OpenCredential credential provider to this host's
// agent LDAP tunnel and enables the tunnel in agent.yml. Run once after the
// OpenCredential installer (its installer deletes these registry keys), and
// re-runnable for idempotent re-seeding.
//
// Requires ldap_base_dn in agent.yml; without it the tunnel is still enabled
// and the LocalMachine fallback keeps working, but directory logon stays
// unconfigured until ldap_base_dn is set and configure-login is re-run.
func configureLogin(cm *ConfigManager) error {
	cfg := cm.Get()

	// 1. Turn on the LDAP byte-pump so 127.0.0.1:389 exists for OpenCredential.
	if err := persistLdapTunnelEnabled(cm); err != nil {
		return fmt.Errorf("enable ldap_tunnel: %w", err)
	}

	// 2. Seed the OpenCredential registry configuration.
	baseDN := cfg.LdapBaseDN
	if baseDN == "" {
		return fmt.Errorf("ldap_base_dn is empty in %s: set it (e.g. dc=example,dc=com) and re-run configure-login", cm.configPath)
	}
	adminGroup := cfg.LdapAdminGroup
	if adminGroup == "" {
		adminGroup = "admins"
	}
	localAdmin := cfg.LdapLocalAdminGroup
	if localAdmin == "" {
		localAdmin = "Administrators"
	}

	root, _, err := registry.CreateKey(registry.LOCAL_MACHINE, openCredentialRoot, registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s: %w", openCredentialRoot, err)
	}
	defer root.Close()

	if err := writeRegValues(root, openCredentialValues(baseDN, adminGroup, localAdmin)); err != nil {
		return err
	}

	log.Printf("configure-login: OpenCredential seeded (LDAP 127.0.0.1:389, base_dn=%s, admin group %q -> %q)", baseDN, adminGroup, localAdmin)
	log.Printf("configure-login: ldap_tunnel enabled in %s — restart the agent service to start the listener", cm.configPath)
	return nil
}

// writeRegValues writes a set of values under root, creating sub-keys as
// needed. Split out so tests can target a scratch key.
func writeRegValues(root registry.Key, vals []regValue) error {
	for _, v := range vals {
		key := root
		if v.key != "" {
			var err error
			key, _, err = registry.CreateKey(root, v.key, registry.CREATE_SUB_KEY|registry.SET_VALUE)
			if err != nil {
				return fmt.Errorf("create key %s: %w", v.key, err)
			}
			defer key.Close()
		}
		var err error
		switch {
		case v.isDword:
			err = key.SetDWordValue(v.name, v.dword)
		case len(v.multi) > 0:
			err = key.SetStringsValue(v.name, v.multi)
		case v.str != "":
			err = key.SetStringValue(v.name, v.str)
		}
		if err != nil {
			return fmt.Errorf("set %s\\%s: %w", v.key, v.name, err)
		}
	}
	return nil
}

// persistLdapTunnelEnabled flips capabilities.ldap_tunnel on in agent.yml and
// reloads the live config.
func persistLdapTunnelEnabled(cm *ConfigManager) error {
	raw, err := os.ReadFile(cm.configPath)
	if err != nil {
		return err
	}
	out := ensureLdapTunnel(string(raw))
	if err := os.WriteFile(cm.configPath, []byte(out), 0600); err != nil {
		return err
	}
	return cm.Reload()
}
