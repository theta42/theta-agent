//go:build windows

package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/windows/registry"
)

// configureLogin wires the OpenCredential credential provider to this host's
// agent LDAP tunnel and enables the LDAP capabilities in agent.yml. Re-runnable
// for idempotent re-seeding.
//
// The LDAP details (base DN) deliberately come from the Directory, not the
// operator: the agent advertises capabilities.configure_ldap, the Directory
// pushes the LDAP config, and ConfigureLDAP seeds OpenCredential automatically.
// configure-login only needs to seed immediately when an operator has set
// ldap_base_dn in agent.yml directly; otherwise it just makes sure the
// capabilities are on and lets the Directory push do the rest.
func configureLogin(cm *ConfigManager) error {
	cfg := cm.Get()

	// 1. Advertise the LDAP capabilities so the tunnel runs and the Directory
	// knows to push the LDAP config. ldap_tunnel is implied by configure_ldap
	// in the loader, but be explicit.
	if err := persistLdapCapabilities(cm); err != nil {
		return fmt.Errorf("enable LDAP capabilities: %w", err)
	}

	// 2. Apply logon-tile white-labeling. Independent of the base DN: it only
	// needs the provider to be registered (the agent installer did that).
	maybeApplyCredentialProviderBranding(cfg)

	baseDN := cfg.LdapBaseDN
	if baseDN == "" {
		log.Printf("configure-login: no ldap_base_dn in %s yet — it will be applied when the Directory pushes the LDAP config (capabilities.configure_ldap is now enabled)", cm.configPath)
		return nil
	}
	return seedOpenCredentialFromConfig(cm, baseDN)
}

// seedOpenCredentialFromConfig seeds OpenCredential using the given base DN and
// the admin-group overrides from agent.yml (defaults: admins -> Administrators).
func seedOpenCredentialFromConfig(cm *ConfigManager, baseDN string) error {
	cfg := cm.Get()
	adminGroup := cfg.LdapAdminGroup
	if adminGroup == "" {
		adminGroup = "admins"
	}
	localAdmin := cfg.LdapLocalAdminGroup
	if localAdmin == "" {
		localAdmin = "Administrators"
	}
	if err := seedOpenCredential(baseDN, adminGroup, localAdmin); err != nil {
		return err
	}
	// Re-apply branding after every seed: the OpenCredential installer resets
	// its registration (and thus the tile name) on upgrade.
	maybeApplyCredentialProviderBranding(cfg)
	log.Printf("configure-login: OpenCredential seeded (LDAP 127.0.0.1:389, base_dn=%s, %q -> %q)", baseDN, adminGroup, localAdmin)
	return nil
}

// seedOpenCredential writes the OpenCredential registry configuration for
// directory logon against the agent's loopback LDAP tunnel.
func seedOpenCredential(baseDN, adminGroup, localAdminGroup string) error {
	root, _, err := registry.CreateKey(registry.LOCAL_MACHINE, openCredentialRoot, registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s: %w", openCredentialRoot, err)
	}
	defer root.Close()
	return writeRegValues(root, openCredentialValues(baseDN, adminGroup, localAdminGroup))
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

// persistLdapCapabilities turns on capabilities.configure_ldap and
// capabilities.ldap_tunnel in agent.yml and reloads the live config.
func persistLdapCapabilities(cm *ConfigManager) error {
	raw, err := os.ReadFile(cm.configPath)
	if err != nil {
		return err
	}
	out := ensureCapability(string(raw), "configure_ldap")
	out = ensureCapability(out, "ldap_tunnel")
	if err := os.WriteFile(cm.configPath, []byte(out), 0600); err != nil {
		return err
	}
	return cm.Reload()
}
