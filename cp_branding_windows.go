//go:build windows

package main

import (
	"fmt"
	"log"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// White-labeling for the OpenCredential logon tile (DESIGN-WINDOWS.md §6.1).
//
// The text shown under the tile on the Windows logon screen is the default
// value of the provider's registration key under
// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential
// Providers\<CLSID> — written by the OpenCredential installer as
// "OpenCredential <version>". We rewrite that value after seeding so a
// deployment can brand the logon screen with its own name
// (credential_provider_name in agent.yml).
//
// The logo bitmap is a Win32 resource compiled into the provider DLL and
// cannot be changed from the registry; see docs/WHITE_LABELING.md.
const credentialProvidersRoot = `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`

// applyCredentialProviderBranding rewrites the OpenCredential tile display
// name. The provider's key is located by its InprocServer32 DLL path (not a
// hard-coded CLSID) so this survives OpenCredential version changes. Empty
// name is a no-op. Best-effort by design: callers log failures but continue —
// a branding miss must never block directory logon.
func applyCredentialProviderBranding(name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, credentialProvidersRoot, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("open %s: %w", credentialProvidersRoot, err)
	}
	defer root.Close()
	return brandCredentialProvider(root, name)
}

// brandCredentialProvider finds the OpenCredential provider under root (a
// Credential Providers-style key) and sets its display name. Split from
// applyCredentialProviderBranding so tests can target a scratch HKCU key.
func brandCredentialProvider(root registry.Key, name string) error {
	subs, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return fmt.Errorf("enumerate credential providers: %w", err)
	}
	for _, sub := range subs {
		if !strings.Contains(strings.ToLower(credentialProviderDLL(root, sub)), "opencredential") {
			continue
		}
		k, err := registry.OpenKey(root, sub, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("open provider %s: %w", sub, err)
		}
		defer k.Close()
		if err := k.SetStringValue("", name); err != nil {
			return fmt.Errorf("set provider display name: %w", err)
		}
		return nil
	}
	return fmt.Errorf("no OpenCredential credential provider registered under %s", credentialProvidersRoot)
}

// credentialProviderDLL returns the DLL path a provider registers in
// InprocServer32 ("" if unreadable).
func credentialProviderDLL(root registry.Key, sub string) string {
	k, err := registry.OpenKey(root, sub+`\InprocServer32`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("")
	if err != nil {
		return ""
	}
	return v
}

// maybeApplyCredentialProviderBranding applies credential_provider_name from
// agent.yml, logging (but never failing) on problems.
func maybeApplyCredentialProviderBranding(cfg *Config) {
	if cfg == nil || cfg.CredentialProviderName == "" {
		return
	}
	if cfg.CredentialProviderLogo != "" {
		log.Printf("configure-login: credential_provider_logo is set but not supported until the provider ships a configurable bitmap (docs/WHITE_LABELING.md); ignoring")
	}
	if err := applyCredentialProviderBranding(cfg.CredentialProviderName); err != nil {
		log.Printf("configure-login: white-label tile name %q: %v", cfg.CredentialProviderName, err)
		return
	}
	log.Printf("configure-login: logon tile renamed to %q", cfg.CredentialProviderName)
}
