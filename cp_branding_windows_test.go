//go:build windows

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// TestBrandCredentialProvider exercises the logon-tile white-labeling against
// a scratch HKCU key shaped like the real Credential Providers root: two fake
// providers, one registered with an OpenCredential DLL and one with an
// unrelated DLL. Only the OpenCredential one may be renamed.
func TestBrandCredentialProvider(t *testing.T) {
	const root = `SOFTWARE\ThetaAgentTest\CredentialProviders`
	const ocClsid = `{D02A0C7E-0000-4000-8000-5B9B4C0A0C0A}`
	const otherClsid = `{AAAAAAAA-BBBB-CCCC-DDDD-EEEEFFFF0000}`
	registry.DeleteKey(registry.CURRENT_USER, root)
	defer registry.DeleteKey(registry.CURRENT_USER, root)

	open := func(path string, access uint32) registry.Key {
		k, err := registry.OpenKey(registry.CURRENT_USER, path, access)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		return k
	}
	create := func(path string) {
		if _, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.CREATE_SUB_KEY|registry.SET_VALUE); err != nil {
			t.Fatalf("create %s: %v", path, err)
		}
	}

	create(root + `\` + ocClsid + `\InprocServer32`)
	create(root + `\` + otherClsid + `\InprocServer32`)
	for path, dll := range map[string]string{
		root + `\` + ocClsid + `\InprocServer32`:    `C:\Program Files\OpenCredential\OpenCredential3.dll`,
		root + `\` + otherClsid + `\InprocServer32`: `C:\Windows\System32\smartcard.dll`,
	} {
		k := open(path, registry.SET_VALUE)
		if err := k.SetStringValue("", dll); err != nil {
			t.Fatalf("set InprocServer32 in %s: %v", path, err)
		}
		k.Close()
	}
	for _, clsid := range []string{ocClsid, otherClsid} {
		k := open(root+`\`+clsid, registry.SET_VALUE)
		if err := k.SetStringValue("", "OpenCredential 1.0"); err != nil {
			t.Fatalf("seed display name: %v", err)
		}
		k.Close()
	}

	scratchRoot := open(root, registry.ENUMERATE_SUB_KEYS)
	defer scratchRoot.Close()

	if err := brandCredentialProvider(scratchRoot, "MyOrg Login"); err != nil {
		t.Fatalf("brandCredentialProvider: %v", err)
	}

	oc := open(root+`\`+ocClsid, registry.QUERY_VALUE)
	defer oc.Close()
	if got, _, err := oc.GetStringValue(""); err != nil || got != "MyOrg Login" {
		t.Errorf("OpenCredential display name = %q, %v; want \"MyOrg Login\"", got, err)
	}

	other := open(root+`\`+otherClsid, registry.QUERY_VALUE)
	defer other.Close()
	if got, _, err := other.GetStringValue(""); err != nil || got != "OpenCredential 1.0" {
		t.Errorf("unrelated provider was touched: %q, %v", got, err)
	}
}

// TestBrandCredentialProviderNotFound verifies a clear error when no
// OpenCredential-style provider is registered.
func TestBrandCredentialProviderNotFound(t *testing.T) {
	const root = `SOFTWARE\ThetaAgentTest\NoProviders`
	registry.DeleteKey(registry.CURRENT_USER, root)
	defer registry.DeleteKey(registry.CURRENT_USER, root)

	k, _, err := registry.CreateKey(registry.CURRENT_USER, root, registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		t.Fatalf("create scratch key: %v", err)
	}
	defer k.Close()
	k.Close()

	scratchRoot, err := registry.OpenKey(registry.CURRENT_USER, root, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("reopen scratch key: %v", err)
	}
	defer scratchRoot.Close()

	err = brandCredentialProvider(scratchRoot, "MyOrg Login")
	if err == nil || !strings.Contains(err.Error(), "no OpenCredential") {
		t.Errorf("want 'no OpenCredential...' error, got: %v", err)
	}
}

// TestApplyCredentialProviderBrandingEmptyName guards the no-op contract.
func TestApplyCredentialProviderBrandingEmptyName(t *testing.T) {
	if err := applyCredentialProviderBranding("   "); err != nil {
		t.Errorf("empty/whitespace name must be a no-op, got: %v", err)
	}
	if err := applyCredentialProviderBranding(""); err != nil {
		t.Errorf("empty name must be a no-op, got: %v", err)
	}
}
