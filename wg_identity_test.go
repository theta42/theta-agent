package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateWireGuardKeyShape(t *testing.T) {
	kp, err := generateWireGuardKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for name, k := range map[string]string{"private": kp.PrivateKey, "public": kp.PublicKey} {
		raw, derr := base64.StdEncoding.DecodeString(k)
		if derr != nil {
			t.Fatalf("%s key is not base64: %v", name, derr)
		}
		if len(raw) != 32 {
			t.Fatalf("%s key is %d bytes, want 32", name, len(raw))
		}
		// wg(8) keys are exactly 44 base64 chars ending in '='.
		if len(k) != 44 {
			t.Fatalf("%s key is %d chars, want 44: %q", name, len(k), k)
		}
	}
	// The Directory validates enrolled keys with this exact regex
	// (mesh_clients.js). A key it would reject is useless to us.
	if !meshPubKeyRe.MatchString(kp.PublicKey) {
		t.Fatalf("public key would be rejected by the Directory: %q", kp.PublicKey)
	}
}

func TestGenerateWireGuardKeyIsClamped(t *testing.T) {
	kp, err := generateWireGuardKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(kp.PrivateKey)
	// RFC 7748 clamping, the same wg genkey applies. An unclamped key
	// interoperates unpredictably.
	if raw[0]&7 != 0 {
		t.Fatalf("low 3 bits of byte 0 not cleared: %08b", raw[0])
	}
	if raw[31]&128 != 0 {
		t.Fatalf("high bit of byte 31 not cleared: %08b", raw[31])
	}
	if raw[31]&64 == 0 {
		t.Fatalf("bit 6 of byte 31 not set: %08b", raw[31])
	}
}

func TestPublicFromPrivateMatchesGeneration(t *testing.T) {
	kp, err := generateWireGuardKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub, err := publicFromPrivate(kp.PrivateKey)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if pub != kp.PublicKey {
		t.Fatalf("re-derived public key %q != generated %q", pub, kp.PublicKey)
	}
}

// The identity must survive a restart: the Directory enrolled this public key,
// so regenerating it would silently orphan the device's peer entry.
func TestLoadOrCreateWireGuardKeyIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg_private.key")

	first, err := LoadOrCreateWireGuardKey(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, err := LoadOrCreateWireGuardKey(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if first.PrivateKey != second.PrivateKey || first.PublicKey != second.PublicKey {
		t.Fatalf("identity changed across loads: %q -> %q", first.PublicKey, second.PublicKey)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("key file mode is %04o, want 0600", perm)
	}
}

func TestLoadOrCreateWireGuardKeyRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg_private.key")
	if err := os.WriteFile(path, []byte("not-a-key\n"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Better to fail loudly than to silently mint a new identity the
	// Directory has never seen.
	if _, err := LoadOrCreateWireGuardKey(path); err == nil {
		t.Fatalf("expected an error for an unusable stored key")
	}
}

func TestTrimKeyStripsWhitespace(t *testing.T) {
	if got := trimKey("  abc\r\ndef\t\n"); got != "abcdef" {
		t.Fatalf("trimKey = %q", got)
	}
}

// The Directory renders an agent-owned device's config with a placeholder
// where the private key goes -- it has none to put there, by design. Nothing
// ever filled it in, so a pushed config reached wg-quick containing the literal
// string "<generated on this device>" and the interface could not come up.
func TestFillPrivateKeySubstitutesPlaceholder(t *testing.T) {
	conf := "[Interface]\nPrivateKey = <generated on this device>\nAddress = 10.2.128.1/32\n"
	out, err := fillPrivateKey(conf, "SECRET")
	if err != nil {
		t.Fatalf("fill: %v", err)
	}
	if strings.Contains(out, configPrivateKeyPlaceholder) {
		t.Fatalf("placeholder survived:\n%s", out)
	}
	if !strings.Contains(out, "PrivateKey = SECRET") {
		t.Fatalf("key not substituted:\n%s", out)
	}
	if !strings.Contains(out, "Address = 10.2.128.1/32") {
		t.Fatalf("rest of the config was disturbed:\n%s", out)
	}
}

// An admin-generated config carries its own key and must pass through untouched.
func TestFillPrivateKeyLeavesCompleteConfigAlone(t *testing.T) {
	conf := "[Interface]\nPrivateKey = ALREADYHERE\n"
	out, err := fillPrivateKey(conf, "SECRET")
	if err != nil {
		t.Fatalf("fill: %v", err)
	}
	if out != conf {
		t.Fatalf("complete config was modified:\n%s", out)
	}
}

func TestFillPrivateKeyErrorsWithoutAKey(t *testing.T) {
	conf := "[Interface]\nPrivateKey = <generated on this device>\n"
	if _, err := fillPrivateKey(conf, ""); err == nil {
		t.Fatalf("expected an error when the config needs a key and none exists")
	}
}

// A complete config must not cause the key file to be created as a side effect.
func TestFillPrivateKeyFromHostSkipsKeyLoadWhenNotNeeded(t *testing.T) {
	dir := t.TempDir()
	prev := wgKeyPathOverride
	wgKeyPathOverride = filepath.Join(dir, "wg_private.key")
	defer func() { wgKeyPathOverride = prev }()

	conf := "[Interface]\nPrivateKey = ALREADYHERE\n"
	if _, err := fillPrivateKeyFromHost(conf); err != nil {
		t.Fatalf("fill: %v", err)
	}
	if _, err := os.Stat(wgKeyPathOverride); err == nil {
		t.Fatalf("key file was created for a config that did not need it")
	}
}

func TestFillPrivateKeyFromHostUsesTheHostKey(t *testing.T) {
	dir := t.TempDir()
	prev := wgKeyPathOverride
	wgKeyPathOverride = filepath.Join(dir, "wg_private.key")
	defer func() { wgKeyPathOverride = prev }()

	kp, err := LoadOrCreateWireGuardKey(wgKeyPathOverride)
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	conf := "[Interface]\nPrivateKey = <generated on this device>\n"
	out, err := fillPrivateKeyFromHost(conf)
	if err != nil {
		t.Fatalf("fill: %v", err)
	}
	if !strings.Contains(out, kp.PrivateKey) {
		t.Fatalf("host key was not used:\n%s", out)
	}
}
