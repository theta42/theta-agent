package main

// This agent's own WireGuard identity.
//
// Until now the agent had no key material at all: the Directory rendered a
// client config with the literal placeholder `PrivateKey = <generated on this
// device>` (mesh_client_conf.js) on the assumption that the agent "completes it
// with the key it already holds" -- but nothing ever generated or held one, so
// a pushed config could only ever fail `wg-quick up`. The device also never
// appeared under jump-host's mesh view, because the only thing that creates a
// MeshClient row is an enrolment carrying a public key.
//
// The private half is generated here and never leaves the host. Only the public
// half is sent to the Directory, which is why the server can honestly say it
// does not store client private keys.

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// meshPubKeyRe mirrors the validation the Directory applies on enrolment
// (utils/mesh_clients.js): a WireGuard key is 32 raw bytes in base64, so 44
// characters. Checking it here means a malformed key is caught before it is
// sent, rather than coming back as a 400 the agent would have to interpret.
var meshPubKeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]{2}$`)

// defaultWireGuardKeyPath returns where this agent's private key is persisted.
// It sits beside agent.yml and carries the same protection: root/SYSTEM only.
func defaultWireGuardKeyPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(windowsDataDir(), "wg", "private.key")
	}
	return "/etc/theta42/wg_private.key"
}

// wgKeyPair is a WireGuard identity in the base64 form wg(8) uses.
type wgKeyPair struct {
	PrivateKey string
	PublicKey  string
}

// generateWireGuardKey produces a fresh Curve25519 keypair with the clamping
// WireGuard requires. Equivalent to `wg genkey | tee private | wg pubkey`, but
// without depending on the wg binary being installed before enrolment.
func generateWireGuardKey() (wgKeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return wgKeyPair{}, fmt.Errorf("wireguard: generate private key: %w", err)
	}
	// Curve25519 clamping, per RFC 7748 -- wg does this too, and an unclamped
	// key would interoperate unpredictably.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	// crypto/ecdh (stdlib since Go 1.20) rather than x/crypto/curve25519 --
	// no new module dependency, and nothing to keep in step with the Go
	// version CI pins.
	key, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return wgKeyPair{}, fmt.Errorf("wireguard: derive public key: %w", err)
	}
	return wgKeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
	}, nil
}

// publicFromPrivate re-derives the public half of a stored key.
func publicFromPrivate(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", fmt.Errorf("wireguard: private key is not base64: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("wireguard: private key is %d bytes, want 32", len(raw))
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("wireguard: derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// LoadOrCreateWireGuardKey returns this host's WireGuard identity, generating
// and persisting one on first call. Idempotent: the same key is returned for
// the life of the host, so the public key the Directory enrolled stays valid.
func LoadOrCreateWireGuardKey(path string) (wgKeyPair, error) {
	if path == "" {
		path = defaultWireGuardKeyPath()
	}
	if raw, err := os.ReadFile(path); err == nil {
		priv := trimKey(string(raw))
		if priv != "" {
			pub, perr := publicFromPrivate(priv)
			if perr != nil {
				return wgKeyPair{}, fmt.Errorf("wireguard: stored key at %s is unusable: %w", path, perr)
			}
			return wgKeyPair{PrivateKey: priv, PublicKey: pub}, nil
		}
	} else if !os.IsNotExist(err) {
		return wgKeyPair{}, fmt.Errorf("wireguard: read %s: %w", path, err)
	}

	kp, err := generateWireGuardKey()
	if err != nil {
		return wgKeyPair{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return wgKeyPair{}, fmt.Errorf("wireguard: create key dir: %w", err)
	}
	// 0600: the private half is as sensitive as auth_token. Written to a temp
	// file and renamed so a crash cannot leave a half-written key that would
	// silently change this device's identity.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(kp.PrivateKey+"\n"), 0600); err != nil {
		return wgKeyPair{}, fmt.Errorf("wireguard: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return wgKeyPair{}, fmt.Errorf("wireguard: install %s: %w", path, err)
	}
	return kp, nil
}

// trimKey strips whitespace/newlines from a stored key file.
func trimKey(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// ── This host's live WireGuard identity ─────────────────────────────────────

var wgIdentity struct {
	mu        sync.RWMutex
	publicKey string
}

// SetWireGuardPublicKey records the public half once the identity is loaded, so
// status reporting can show it without re-reading the key file.
func SetWireGuardPublicKey(pub string) {
	wgIdentity.mu.Lock()
	wgIdentity.publicKey = pub
	wgIdentity.mu.Unlock()
}

// WireGuardPublicKey returns this host's public key, or "" before enrolment.
func WireGuardPublicKey() string {
	wgIdentity.mu.RLock()
	defer wgIdentity.mu.RUnlock()
	return wgIdentity.publicKey
}

// configPrivateKeyPlaceholder is what the Directory writes into a config for a
// device that generated its own keypair (mesh_client_conf.js). The server has
// no private key to put there and must not invent one.
const configPrivateKeyPlaceholder = "<generated on this device>"

// fillPrivateKey substitutes this host's real private key into a pushed
// WireGuard config.
//
// Without this the config reaches wg-quick containing the literal placeholder
// and the interface cannot come up -- the server-side comment says the agent
// "completes it with the key it already holds", but no agent ever held one.
// Returns the config unchanged when there is no placeholder, so a fully
// rendered config (an admin-generated one carrying its own key) still works.
func fillPrivateKey(conf, privateKey string) (string, error) {
	if !strings.Contains(conf, configPrivateKeyPlaceholder) {
		return conf, nil
	}
	if privateKey == "" {
		return "", fmt.Errorf("wireguard: config expects this device's private key but none is available")
	}
	return strings.ReplaceAll(conf, configPrivateKeyPlaceholder, privateKey), nil
}

// wgKeyPathOverride lets tests point the identity at a temp file instead of the
// real system path. Empty means "use defaultWireGuardKeyPath()".
var wgKeyPathOverride string

// fillPrivateKeyFromHost substitutes this host's private key into a pushed
// config, loading (or creating) the identity ONLY when the config actually
// carries the placeholder. A fully rendered config -- one an admin generated
// with its own key -- is returned untouched without going near the key file.
func fillPrivateKeyFromHost(conf string) (string, error) {
	if !strings.Contains(conf, configPrivateKeyPlaceholder) {
		return conf, nil
	}
	kp, err := LoadOrCreateWireGuardKey(wgKeyPathOverride)
	if err != nil {
		return "", err
	}
	return fillPrivateKey(conf, kp.PrivateKey)
}
