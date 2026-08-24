package main

// Mesh self-enrolment: tell the Directory this host's WireGuard public key.
//
// The Directory can only build a peer entry for a device it has a public key
// for, and jump-host's mesh view lists exactly those devices. Before this, the
// only way to create one was an admin POSTing /api/mesh/clients by hand, so an
// installed agent never showed up and could not be routed to.
//
// Only the public half is sent. The private key stays in
// /etc/theta42/wg_private.key (or %ProgramData%\Theta42\wg\private.key) for the
// life of the host.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// MeshDevice is what the Directory hands back once this host has a mesh
// identity: the address it allocated and the exit it is currently routed
// through.
type MeshDevice struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	AssignedIP string `json:"assignedIp"`
	SiteID     int    `json:"siteId"`
	ExitSiteID *int   `json:"exitSiteId"`
}

// httpBaseURL converts the configured ws(s):// server URL into the http(s)://
// form the REST endpoints live on.
func httpBaseURL(serverURL string) string {
	base := strings.Replace(serverURL, "wss://", "https://", 1)
	base = strings.Replace(base, "ws://", "http://", 1)
	return strings.TrimRight(base, "/")
}

// enrollMeshIdentity registers this host's WireGuard public key with the
// Directory. Idempotent at both ends: the key is stable across restarts and the
// server converges on one device row per agent, so calling it on every connect
// is safe and repairs a device row deleted at the far end.
func enrollMeshIdentity(cfg *Config, pubKey string) (*MeshDevice, error) {
	if !meshPubKeyRe.MatchString(pubKey) {
		return nil, fmt.Errorf("refusing to enrol a malformed public key %q", pubKey)
	}
	url := httpBaseURL(cfg.ServerURL) + "/api/v1/agent/mesh/enroll"
	body, _ := json.Marshal(map[string]string{"publicKey": pubKey})

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Credential())

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Message == "" {
			e.Message = resp.Status
		}
		return nil, fmt.Errorf("mesh enrol failed (%s): %s", resp.Status, e.Message)
	}

	var out struct {
		Client  MeshDevice `json:"client"`
		Rotated bool       `json:"rotated"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("mesh enrol: could not read response: %w", err)
	}
	if out.Rotated {
		log.Printf("[mesh] public key rotated at the directory for device %s", out.Client.Name)
	}
	return &out.Client, nil
}

// ensureMeshIdentity loads (or creates) this host's key and enrols it. Called
// once the agent is connected and authenticated. Best-effort: a Directory that
// does not support mesh enrolment, or is briefly unreachable, must not stop the
// agent doing everything else.
func ensureMeshIdentity(cfg *Config) {
	if !cfg.Capabilities.WireGuardEnabled() {
		return
	}
	kp, err := LoadOrCreateWireGuardKey("")
	if err != nil {
		log.Printf("[mesh] could not establish a WireGuard identity: %v", err)
		return
	}
	SetWireGuardPublicKey(kp.PublicKey)

	device, err := enrollMeshIdentity(cfg, kp.PublicKey)
	if err != nil {
		log.Printf("[mesh] could not enrol with the directory: %v", err)
		return
	}
	log.Printf("[mesh] enrolled as %q at %s (site %d)", device.Name, device.AssignedIP, device.SiteID)

	// The device row now exists, so the exit list is answerable.
	refreshMeshExits(cfg)
}

// ── Exit selection ──────────────────────────────────────────────────────────

// MeshExit is one site this device may route its internet traffic through.
type MeshExit struct {
	SiteID  int    `json:"siteId"`
	Name    string `json:"name"`
	Country string `json:"country"`
	City    string `json:"city"`
	IsLocal bool   `json:"isLocal"`
}

// fetchMeshExits reads the exits this device may choose and the one it is
// currently on. A nil current means local breakout.
func fetchMeshExits(cfg *Config) (exits []MeshExit, current *int, err error) {
	url := httpBaseURL(cfg.ServerURL) + "/api/v1/agent/mesh/exits"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Credential())

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("mesh exits: %s", resp.Status)
	}

	var out struct {
		Current *int       `json:"current"`
		Exits   []MeshExit `json:"exits"`
	}
	if derr := json.NewDecoder(resp.Body).Decode(&out); derr != nil {
		return nil, nil, derr
	}
	return out.Exits, out.Current, nil
}

// setMeshExit routes this device through siteId, or through its local breakout
// when siteId is nil. The Directory pushes the new peer config back down the
// WSS channel on success, so there is nothing to apply here.
func setMeshExit(cfg *Config, siteID *int) error {
	url := httpBaseURL(cfg.ServerURL) + "/api/v1/agent/mesh/exit"
	body, _ := json.Marshal(map[string]interface{}{"siteId": siteID})

	req, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Credential())

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Message == "" {
			e.Message = resp.Status
		}
		return fmt.Errorf("%s", e.Message)
	}
	return nil
}

// refreshMeshExits pulls the exit list and current selection into the shared
// state the tray status is built from. Best-effort: a directory that is
// unreachable or too old to serve exits leaves the tray showing what it last
// knew rather than an empty picker.
func refreshMeshExits(cfg *Config) {
	if !cfg.Capabilities.WireGuardEnabled() {
		return
	}
	exits, current, err := fetchMeshExits(cfg)
	if err != nil {
		log.Printf("[mesh] could not read exit choices: %v", err)
		return
	}
	tray := make([]TrayExit, 0, len(exits))
	for _, e := range exits {
		tray = append(tray, TrayExit{
			SiteID: e.SiteID, Name: e.Name, Country: e.Country, City: e.City, IsLocal: e.IsLocal,
		})
	}
	SetMeshExits(tray, current)
}
