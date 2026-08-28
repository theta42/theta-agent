package main

import (
	"encoding/json"
	"testing"
)

// The tray is a separate binary with its own copy of these structs. A field
// renamed on one side and not the other fails silently -- the JSON just does
// not decode into anything -- so pin the wire names here.
func TestTrayStatusWireNames(t *testing.T) {
	site := 5
	b, err := json.Marshal(TrayStatus{
		Color: ColorGreen, Connected: true, ConfigPath: "/etc/theta42/agent.yml",
		Exits:             []TrayExit{{SiteID: 5, Name: "LON", Country: "GB", City: "London", IsLocal: false}},
		CurrentExitSiteID: &site,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"color", "connected", "config_path", "exits", "current_exit_site_id"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("TrayStatus is missing wire field %q: %s", key, b)
		}
	}
	exits := m["exits"].([]interface{})
	first := exits[0].(map[string]interface{})
	for _, key := range []string{"site_id", "name", "country", "city", "is_local"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("TrayExit is missing wire field %q: %s", key, b)
		}
	}
}

// Local breakout is "no exit", and it has to survive the wire as null rather
// than as site 0 -- which is a real site id shape.
func TestTrayCommandLocalBreakoutIsNull(t *testing.T) {
	b, _ := json.Marshal(TrayCommand{Command: "set_exit", SiteID: nil})
	var decoded TrayCommand
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.SiteID != nil {
		t.Fatalf("local breakout decoded as site %d, want nil", *decoded.SiteID)
	}
	if decoded.Command != "set_exit" {
		t.Fatalf("command = %q", decoded.Command)
	}
}

func TestTrayCommandCarriesSiteID(t *testing.T) {
	site := 7
	b, _ := json.Marshal(TrayCommand{Command: "set_exit", SiteID: &site})
	var decoded TrayCommand
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.SiteID == nil || *decoded.SiteID != 7 {
		t.Fatalf("site id did not survive the wire: %s", b)
	}
}

// The CLI's register/unregister hand the frame to the daemon over the same
// socket, so the service fields must survive the wire under the names the
// daemon's handler reads.
func TestTrayCommandServiceWireNames(t *testing.T) {
	b, _ := json.Marshal(TrayCommand{Command: "register_service", Service: "emby-server", Subtype: "systemd"})
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"command", "service", "subtype"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("TrayCommand is missing wire field %q: %s", key, b)
		}
	}
	if m["service"] != "emby-server" || m["subtype"] != "systemd" {
		t.Fatalf("service fields did not survive the wire: %s", b)
	}
}

// An older tray sends no site_id at all; that must mean local breakout, not a
// decode error.
func TestTrayCommandFromLegacyTray(t *testing.T) {
	var decoded TrayCommand
	if err := json.Unmarshal([]byte(`{"command":"vpn_connect","value":false}`), &decoded); err != nil {
		t.Fatalf("legacy command failed to decode: %v", err)
	}
	if decoded.SiteID != nil {
		t.Fatalf("legacy command produced a site id")
	}
}
