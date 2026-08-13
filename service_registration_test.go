package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddRemoveYamlListItem(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		key     string
		item    string
		subtype string
		remove  bool
		wantSub string
		wantErr bool
	}{
		{
			name:    "adds to existing empty block",
			doc:     "services: []\ncapabilities:\n  telemetry: true\n",
			key:     "services",
			item:    "nginx",
			wantSub: "services:\n  - nginx\n",
		},
		{
			name:    "appends after existing items",
			doc:     "services:\n  - nginx\ncapabilities:\n  telemetry: true\n",
			key:     "services",
			item:    "gitea",
			wantSub: "services:\n  - nginx\n  - gitea\n",
		},
		{
			name:    "duplicate rejected",
			doc:     "services:\n  - nginx\n",
			key:     "services",
			item:    "nginx",
			wantErr: true,
		},
		{
			name:    "creates block when absent",
			doc:     "server_url: x\n",
			key:     "services",
			item:    "nginx",
			wantSub: "services:\n  - nginx\n",
		},
		{
			name:    "removes existing item",
			doc:     "services:\n  - nginx\n  - gitea\n",
			key:     "services",
			item:    "nginx",
			remove:  true,
			wantSub: "services:\n  - gitea\n",
		},
		{
			name:    "adds object entry with subtype",
			doc:     "services: []\n",
			key:     "services",
			item:    "nginx",
			subtype: "docker",
			wantSub: "services:\n  - name: nginx\n    subtype: docker\n",
		},
		{
			name:    "remove of absent item errors",
			doc:     "services:\n  - gitea\n",
			key:     "services",
			item:    "nginx",
			remove:  true,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				out string
				err error
			)
			if tc.remove {
				out, err = removeYamlListItem(tc.doc, tc.key, tc.item)
			} else {
				out, err = addYamlListItem(tc.doc, tc.key, tc.item, tc.subtype)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none; out=%q", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantSub != "" && !strings.Contains(out, tc.wantSub) {
				t.Fatalf("output missing %q:\n%s", tc.wantSub, out)
			}
		})
	}
}

func TestPersistServiceRoundTrip(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "persist-service")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "agent.yml")
	content := "server_url: \"https://sso.local\"\nauth_token: \"tok\"\npublic_key: \"k\"\nservices: []\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cm, err := NewConfigManager(path)
	if err != nil {
		t.Fatal(err)
	}

	// Add
	if err := cm.PersistService("nginx", "systemd", false); err != nil {
		t.Fatal(err)
	}
	if got := cm.Get().Services; len(got) != 1 || got[0].Name != "nginx" || got[0].SubType != "systemd" {
		t.Fatalf("expected [nginx/systemd], got %v", got)
	}

	// Add second
	if err := cm.PersistService("gitea", "systemd", false); err != nil {
		t.Fatal(err)
	}
	if got := cm.Get().Services; len(got) != 2 {
		t.Fatalf("expected 2 services, got %v", got)
	}

	// Duplicate must fail
	if err := cm.PersistService("nginx", "systemd", false); err == nil {
		t.Fatal("expected duplicate-add error")
	}

	// Remove
	if err := cm.PersistService("nginx", "systemd", true); err != nil {
		t.Fatal(err)
	}
	if got := cm.Get().Services; len(got) != 1 || got[0].Name != "gitea" {
		t.Fatalf("expected [gitea], got %v", got)
	}

	// Add a docker service and verify its subtype round-trips.
	if err := cm.PersistService("nginx-proxy", "docker", false); err != nil {
		t.Fatal(err)
	}
	if got := cm.Get().Services; len(got) != 2 || got[1].Name != "nginx-proxy" || got[1].SubType != "docker" {
		t.Fatalf("expected docker subtype, got %v", got)
	}

	// Comments/other lines preserved
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "public_key: \"k\"") {
		t.Fatalf("unrelated config line was clobbered:\n%s", raw)
	}
}
