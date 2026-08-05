package main

import (
	"encoding/json"
	"os"
	"testing"
)

// Cross-implementation check: a payload signed by the Node server (utils/
// agent_manager.js) must verify with the agent's own verifySignature. Skips
// unless the fixture is present, so it never breaks a normal `go test`.
func TestInteropWithServerSignature(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("INTEROP_FIXTURE"))
	if err != nil {
		t.Skip("no INTEROP_FIXTURE provided")
	}
	var fx struct {
		Pub     string                 `json:"pub"`
		Payload map[string]interface{} `json:"payload"`
		Sig     string                 `json:"sig"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	payload := map[string]interface{}{}
	for k, v := range fx.Payload {
		payload[k] = v
	}
	payload["signature"] = fx.Sig

	cfg := &Config{PublicKey: fx.Pub}
	if !verifySignature(cfg, WSMessage{Type: "arbitrary_bash", Payload: payload}) {
		t.Fatal("agent REJECTED a signature produced by the SSO server")
	}
	t.Log("agent accepted the server-produced signature")
}
