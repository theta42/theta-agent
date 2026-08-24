package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testConfig(serverURL string) *Config {
	enabled := true
	return &Config{
		ServerURL:    serverURL,
		AuthToken:    "tok-abc",
		Capabilities: Capabilities{WireGuard: &enabled},
	}
}

const goodPubKey = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="

func TestHTTPBaseURLConvertsWebSocketSchemes(t *testing.T) {
	cases := map[string]string{
		"wss://sso.example.com":        "https://sso.example.com",
		"ws://sso.example.com":         "http://sso.example.com",
		"https://sso.example.com/":     "https://sso.example.com",
		"https://sso.example.com:8443": "https://sso.example.com:8443",
	}
	for in, want := range cases {
		if got := httpBaseURL(in); got != want {
			t.Fatalf("httpBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnrollMeshIdentitySendsPublicKeyAndToken(t *testing.T) {
	var gotPath, gotAuth, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		gotKey = in["publicKey"]
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"ok","client":{"id":"d1","name":"laptop","assignedIp":"10.2.128.1","siteId":2}}`))
	}))
	defer srv.Close()

	device, err := enrollMeshIdentity(testConfig(srv.URL), goodPubKey)
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if gotPath != "/api/v1/agent/mesh/enroll" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer tok-abc" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotKey != goodPubKey {
		t.Fatalf("public key = %q", gotKey)
	}
	if device.AssignedIP != "10.2.128.1" || device.SiteID != 2 {
		t.Fatalf("device decoded wrong: %+v", device)
	}
}

// The private half must never be in the request. This is the promise that lets
// the Directory say it does not store client private keys.
func TestEnrollMeshIdentityNeverSendsAPrivateKey(t *testing.T) {
	var raw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		raw = string(b)
		_, _ = w.Write([]byte(`{"status":"ok","client":{}}`))
	}))
	defer srv.Close()

	kp, err := generateWireGuardKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := enrollMeshIdentity(testConfig(srv.URL), kp.PublicKey); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if len(raw) == 0 {
		t.Fatalf("no request body captured")
	}
	if strings.Contains(raw, kp.PrivateKey) {
		t.Fatalf("the private key was sent to the server: %s", raw)
	}
	if strings.Contains(raw, "privateKey") || strings.Contains(raw, "private_key") {
		t.Fatalf("request carries a private-key field: %s", raw)
	}
}

// A malformed key is caught before it goes out, rather than coming back as a
// 400 the agent would have to interpret.
func TestEnrollMeshIdentityRejectsMalformedKeyLocally(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	if _, err := enrollMeshIdentity(testConfig(srv.URL), "not-a-key"); err == nil {
		t.Fatalf("expected a refusal for a malformed key")
	}
	if called {
		t.Fatalf("a malformed key was sent to the server anyway")
	}
}

func TestEnrollMeshIdentitySurfacesServerMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"status":"error","message":"this node has no site id yet"}`))
	}))
	defer srv.Close()

	_, err := enrollMeshIdentity(testConfig(srv.URL), goodPubKey)
	if err == nil {
		t.Fatalf("expected an error")
	}
	if !strings.Contains(err.Error(), "no site id") {
		t.Fatalf("server message was lost: %v", err)
	}
}

func TestFetchMeshExitsDecodesCurrentAndList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","current":5,"exits":[
			{"siteId":2,"name":"HQ","country":"US","city":"Austin","isLocal":true},
			{"siteId":5,"name":"LON","country":"GB","city":"London","isLocal":false}]}`))
	}))
	defer srv.Close()

	exits, current, err := fetchMeshExits(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if current == nil || *current != 5 {
		t.Fatalf("current = %v, want 5", current)
	}
	if len(exits) != 2 || exits[0].Name != "HQ" || !exits[0].IsLocal || exits[1].SiteID != 5 {
		t.Fatalf("exits decoded wrong: %+v", exits)
	}
}

// Local breakout is null on the wire, not 0 -- 0 is a plausible site id.
func TestFetchMeshExitsLocalBreakoutIsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","current":null,"exits":[]}`))
	}))
	defer srv.Close()

	_, current, err := fetchMeshExits(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if current != nil {
		t.Fatalf("current = %d, want nil for local breakout", *current)
	}
}

func TestSetMeshExitSendsSiteIDAndMethod(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"status":"ok","current":5,"pushed":true}`))
	}))
	defer srv.Close()

	site := 5
	if err := setMeshExit(testConfig(srv.URL), &site); err != nil {
		t.Fatalf("set: %v", err)
	}
	if gotMethod != "PUT" || gotPath != "/api/v1/agent/mesh/exit" {
		t.Fatalf("%s %s", gotMethod, gotPath)
	}
	if !strings.Contains(gotBody, `"siteId":5`) {
		t.Fatalf("body = %s", gotBody)
	}
}

func TestSetMeshExitLocalBreakoutSendsNull(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	if err := setMeshExit(testConfig(srv.URL), nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	if !strings.Contains(gotBody, `"siteId":null`) {
		t.Fatalf("local breakout must send null, got %s", gotBody)
	}
}

// The capability gates the whole mesh path; with it off nothing should reach
// the network.
func TestEnsureMeshIdentitySkippedWhenCapabilityOff(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	off := false
	cfg := &Config{ServerURL: srv.URL, AuthToken: "t", Capabilities: Capabilities{WireGuard: &off}}
	ensureMeshIdentity(cfg)
	refreshMeshExits(cfg)
	if called {
		t.Fatalf("mesh endpoints were called with the wireguard capability off")
	}
}
