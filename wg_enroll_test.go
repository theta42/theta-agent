package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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
	ensureMeshIdentity(&ConfigManager{current: cfg})
	refreshMeshExits(cfg)
	if called {
		t.Fatalf("mesh endpoints were called with the wireguard capability off")
	}
}

// A self-enrolling host dials the WebSocket with its join key and is handed a
// real auth token a moment later. Enrolment must not burn its single attempt
// on the join key: the REST endpoint rejects it, and the shipped version then
// never tried again for the life of the connection, leaving the device with no
// mesh row at all.
func TestEnsureMeshIdentityWaitsForAuthTokenThenEnrols(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	wgKeyPathOverride = filepath.Join(t.TempDir(), "wg.key")
	defer func() { wgKeyPathOverride = "" }()

	var mu sync.Mutex
	var seenTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenTokens = append(seenTokens, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.URL.Path == "/api/v1/agent/mesh/enroll" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"client":{"id":"d1","name":"host","assignedIp":"10.1.0.9","siteId":1}}`))
			return
		}
		w.Write([]byte(`{"exits":[],"current":null}`))
	}))
	defer srv.Close()

	// Start with only a join key, exactly as a fresh host does.
	cm := &ConfigManager{current: &Config{ServerURL: srv.URL, JoinKey: "join-key"}}

	prevDelay := meshEnrolRetryDelay
	meshEnrolRetryDelay = 5 * time.Millisecond
	defer func() { meshEnrolRetryDelay = prevDelay }()

	done := make(chan struct{})
	go func() { ensureMeshIdentity(cm); close(done) }()

	// The token arrives over the WebSocket shortly after the dial.
	time.Sleep(20 * time.Millisecond)
	cm.mu.Lock()
	cm.current = &Config{ServerURL: srv.URL, JoinKey: "join-key", AuthToken: "real-token"}
	cm.mu.Unlock()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ensureMeshIdentity never completed after the auth token appeared")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenTokens) == 0 {
		t.Fatal("never reached the directory at all")
	}
	for _, tok := range seenTokens {
		if strings.Contains(tok, "join-key") {
			t.Fatalf("enrolled with the join key, which the REST API rejects: %q", tok)
		}
	}
}

// The retry must re-read the config rather than a snapshot: retrying a
// captured join key would resend the credential that cannot work.
func TestEnsureMeshIdentityGivesUpWithoutAToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	wgKeyPathOverride = filepath.Join(t.TempDir(), "wg.key")
	defer func() { wgKeyPathOverride = "" }()

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	prevDelay, prevMax := meshEnrolRetryDelay, meshEnrolMaxAttempts
	meshEnrolRetryDelay, meshEnrolMaxAttempts = time.Millisecond, 3
	defer func() { meshEnrolRetryDelay, meshEnrolMaxAttempts = prevDelay, prevMax }()

	ensureMeshIdentity(&ConfigManager{current: &Config{ServerURL: srv.URL, JoinKey: "join-key"}})
	if called {
		t.Fatal("contacted the mesh REST API with only a join key")
	}
}

// A Directory without the endpoint will never grow one mid-connection.
// Retrying it twenty times per reconnect just fills both logs.
func TestEnsureMeshIdentityStopsWhenTheDirectoryHasNoMeshEndpoint(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	wgKeyPathOverride = filepath.Join(t.TempDir(), "wg.key")
	defer func() { wgKeyPathOverride = "" }()

	var mu sync.Mutex
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Page not found"}`))
	}))
	defer srv.Close()

	prevDelay, prevMax := meshEnrolRetryDelay, meshEnrolMaxAttempts
	meshEnrolRetryDelay, meshEnrolMaxAttempts = time.Millisecond, 10
	defer func() { meshEnrolRetryDelay, meshEnrolMaxAttempts = prevDelay, prevMax }()

	ensureMeshIdentity(&ConfigManager{current: &Config{ServerURL: srv.URL, AuthToken: "tok"}})

	mu.Lock()
	defer mu.Unlock()
	if attempts != 1 {
		t.Fatalf("kept retrying an endpoint that does not exist: %d attempts", attempts)
	}
}

// ...but an ordinary rejection is worth retrying: the credential may be about
// to change, or the far end may be briefly unhappy.
func TestEnsureMeshIdentityRetriesATransientRejection(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	wgKeyPathOverride = filepath.Join(t.TempDir(), "wg.key")
	defer func() { wgKeyPathOverride = "" }()

	var mu sync.Mutex
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n < 3 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message":"unauthorized"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"client":{"id":"d1","name":"host","assignedIp":"10.1.0.9","siteId":1}}`))
	}))
	defer srv.Close()

	prevDelay, prevMax := meshEnrolRetryDelay, meshEnrolMaxAttempts
	meshEnrolRetryDelay, meshEnrolMaxAttempts = time.Millisecond, 10
	defer func() { meshEnrolRetryDelay, meshEnrolMaxAttempts = prevDelay, prevMax }()

	ensureMeshIdentity(&ConfigManager{current: &Config{ServerURL: srv.URL, AuthToken: "tok"}})

	mu.Lock()
	defer mu.Unlock()
	if attempts < 3 {
		t.Fatalf("gave up before the far end recovered: %d attempts", attempts)
	}
}
