package main

import (
	"errors"
	"testing"
)

// A plain-http directory has no certificate the override could break, so the
// check must not gate it (and must not dial).
func TestOverrideIsSafeSkipsVerificationForNonTLS(t *testing.T) {
	prev := verifyTLSDial
	dialed := false
	verifyTLSDial = func(addr, serverName string) error {
		dialed = true
		return errors.New("should not have been called")
	}
	defer func() { verifyTLSDial = prev }()

	for _, u := range []string{"http://sso.example.com", "ws://sso.example.com"} {
		if !overrideIsSafe(u, "sso.example.com", "192.168.1.5") {
			t.Fatalf("%s: a non-TLS directory has no certificate to break", u)
		}
	}
	if dialed {
		t.Fatal("verified TLS for a directory that does not use TLS")
	}
}

// The reported failure: the LAN address answers, but with something else --
// here, the self-signed `sni-support-required-for-valid-ssl` fallback that the
// suite's own OpenResty data plane serves for any SNI it has not issued for.
// Committing the override then breaks TLS for every client on the machine,
// because /etc/hosts is system-wide, while the public path was working fine.
func TestOverrideIsRefusedWhenLanCertDoesNotValidate(t *testing.T) {
	prev := verifyTLSDial
	verifyTLSDial = func(addr, serverName string) error {
		return errors.New("x509: certificate signed by unknown authority")
	}
	defer func() { verifyTLSDial = prev }()

	if overrideIsSafe("https://sso.example.com", "sso.example.com", "192.168.1.5") {
		t.Fatal("override was allowed against an address serving an invalid certificate")
	}
}

func TestOverrideIsAllowedWhenLanCertValidates(t *testing.T) {
	prev := verifyTLSDial
	var gotAddr, gotName string
	verifyTLSDial = func(addr, serverName string) error {
		gotAddr, gotName = addr, serverName
		return nil
	}
	defer func() { verifyTLSDial = prev }()

	if !overrideIsSafe("wss://sso.example.com", "sso.example.com", "192.168.1.5") {
		t.Fatal("a valid certificate at the LAN address must permit the override")
	}
	// SNI has to carry the real hostname -- verifying against the IP would
	// always fail and would defeat the check.
	if gotAddr != "192.168.1.5:443" {
		t.Fatalf("verified the wrong address: %q", gotAddr)
	}
	if gotName != "sso.example.com" {
		t.Fatalf("verified with the wrong SNI: %q", gotName)
	}
}

func TestServerURLUsesTLS(t *testing.T) {
	cases := map[string]bool{
		"https://a.example.com": true,
		"wss://a.example.com":   true,
		"WSS://a.example.com":   true,
		"http://a.example.com":  false,
		"ws://a.example.com":    false,
		"":                      false,
		"::not a url":           false,
	}
	for in, want := range cases {
		if got := serverURLUsesTLS(in); got != want {
			t.Errorf("serverURLUsesTLS(%q) = %v, want %v", in, got, want)
		}
	}
}
