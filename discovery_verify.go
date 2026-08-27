package main

// Certificate verification for local-discovery's hosts override.
//
// Local discovery repoints the directory's hostname at a LAN address found
// over mDNS. That is a name-resolution change only -- it never relaxes TLS
// (see local_discovery.go's HARD RULE) -- but the shipped version applied the
// override without first checking that the LAN address actually serves a
// certificate valid for that hostname, and a failed handshake afterwards is
// not a private problem: /etc/hosts is system-wide, so the browser, curl and
// every other client on the machine break too.
//
// That is not a corner case. Wherever TLS terminates at an edge the LAN
// address is not behind -- a wildcard cert on a border reverse proxy, a
// tunnel provider, a corporate ingress -- the internal address answers with
// something else. An OpenResty/lua-resty-auto-ssl data plane, which the suite
// itself ships, answers with its `sni-support-required-for-valid-ssl`
// self-signed fallback for any SNI it has not issued for, so the override
// turns a working public path into a hard TLS failure for the whole host.
//
// So: verify first, override second. The check is the same verification the
// agent's own HTTPS client would do -- system trust store, hostname match --
// against the discovered address, with SNI set to the real hostname. An
// internal CA in the system store passes, which is the intended case; a
// self-signed fallback does not, which is the case that broke.

import (
	"crypto/tls"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

// discoveryTLSTimeout bounds the verification handshake. Generous relative to
// a LAN round-trip on purpose: a timeout is indistinguishable from a bad
// certificate at the call site, so a tight bound would refuse a perfectly good
// override on a slow link. Measured against a real deployment, an OpenResty
// data plane that has to fall back to its self-signed certificate takes 4-5s
// to answer, and a 4s bound reported "context deadline exceeded" instead of
// the honest reason. Still well inside the 30s discovery poll.
const discoveryTLSTimeout = 12 * time.Second

// discoveryVerifyPort is the port the override's correctness is judged on.
// Local discovery only ever repoints https hostnames, and the agent reaches
// the directory on 443.
const discoveryVerifyPort = "443"

// serverURLUsesTLS reports whether the configured directory URL is a TLS
// scheme. A plain-http directory has no certificate to check, so the override
// cannot break one.
func serverURLUsesTLS(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		return true
	}
	return false
}

// lanCertValidFor reports whether ip serves a certificate that fully validates
// for host: chains to the system trust store and matches the name. This is
// deliberately the strict check -- the point is to predict whether ordinary
// clients on this machine will still work once the hosts override is in place.
//
// verifyTLSDial is a var so tests can drive both outcomes without a real
// listener and a real CA.
var verifyTLSDial = func(addr, serverName string) error {
	d := &net.Dialer{Timeout: discoveryTLSTimeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	return conn.Close()
}

func lanCertValidFor(host, ip string) bool {
	addr := net.JoinHostPort(ip, discoveryVerifyPort)
	if err := verifyTLSDial(addr, host); err != nil {
		log.Printf("[local-discovery] %s at %s does not serve a certificate valid for that name (%v)", host, ip, err)
		return false
	}
	return true
}

// overrideIsSafe decides whether pointing host at ip is safe to commit.
// Only TLS directories are ever overridden: the certificate check is what
// proves the LAN address actually serves this hostname, and a plain-http
// directory has no such proof — committing the override would repoint
// system-wide DNS at an unverified address. (The shipped version exempted
// http and broke whole hosts.)
func overrideIsSafe(serverURL, host, ip string) bool {
	if !serverURLUsesTLS(serverURL) {
		return false
	}
	return lanCertValidFor(host, ip)
}
