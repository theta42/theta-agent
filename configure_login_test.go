package main

import (
	"strings"
	"testing"
)

func TestOpenCredentialValues(t *testing.T) {
	vals := openCredentialValues("dc=example,dc=com", "admins", "Administrators")

	get := func(name string) *regValue {
		for i := range vals {
			if vals[i].name == name {
				return &vals[i]
			}
		}
		return nil
	}

	order := get("IPluginAuthentication_Order")
	if order == nil || len(order.multi) != 2 || order.multi[0] != ldapUuid || order.multi[1] != localMachineUuid {
		t.Fatalf("auth order wrong: %+v", order)
	}
	gw := get("IPluginAuthenticationGateway_Order")
	if gw == nil || len(gw.multi) != 1 || gw.multi[0] != ldapUuid {
		t.Fatalf("gateway order wrong: %+v", gw)
	}

	host := get("LdapHost")
	if host == nil || len(host.multi) != 1 || host.multi[0] != "127.0.0.1" {
		t.Errorf("LdapHost wrong: %+v", host)
	}
	port := get("LdapPort")
	if port == nil || !port.isDword || port.dword != 389 {
		t.Errorf("LdapPort wrong: %+v", port)
	}
	dn := get("DnPattern")
	if dn == nil || dn.str != "uid=%u,ou=people,dc=example,dc=com" {
		t.Errorf("DnPattern wrong: %+v", dn)
	}
	memberAttrib := get("GroupMemberAttrib")
	if memberAttrib == nil || memberAttrib.str != "member" {
		t.Errorf("GroupMemberAttrib wrong: %+v", memberAttrib)
	}

	// LDAP plugin: authenticate (2) + gateway (8) = 10; LocalMachine: auth (2).
	var ldapState, localState *regValue
	for i := range vals {
		if vals[i].key == "Plugins\\"+ldapUuid && vals[i].name == "" {
			ldapState = &vals[i]
		}
		if vals[i].key == "Plugins\\"+localMachineUuid && vals[i].name == "" {
			localState = &vals[i]
		}
	}
	if ldapState == nil || ldapState.dword != 10 {
		t.Errorf("LDAP plugin state wrong: %+v", ldapState)
	}
	if localState == nil || localState.dword != 2 {
		t.Errorf("LocalMachine state wrong: %+v", localState)
	}

	// Gateway rule maps the admin group to local Administrators.
	rules := get("GroupGatewayRules")
	if rules == nil || len(rules.multi) != 1 {
		t.Fatalf("GroupGatewayRules wrong: %+v", rules)
	}
	want := "cn=admins,ou=groups,dc=example,dc=com\n0\nAdministrators"
	if rules.multi[0] != want {
		t.Errorf("gateway rule = %q, want %q", rules.multi[0], want)
	}
}

func TestEnsureLdapTunnel_LinePresent(t *testing.T) {
	doc := "server_url: \"https://sso.example.com\"\ncapabilities:\n  ldap_tunnel: false\n  reboot: true\n"
	out := ensureLdapTunnel(doc)
	if !strings.Contains(out, "ldap_tunnel: true") {
		t.Fatalf("expected ldap_tunnel: true, got:\n%s", out)
	}
	if strings.Contains(out, "ldap_tunnel: false") {
		t.Fatalf("old value not replaced:\n%s", out)
	}
}

func TestEnsureLdapTunnel_NoCapabilities(t *testing.T) {
	doc := "server_url: \"https://sso.example.com\"\njoin_key: \"tjk_x\"\n"
	out := ensureLdapTunnel(doc)
	if !strings.Contains(out, "capabilities:\n  ldap_tunnel: true") {
		t.Fatalf("expected capabilities block added, got:\n%s", out)
	}
	if !strings.Contains(out, "server_url") {
		t.Fatalf("existing content clobbered:\n%s", out)
	}
}

func TestEnsureLdapTunnel_CapabilitiesEmpty(t *testing.T) {
	doc := "capabilities:\n"
	out := ensureLdapTunnel(doc)
	if !strings.Contains(out, "capabilities:\n  ldap_tunnel: true") {
		t.Fatalf("expected ldap_tunnel under empty capabilities, got:\n%s", out)
	}
}

func TestEnsureCapability_ConfigureLdap(t *testing.T) {
	doc := "server_url: x\ncapabilities:\n  telemetry: true\n  configure_ldap: false\n"
	out := ensureCapability(doc, "configure_ldap")
	if !strings.Contains(out, "  configure_ldap: true") {
		t.Fatalf("expected configure_ldap: true, got:\n%s", out)
	}
	if strings.Contains(out, "configure_ldap: false") {
		t.Fatalf("old value not replaced:\n%s", out)
	}
}

func TestParseSSSDBaseDN(t *testing.T) {
	cfg := `
[domain/default]
ldap_search_base = dc=laptop-dev,dc=vm42,dc=us
ldap_user_search_base = ou=people,dc=laptop-dev,dc=vm42,dc=us
ldap_group_search_base = ou=groups,dc=laptop-dev,dc=vm42,dc=us
ldap_sudo_search_base = ou=people,dc=laptop-dev,dc=vm42,dc=us
`
	if got := parseSSSDBaseDN(cfg); got != "dc=laptop-dev,dc=vm42,dc=us" {
		t.Errorf("parseSSSDBaseDN = %q, want dc=laptop-dev,dc=vm42,dc=us", got)
	}
	// ldap_user_search_base etc. must not be mistaken for ldap_search_base.
	if got := parseSSSDBaseDN("ldap_user_search_base = dc=wrong\n"); got != "" {
		t.Errorf("matched a non-exact search base: %q", got)
	}
	if got := parseSSSDBaseDN(""); got != "" {
		t.Errorf("empty config should yield empty DN, got %q", got)
	}
}
