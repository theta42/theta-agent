//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

// TestWriteRegValues exercises the registry writer against a scratch key
// under HKCU so no real OpenCredential config is touched, then cleans up.
func TestWriteRegValues(t *testing.T) {
	const root = `SOFTWARE\ThetaAgentTest\OpenCredential`
	registry.DeleteKey(registry.CURRENT_USER, root)
	defer registry.DeleteKey(registry.CURRENT_USER, root)

	k, _, err := registry.CreateKey(registry.CURRENT_USER, root, registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		t.Fatalf("create scratch key: %v", err)
	}
	defer k.Close()

	vals := []regValue{
		{name: "IPluginAuthentication_Order", multi: []string{ldapUuid, localMachineUuid}},
		{key: "Plugins\\" + ldapUuid, dword: 10, isDword: true},
		{key: "Plugins\\" + ldapUuid, name: "LdapHost", multi: []string{"127.0.0.1"}},
		{key: "Plugins\\" + ldapUuid, name: "DnPattern", str: "uid=%u,ou=people,dc=example,dc=com"},
		{key: "Plugins\\" + ldapUuid, name: "GroupGatewayRules", multi: []string{"cn=admins,ou=groups,dc=example,dc=com\n0\nAdministrators"}},
	}
	if err := writeRegValues(k, vals); err != nil {
		t.Fatalf("writeRegValues: %v", err)
	}

	// Verify round-trip (re-open with read access; the write handle lacked it).
	k2, err := registry.OpenKey(registry.CURRENT_USER, root, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("reopen root: %v", err)
	}
	defer k2.Close()
	order, _, err := k2.GetStringsValue("IPluginAuthentication_Order")
	if err != nil || len(order) != 2 || order[0] != ldapUuid {
		t.Fatalf("order round-trip failed: %v %v", order, err)
	}
	plugin, err := registry.OpenKey(registry.CURRENT_USER, root+`\Plugins\`+ldapUuid, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("open plugin key: %v", err)
	}
	defer plugin.Close()
	if state, _, err := plugin.GetIntegerValue(""); err != nil || state != 10 {
		t.Errorf("plugin state = %d, %v; want 10", state, err)
	}
	if host, _, err := plugin.GetStringsValue("LdapHost"); err != nil || len(host) != 1 || host[0] != "127.0.0.1" {
		t.Errorf("LdapHost = %v, %v", host, err)
	}
	rules, _, err := plugin.GetStringsValue("GroupGatewayRules")
	if err != nil || len(rules) != 1 || rules[0] != "cn=admins,ou=groups,dc=example,dc=com\n0\nAdministrators" {
		t.Errorf("GroupGatewayRules = %q, %v", rules, err)
	}
}
