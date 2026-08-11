package main

import (
	"fmt"
	"regexp"
	"strings"
)

// LDAP logon via the bundled OpenCredential credential provider
// (DESIGN-WINDOWS.md §6). OpenCredential stores its whole configuration in the
// registry under HKLM\SOFTWARE\OpenCredential3 (this is pGina's keyed
// settings-store: plugin UUIDs drive the auth/gateway pipeline order, each
// plugin's enabled state sits in the default value of its Plugins\{GUID} key,
// and plugin settings are values under that key). Its installer wipes those
// keys, so `configure-login` must run after it — it is wired into the agent
// installer as a post-install step.
//
// The LDAP plugin authenticates a directory user by simple-bind as
// uid=<user>,ou=people,<base> on the agent's loopback LDAP tunnel
// (127.0.0.1:389) and, as the gateway, creates/updates the local account and
// applies local group membership — that last bit is how a directory admin
// ends up with Administrator on the host.

const (
	ldapUuid         = "0F52390B-C781-43AE-BD62-553C77FA4CF7"
	localMachineUuid = "12FA152D-A2E3-4C8D-9535-5DCD49DFCB6D"
)

// Plugin state bitmask (OpenCredential.PluginLoader.State): Authenticate=2,
// Gateway=8.
const (
	stateAuthenticate = 2
	stateGateway      = 8
)

// OpenCredential root registry key under HKLM.
const openCredentialRoot = `SOFTWARE\OpenCredential3`

// regValue is one registry value to write when seeding OpenCredential.
type regValue struct {
	key     string // sub-key path under the root ("" = the root itself)
	name    string // value name; "" = the key's default value
	multi   []string
	str     string
	dword   uint32
	isDword bool
}

// openCredentialValues returns the registry values that configure
// OpenCredential for directory logon against the agent's LDAP tunnel:
//   - LDAP plugin authenticates first (uid=<user>,ou=people,<base> at
//     127.0.0.1:389), LocalMachine plugin stays enabled as a fallback so a
//     local admin can never be locked out.
//   - LDAP plugin is also the gateway: directory users in the admin group are
//     added to the local admin group.
func openCredentialValues(baseDN, adminGroup, localAdminGroup string) []regValue {
	ldapKey := "Plugins\\" + ldapUuid
	adminDN := fmt.Sprintf("cn=%s,ou=groups,%s", adminGroup, baseDN)

	return []regValue{
		// Pipeline order: LDAP first, LocalMachine fallback.
		{name: "IPluginAuthentication_Order", multi: []string{ldapUuid, localMachineUuid}},
		{name: "IPluginAuthenticationGateway_Order", multi: []string{ldapUuid}},
		// Plugin enabled states (default value of each plugin key).
		{key: "Plugins\\" + ldapUuid, dword: stateAuthenticate | stateGateway, isDword: true},
		{key: "Plugins\\" + localMachineUuid, dword: stateAuthenticate, isDword: true},
		// LDAP plugin settings.
		{key: ldapKey, name: "LdapHost", multi: []string{"127.0.0.1"}},
		{key: ldapKey, name: "LdapPort", dword: 389, isDword: true},
		{key: ldapKey, name: "LdapTimeout", dword: 10, isDword: true},
		{key: ldapKey, name: "EncryptionMethod", dword: 0, isDword: true},
		{key: ldapKey, name: "RequireCert", dword: 0, isDword: true},
		{key: ldapKey, name: "DoSearch", dword: 0, isDword: true},
		{key: ldapKey, name: "DnPattern", str: "uid=%u,ou=people," + baseDN},
		{key: ldapKey, name: "GroupDnPattern", str: "cn=%g,ou=groups," + baseDN},
		{key: ldapKey, name: "GroupMemberAttrib", str: "member"},
		{key: ldapKey, name: "AuthzApplyToAllUsers", dword: 1, isDword: true},
		// Authorization: allow everyone the LDAP plugin authenticated.
		{key: ldapKey, name: "GroupAuthzRules", multi: []string{"\n2\n1"}},
		// Gateway: members of the directory admin group become local admins.
		{key: ldapKey, name: "GroupGatewayRules", multi: []string{
			fmt.Sprintf("%s\n0\n%s", adminDN, localAdminGroup),
		}},
	}
}

// ensureLdapTunnel turns the agent's ldap_tunnel capability on in the config
// document so the byte-pump listens on 127.0.0.1:389 for OpenCredential.
// Line-based, like the other config edits, so comments/formatting survive.
func ensureLdapTunnel(doc string) string {
	re := regexp.MustCompile(`(?m)^(\s*)ldap_tunnel:\s*\w+.*$`)
	if re.MatchString(doc) {
		return re.ReplaceAllString(doc, "${1}ldap_tunnel: true")
	}
	capRe := regexp.MustCompile(`(?m)^(capabilities:)\s*$`)
	if capRe.MatchString(doc) {
		return capRe.ReplaceAllString(doc, "$1\n  ldap_tunnel: true")
	}
	if !strings.HasSuffix(doc, "\n") {
		doc += "\n"
	}
	return doc + "capabilities:\n  ldap_tunnel: true\n"
}
