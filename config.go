package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Capabilities struct {
	Telemetry      bool     `yaml:"telemetry"`
	ConfigureLDAP  bool     `yaml:"configure_ldap"`
	Reboot         bool     `yaml:"reboot"`
	ServiceControl []string `yaml:"service_control"`
	ArbitraryBash  bool     `yaml:"arbitrary_bash"`
	LdapTunnel     bool     `yaml:"ldap_tunnel"`
	Secrets        bool     `yaml:"secrets"`
	IAM            bool     `yaml:"iam"`
	// A POINTER so an absent key is distinguishable from an explicit `false`.
	// This capability now defaults ON (see WireGuardEnabled): it gates the
	// whole auto-VPN path, and defaulting it off meant the tray's
	// "auto-connect VPN when away" checkbox silently did nothing on every
	// stock install -- the installer never wrote the key at all, so it was
	// false by omission rather than by anyone's decision.
	WireGuard           *bool `yaml:"wireguard"`
	ServiceRegistration bool  `yaml:"service_registration"`
}

// SecretTarget maps a local template to a rendered target file and an optional
// post-render reload command (DESIGN.md §5).
type SecretTarget struct {
	Template string `yaml:"template"`
	Target   string `yaml:"target"`
	Reload   string `yaml:"reload"`
}

// WireGuardConfig holds the mesh client settings (DESIGN-WINDOWS.md §5).
type WireGuardConfig struct {
	// TunnelName is the WireGuard interface (Linux) / service name (Windows).
	TunnelName string `yaml:"tunnel_name"`
	// Conf is where the pushed peer config is persisted on disk.
	Conf string `yaml:"conf"`
	// Executable is the wireguard.exe path (Windows); "" = PATH or default
	// install location.
	Executable string `yaml:"executable"`
}

type Config struct {
	ServerURL string `yaml:"server_url"`
	AuthToken string `yaml:"auth_token"`
	// A join key is the one credential an operator hands out. On first connect
	// the server exchanges it for a per-agent AuthToken (written back to this
	// file), so it is a bootstrap value, not a long-term credential. Used only
	// when AuthToken is empty.
	JoinKey    string         `yaml:"join_key"`
	Location   string         `yaml:"location"`
	PublicKey  string         `yaml:"public_key"`  // Ed25519 public key for signed commands
	LdapSocket string         `yaml:"ldap_socket"` // local LDAP tunnel socket (DESIGN.md §4)
	Secrets    []SecretTarget `yaml:"secrets"`     // secret templates to render (DESIGN.md §5)
	// Services are the services this agent has registered with the directory as
	// children of its host. Kept in agent.yml so the running daemon knows which
	// per-service metrics to report without the directory having to push the list
	// back down. Managed by `theta-agent register <type> <name>` /
	// `theta-agent unregister <type> <name>`, where <type> is systemd or docker.
	Services     []RegisteredService `yaml:"services"` // registered child services
	Capabilities Capabilities        `yaml:"capabilities"`

	// Windows-specific (DESIGN-WINDOWS.md §11).
	ServiceName    string          `yaml:"service_name"`     // Windows service name
	DesktopHelper  string          `yaml:"desktop_helper"`   // theta-agent-helper.exe path
	PublicIPDetect *bool           `yaml:"public_ip_detect"` // false disables external lookups (air-gap)
	AutoVPN        bool            `yaml:"auto_vpn"`         // auto-connect WireGuard when away
	WireGuard      WireGuardConfig `yaml:"wireguard"`
	// LocalDiscovery enables mDNS-based LAN shortcutting (local_discovery.go).
	// Default is true. Set to false to disable /etc/hosts and route overrides.
	LocalDiscovery *bool `yaml:"local_discovery"`

	// LDAP logon via the bundled OpenCredential credential provider
	// (DESIGN-WINDOWS.md §6). LdapBaseDN is the directory's LDAP base DN,
	// used to derive user/group DNs (uid=<user>,ou=people,<base>). Members of
	// LdapAdminGroup are granted LdapLocalAdminGroup (default Administrators)
	// on this host at logon.
	LdapBaseDN          string `yaml:"ldap_base_dn"`
	LdapAdminGroup      string `yaml:"ldap_admin_group"`
	LdapLocalAdminGroup string `yaml:"ldap_local_admin_group"`

	// White-labeling for the Windows logon tile (DESIGN-WINDOWS.md §6.1).
	// CredentialProviderName replaces the stock "OpenCredential" display name
	// shown under the tile on the Windows logon screen; empty keeps the
	// vendor default. CredentialProviderLogo is reserved: the tile bitmap is
	// a Win32 resource inside the provider DLL, so it cannot be applied from
	// config today — see docs/WHITE_LABELING.md for the supported paths.
	CredentialProviderName string `yaml:"credential_provider_name"`
	CredentialProviderLogo string `yaml:"credential_provider_logo"`

	// OrganizationName is pushed by the directory via the WebSocket config
	// frame. It overrides the hardcoded "Theta Agent" branding in the tray
	// and Windows logon tile. Falls back to local config / defaults.
	OrganizationName string
}

// DetectPublicIP reports whether the agent may perform external public-IP
// lookups. Defaults to true; an air-gapped host sets public_ip_detect: false so
// the agent never tries to reach ipify/icanhazip/etc.
func (c *Config) DetectPublicIP() bool {
	if c.PublicIPDetect == nil {
		return true
	}
	return *c.PublicIPDetect
}

// ServiceNameOrDefault returns the Windows service name, defaulting to
// theta-agent when unset.
func (c *Config) ServiceNameOrDefault() string {
	if c.ServiceName != "" {
		return c.ServiceName
	}
	return "theta-agent"
}

// Credential returns the value to present when connecting: our own token once
// enrolled, otherwise the join key.
func (c *Config) Credential() string {
	if c.AuthToken != "" {
		return c.AuthToken
	}
	return c.JoinKey
}

// ConfigManager handles thread-safe access and reloading of the agent configuration.
type ConfigManager struct {
	mu         sync.RWMutex
	current    *Config
	configPath string
	// Last observed size/mtime of configPath, for ReloadIfChanged. Zero until
	// the first call, which only establishes the baseline.
	lastSize int64
	lastMod  time.Time
}

func NewConfigManager(path string) (*ConfigManager, error) {
	cfg, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	return &ConfigManager{
		current:    cfg,
		configPath: path,
	}, nil
}

// Get returns a copy of the current configuration.
func (cm *ConfigManager) Get() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.current
}

// Reload re-reads the configuration from disk and updates the active config.
func (cm *ConfigManager) Reload() error {
	cfg, err := LoadConfig(cm.configPath)
	if err != nil {
		return fmt.Errorf("reload failed: %w", err)
	}
	cm.mu.Lock()
	cm.current = cfg
	cm.mu.Unlock()
	return nil
}

// ReloadIfChanged re-reads agent.yml when it has changed on disk since the last
// read, and reports whether it did.
//
// # THE BUG THIS EXISTS TO FIX
//
// `theta-agent register systemd <unit>` runs in its OWN process: it writes the
// service into agent.yml and asks the running daemon to push the frame over
// its own WebSocket (tray IPC; a one-shot connection only when the daemon is
// down). The DAEMON, which is what actually reports telemetry, holds its
// config in memory and had no reason to look at the file again -- so the newly
// registered service never appeared in `services:` on the wire. The Directory
// duly created the service resource from the registration frame, and then
// never received a single status sample for it: a resource in the tree with
// permanently empty live status, which is exactly what was reported. The same
// silence swallowed `theta-agent config-set` and any hand edit until the
// service was restarted.
//
// Compares size and mtime rather than hashing: agent.yml is written by rename,
// so a change always moves both.
func (cm *ConfigManager) ReloadIfChanged() (bool, error) {
	fi, err := os.Stat(cm.configPath)
	if err != nil {
		return false, err
	}
	cm.mu.Lock()
	unchanged := cm.lastSize == fi.Size() && cm.lastMod.Equal(fi.ModTime()) && !cm.lastMod.IsZero()
	cm.mu.Unlock()
	if unchanged {
		return false, nil
	}

	cfg, lerr := LoadConfig(cm.configPath)
	if lerr != nil {
		// A half-written or briefly invalid file must not take the running
		// agent's config away from it; keep what we have and try again next tick.
		return false, fmt.Errorf("reload %s: %w", cm.configPath, lerr)
	}
	cm.mu.Lock()
	first := cm.lastMod.IsZero()
	cm.current = cfg
	cm.lastSize = fi.Size()
	cm.lastMod = fi.ModTime()
	cm.mu.Unlock()
	// The first call only establishes the baseline -- the config it "reloaded"
	// is the one already in memory, and reporting that as a change would log a
	// reload on every startup.
	return !first, nil
}

// PersistEnrollment writes the credentials the server issued during join-key
// enrollment back into agent.yml, then reloads. Only the auth_token and
// public_key lines are rewritten (added if absent); every other line, including
// operator comments and the capability matrix, is preserved -- this file is
// hand-edited, so a naive marshal-and-write would destroy it.
//
// The join key is blanked once we hold our own token: leaving a fleet-wide
// credential on every host after it has stopped being needed is exactly the
// blast radius the per-agent token exists to avoid.
func (cm *ConfigManager) PersistEnrollment(token, publicKey string) error {
	if token == "" {
		return fmt.Errorf("server reported enrollment but sent no token")
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	raw, err := os.ReadFile(cm.configPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cm.configPath, err)
	}

	out := setYamlScalar(string(raw), "auth_token", token)
	if publicKey != "" {
		out = setYamlScalar(out, "public_key", publicKey)
	}
	out = setYamlScalar(out, "join_key", "")

	// Same permissions the installer sets: this file now holds a credential.
	if err := os.WriteFile(cm.configPath, []byte(out), 0600); err != nil {
		return fmt.Errorf("write %s: %w", cm.configPath, err)
	}

	cfg, err := LoadConfig(cm.configPath)
	if err != nil {
		return fmt.Errorf("reload after enrollment: %w", err)
	}
	cm.current = cfg
	return nil
}

// PersistAutoVPN writes the tray's auto-VPN preference back into agent.yml so
// it survives a restart. Same line-preserving edit as PersistEnrollment.
func (cm *ConfigManager) PersistAutoVPN(value bool) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	raw, err := os.ReadFile(cm.configPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cm.configPath, err)
	}
	out := setYamlScalarValue(string(raw), "auto_vpn", fmt.Sprintf("%t", value), false)
	if err := os.WriteFile(cm.configPath, []byte(out), 0600); err != nil {
		return fmt.Errorf("write %s: %w", cm.configPath, err)
	}

	cfg, err := LoadConfig(cm.configPath)
	if err != nil {
		return fmt.Errorf("reload after auto_vpn: %w", err)
	}
	cm.current = cfg
	return nil
}

// ClearEnrollment blanks the auth_token and public_key so the agent re-enrolls
// with whatever join_key is configured. Triggered by the tray's "re-enroll".
func (cm *ConfigManager) ClearEnrollment() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	raw, err := os.ReadFile(cm.configPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cm.configPath, err)
	}
	out := setYamlScalar(string(raw), "auth_token", "")
	out = setYamlScalar(out, "public_key", "")
	if err := os.WriteFile(cm.configPath, []byte(out), 0600); err != nil {
		return fmt.Errorf("write %s: %w", cm.configPath, err)
	}

	cfg, err := LoadConfig(cm.configPath)
	if err != nil {
		return fmt.Errorf("reload after enrollment clear: %w", err)
	}
	cm.current = cfg
	return nil
}

// RegisteredService is one entry in the `services:` list of agent.yml: the
// name (systemd unit or docker container) and its type, which the directory
// uses to pick the right child-resource subtype and the agent to report the
// right metrics.
type RegisteredService struct {
	Name    string `yaml:"name"`
	SubType string `yaml:"subtype"`
}

// UnmarshalYAML accepts both the legacy scalar form (`- nginx`) and the object
// form (`- name: nginx` / `subtype: systemd`) so pre-subtype configs keep
// loading. A bare string is treated as a systemd service.
func (s *RegisteredService) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		s.Name = node.Value
		s.SubType = ""
		return nil
	}
	type raw RegisteredService
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	s.Name = r.Name
	s.SubType = r.SubType
	return nil
}

// SubTypeOr reports the service type, defaulting to "systemd" for legacy
// entries written before subtypes existed.
func (s RegisteredService) SubTypeOr(def string) string {
	if s.SubType != "" {
		return s.SubType
	}
	return def
}

// PersistService adds (or, when remove is true, removes) a service of the given
// subtype in the `services:` list in agent.yml. Like the enrollment/auto_vpn
// edits it is line-based rather than a YAML round-trip so comments and
// formatting survive, and it reloads the active config so the running daemon
// picks up the change without a restart.
func (cm *ConfigManager) PersistService(name, subtype string, remove bool) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	raw, err := os.ReadFile(cm.configPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cm.configPath, err)
	}

	var out string
	if remove {
		out, err = removeYamlListItem(string(raw), "services", name)
	} else {
		out, err = addYamlListItem(string(raw), "services", name, subtype)
	}
	if err != nil {
		return err
	}

	if err := os.WriteFile(cm.configPath, []byte(out), 0600); err != nil {
		return fmt.Errorf("write %s: %w", cm.configPath, err)
	}

	cfg, err := LoadConfig(cm.configPath)
	if err != nil {
		return fmt.Errorf("reload after service edit: %w", err)
	}
	cm.current = cfg
	return nil
}

// addYamlListItem appends a new item under the `key:` block. It understands
// both the inline empty form (`key: []`) and the block form, converting the
// former into a block. Creates the key when absent, and inserts right after the
// block's last entry so the item is never misattributed to a following top-level
// key. When subtype is non-empty the item is written as an object
// (`- name: <item>` / `  subtype: <subtype>`), otherwise as a plain scalar
// (`- <item>`). Preserves all other lines verbatim.
func addYamlListItem(doc, key, item, subtype string) (string, error) {
	if !strings.HasSuffix(doc, "\n") {
		doc += "\n"
	}

	// Build the indented entry (2 spaces under the block key, 4 for nested).
	entry := "- " + item
	if subtype != "" {
		entry = "- name: " + item + "\n    subtype: " + subtype
	}
	entry = "  " + entry + "\n"

	// Existing scalar/object item with this name at the top level of the block.
	itemRe := regexp.MustCompile(`(?m)^[ \t]*-\s*` + regexp.QuoteMeta(item) + `\s*$`)
	namedRe := regexp.MustCompile(`(?m)^[ \t]*-\s*name:\s*` + regexp.QuoteMeta(item) + `\s*$`)
	if itemRe.MatchString(doc) || namedRe.MatchString(doc) {
		return doc, fmt.Errorf("service %q already registered", item)
	}

	// Inline empty list `key: []` -> convert to a block.
	inlineEmpty := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*:\s*\[\s*\]\s*$`)
	if inlineEmpty.MatchString(doc) {
		return inlineEmpty.ReplaceAllString(doc, key+":\n"+entry), nil
	}

	lines := strings.SplitAfter(doc, "\n")
	keyRe := regexp.MustCompile(`^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*:\s*$`)

	var blockIndex = -1
	for i, l := range lines {
		if keyRe.MatchString(l) {
			blockIndex = i
		}
	}
	if blockIndex < 0 {
		// No existing block: append a fresh one at the end.
		return doc + key + ":\n" + entry, nil
	}

	// Find the last line of the block: the next top-level (non-space-prefixed)
	// key after blockIndex, or end of file.
	end := len(lines)
	for i := blockIndex + 1; i < len(lines); i++ {
		if lines[i] != "\n" && !strings.HasPrefix(lines[i], " ") && !strings.HasPrefix(lines[i], "\t") {
			end = i
			break
		}
	}
	if end == len(lines) {
		return doc + entry, nil
	}
	// end points at the next top-level line; splice insert before it.
	return strings.Join(append(lines[:end], append([]string{entry}, lines[end:]...)...), ""), nil
}

// removeYamlListItem deletes the item (scalar or multi-line object entry) under
// the `key:` block, if present.
func removeYamlListItem(doc, key, item string) (string, error) {
	// Object form: `- name: <item>` optionally followed by its own indented
	// nested keys (`  subtype: ...`). The continuation must not consume the next
	// list entry (which starts with `-`).
	objectRe := regexp.MustCompile(`(?m)^[ \t]*-\s*name:\s*` + regexp.QuoteMeta(item) + `[ \t]*\r?\n(?:[ \t]+[^-\s][^\r\n]*\r?\n)*`)
	if objectRe.MatchString(doc) {
		return objectRe.ReplaceAllString(doc, ""), nil
	}

	// Scalar form: `- <item>`.
	itemRe := regexp.MustCompile(`(?m)^[ \t]*-\s*` + regexp.QuoteMeta(item) + `[ \t]*\r?\n`)
	if !itemRe.MatchString(doc) {
		itemReNoNL := regexp.MustCompile(`(?m)^[ \t]*-\s*` + regexp.QuoteMeta(item) + `[ \t]*$`)
		if !itemReNoNL.MatchString(doc) {
			return doc, fmt.Errorf("service %q is not registered", item)
		}
		return itemReNoNL.ReplaceAllString(doc, ""), nil
	}
	return itemRe.ReplaceAllString(doc, ""), nil
}

// setYamlScalar replaces the value of a top-level `key: "..."` line, or appends
// the key when it is absent. Deliberately line-based rather than a YAML
// round-trip so comments and formatting survive.
func setYamlScalar(doc, key, value string) string {
	return setYamlScalarValue(doc, key, value, true)
}

// setYamlScalarValue is setYamlScalar with control over quoting. Numeric/bool
// scalars (e.g. auto_vpn: true) must stay unquoted or YAML decodes them as
// strings.
func setYamlScalarValue(doc, key, value string, quote bool) string {
	line := fmt.Sprintf("%s: %s", key, value)
	if quote {
		line = fmt.Sprintf("%s: %q", key, value)
	}
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*:.*$`)
	if re.MatchString(doc) {
		return re.ReplaceAllString(doc, line)
	}
	if !strings.HasSuffix(doc, "\n") {
		doc += "\n"
	}
	return doc + line + "\n"
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var cfg Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode YAML config: %w", err)
	}

	if cfg.Capabilities.ConfigureLDAP {
		cfg.Capabilities.LdapTunnel = true
	}

	return &cfg, nil
}

// WireGuardEnabled reports whether this agent may run the mesh tunnel.
//
// Absent means enabled: the capability gates auto-VPN, mesh enrolment and the
// signed wireguard_apply/remove commands, and every config written by an older
// installer omits it entirely. An explicit `wireguard: false` is still honoured
// -- that is an operator saying no, rather than a key nobody ever wrote.
func (c *Capabilities) WireGuardEnabled() bool {
	return c.WireGuard == nil || *c.WireGuard
}

// CanManageService checks if a specific service is permitted to be restarted/stopped
func (c *Capabilities) CanManageService(serviceName string) bool {
	for _, allowed := range c.ServiceControl {
		if allowed == serviceName {
			return true
		}
	}
	return false
}

// ApplyConfigValues merges key=value pairs into the YAML document at path,
// leaving every other setting -- comments, capabilities, wireguard block --
// exactly as the operator left it.
//
// install.sh used to do this with `sed -i "s|^key:.*|key: value|"`, which only
// substitutes when the key is ALREADY present. A config written by an older
// agent (or hand-trimmed) silently dropped anything new, which is why a
// re-install appeared to need the old agent.yml deleted before new settings
// took effect. setYamlScalarValue appends a missing key instead of dropping it.
func ApplyConfigValues(path string, pairs map[string]string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	doc := string(raw)

	// Deterministic order so a re-run produces an identical file.
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := pairs[k]
		// Only top-level keys. setYamlScalarValue's pattern also matches an
		// INDENTED line, and replacing one rewrites it flush-left -- so
		// `config-set reboot=true` would lift `reboot` out of the capabilities
		// block, silently dropping the capability while still producing valid
		// YAML. Refuse rather than mangle the file.
		if !topLevelKeyRe(k).MatchString(doc) && nestedKeyRe(k).MatchString(doc) {
			return fmt.Errorf("%q exists only as a nested key; config-set handles "+
				"top-level keys only -- edit %s by hand for nested settings", k, path)
		}
		// Booleans and plain integers must stay unquoted or YAML decodes them
		// as strings (auto_vpn: "true" is not a bool).
		quote := true
		if v == "true" || v == "false" {
			quote = false
		} else if _, err := strconv.Atoi(v); err == nil && v != "" {
			quote = false
		}
		doc = setTopLevelYamlScalar(doc, k, v, quote)
	}

	// Verify the result still parses before replacing the live file -- a
	// corrupted agent.yml would leave the host unmanageable.
	var probe map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &probe); err != nil {
		return fmt.Errorf("refusing to write %s: result is not valid YAML: %w", path, err)
	}

	// Preserve the existing mode (0640, root:theta-secrets) rather than
	// inventing one.
	mode := os.FileMode(0640)
	if fi, serr := os.Stat(path); serr == nil {
		mode = fi.Mode().Perm()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(doc), mode); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// topLevelKeyRe matches `key:` only at column zero.
func topLevelKeyRe(key string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `[ \t]*:.*$`)
}

// nestedKeyRe matches `key:` only when indented under a parent.
func nestedKeyRe(key string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^[ \t]+` + regexp.QuoteMeta(key) + `[ \t]*:.*$`)
}

// setTopLevelYamlScalar is setYamlScalarValue restricted to column zero, so it
// can never reach inside a nested block. Appends the key when absent.
func setTopLevelYamlScalar(doc, key, value string, quote bool) string {
	line := fmt.Sprintf("%s: %s", key, value)
	if quote {
		line = fmt.Sprintf("%s: %q", key, value)
	}
	re := topLevelKeyRe(key)
	if re.MatchString(doc) {
		return re.ReplaceAllString(doc, line)
	}
	if !strings.HasSuffix(doc, "\n") {
		doc += "\n"
	}
	return doc + line + "\n"
}
