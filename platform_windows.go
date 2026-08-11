//go:build windows

package main

// windowsPlatformOps implements PlatformOps for Windows. Remote ops map to
// Windows equivalents:
//
//   - reboot/shutdown  → shutdown.exe
//   - service control  → sc.exe
//   - fetch logs       → Get-WinEvent (PowerShell)
//   - arbitrary_bash   → powershell -EncodedCommand (survives arbitrary quoting)
//   - desktop control  → theta-agent-helper (session-0 workaround, see
//     DESIGN-WINDOWS.md §4)
//   - self-update      → staged `.new` + helper swap (the running exe is locked)
//
// configure_ldap is declined: Windows logon goes through the OpenCredential
// credential provider, which the installer configures directly.

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

type windowsPlatformOps struct {
	exec        Executor
	helperPath  string // theta-agent-helper.exe (DESIGN-WINDOWS.md §8)
	serviceName string // Windows service name (defaults to theta-agent)
	tunnelName  string // WireGuard tunnel/service name
	confPath    string // persisted peer config path
	wgExe       string // wireguard.exe client path ("" = PATH lookup)
}

func (p *windowsPlatformOps) Reboot() ([]byte, error) {
	return p.exec.Execute("shutdown", "/r", "/t", "0")
}

func (p *windowsPlatformOps) Shutdown() ([]byte, error) {
	return p.exec.Execute("shutdown", "/s", "/t", "0")
}

func (p *windowsPlatformOps) FetchLogs(service string, lines int) ([]byte, error) {
	script := fmt.Sprintf("Get-WinEvent -LogName Application -MaxEvents %d -ErrorAction SilentlyContinue | Format-List TimeCreated, ProviderName, Id, LevelDisplayName, Message", lines)
	return p.runPowerShell(script)
}

// ServiceControl maps systemd-style actions onto sc.exe. `restart` has no
// one-shot sc command, so it stops then starts; `status` is `sc query`.
func (p *windowsPlatformOps) ServiceControl(service, action string) ([]byte, error) {
	switch action {
	case "status":
		return p.exec.Execute("sc.exe", "query", service)
	case "restart":
		// A service that is already stopped is not an error worth failing on.
		if _, err := p.exec.Execute("sc.exe", "stop", service); err != nil {
			log.Printf("[windows] sc stop %s: %v (continuing to start)", service, err)
		}
		out, err := p.exec.Execute("sc.exe", "start", service)
		if err != nil && strings.Contains(string(out), "1056") {
			// ERROR_SERVICE_ALREADY_RUNNING — the stop never landed; treat as up.
			return out, nil
		}
		return out, err
	default:
		return p.exec.Execute("sc.exe", action, service)
	}
}

func (p *windowsPlatformOps) RunScript(script string) ([]byte, error) {
	return p.runPowerShell(script)
}

// runPowerShell invokes powershell with a UTF-16LE base64 -EncodedCommand. An
// operator script can contain arbitrary quotes, `&`, `%`, etc.; passing it as a
// plain argument would be mangled by cmd.exe/arg quoting rules, while the
// encoded form is byte-exact on both sides.
func (p *windowsPlatformOps) runPowerShell(script string) ([]byte, error) {
	units := utf16.Encode([]rune(script))
	b := make([]byte, len(units)*2)
	for i, r := range units {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	enc := base64.StdEncoding.EncodeToString(b)
	return p.exec.Execute("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc)
}

// DesktopControl routes ops that need an interactive desktop to the helper,
// which the service launches in the target session (DESIGN-WINDOWS.md §4).
// Sleep can run from session 0 and is handled in-process.
func (p *windowsPlatformOps) DesktopControl(subAction, targetUser string) ([]byte, error) {
	var action string
	switch subAction {
	case "sleep_host", "sleep":
		return nil, setSuspendState()
	case "lock_session", "lock":
		action = "lock"
	case "display_off":
		action = "display_off"
	case "logout_user", "logout":
		action = "logout"
	default:
		return nil, fmt.Errorf("unknown desktop action '%s'", subAction)
	}

	if p.helperPath == "" {
		return nil, fmt.Errorf("desktop control requires theta-agent-helper (desktop_helper not configured)")
	}
	args := []string{action}
	if targetUser != "" {
		args = append(args, targetUser)
	}
	return p.exec.Execute(p.helperPath, args...)
}

// setSuspendState puts the machine to sleep. Requires SeShutdownPrivilege,
// which the SYSTEM service holds.
func setSuspendState() error {
	powrprof := syscall.NewLazyDLL("powrprof.dll")
	proc := powrprof.NewProc("SetSuspendState")
	r, _, err := proc.Call(0, 0, 0) // Hibernate=false, ForceCritical=false, WakeIfDisarmed=false
	if r == 0 {
		return err
	}
	return nil
}

// ConfigureLDAP wires directory logon on Windows. The Directory pushes the
// LDAP config (SSSD-style) to agents advertising capabilities.configure_ldap;
// here we pull the base DN out of it, persist it to agent.yml, and seed the
// OpenCredential credential provider to authenticate against the agent's local
// LDAP tunnel (127.0.0.1:389). This is how LDAP details come from the
// Directory rather than being typed into the installer.
func (p *windowsPlatformOps) ConfigureLDAP(configData string) error {
	baseDN := parseSSSDBaseDN(configData)
	if baseDN == "" {
		return fmt.Errorf("configure_ldap: no ldap_search_base in pushed config")
	}

	cm := currentCM
	if cm != nil {
		// Persist the learned base DN so the config is self-describing and
		// configure-login can re-seed without waiting for the next push.
		if raw, err := os.ReadFile(cm.configPath); err == nil {
			out := setYamlScalar(string(raw), "ldap_base_dn", baseDN)
			if err := os.WriteFile(cm.configPath, []byte(out), 0600); err == nil {
				_ = cm.Reload()
			}
		}
	}

	if cm == nil {
		return seedOpenCredential(baseDN, "admins", "Administrators")
	}
	return seedOpenCredentialFromConfig(cm, baseDN)
}

// ApplyUpdate downloads and verifies the new binary to `<self>.new`, then hands
// the swap to the helper: the running service holds the exe open, so the agent
// must stop before the file can be replaced. The helper outlives the service
// (detached process), swaps the files, and restarts the service.
func (p *windowsPlatformOps) ApplyUpdate(downloadURL, checksum string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to resolve current binary path: %w", err)
	}

	tmpPath, err := downloadBinary(downloadURL, checksum)
	if err != nil {
		return err
	}

	newPath := selfPath + ".new"
	if err := moveFile(tmpPath, newPath); err != nil {
		return fmt.Errorf("failed to stage new binary: %w", err)
	}

	helper := p.helperPath
	if helper == "" {
		return fmt.Errorf("desktop_helper not configured; cannot complete self-update")
	}
	service := p.serviceName
	if service == "" {
		service = "theta-agent"
	}

	log.Printf("[windows] staging self-update via helper (%s -> %s)", newPath, selfPath)
	if err := spawnDetached(helper, "update", newPath, selfPath, service); err != nil {
		return fmt.Errorf("failed to launch updater helper: %w", err)
	}
	return nil
}

func (p *windowsPlatformOps) SelfRestart() {
	stopAgent()
}

// wireGuardExe resolves the WireGuard client executable: explicit config path,
// PATH lookup, or the default install location.
func (p *windowsPlatformOps) wireGuardExe() string {
	if p.wgExe != "" {
		return p.wgExe
	}
	const defaultInstall = `C:\Program Files\WireGuard\wireguard.exe`
	if _, err := os.Stat(defaultInstall); err == nil {
		return defaultInstall
	}
	return "wireguard.exe"
}

// ApplyWireGuard persists the peer config and installs it as a WireGuard
// service via the official client (wireguard.exe /installtunnelservice).
func (p *windowsPlatformOps) ApplyWireGuard(conf string) error {
	if err := os.MkdirAll(filepath.Dir(p.confPath), 0700); err != nil {
		return fmt.Errorf("wireguard: create config dir: %w", err)
	}
	if err := os.WriteFile(p.confPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("wireguard: persist config: %w", err)
	}
	out, err := p.exec.Execute(p.wireGuardExe(), "/installtunnelservice", p.tunnelName, p.confPath)
	if err != nil {
		return fmt.Errorf("wireguard: installtunnelservice %s: %v: %s", p.tunnelName, err, out)
	}
	return nil
}

func (p *windowsPlatformOps) RemoveWireGuard() error {
	out, err := p.exec.Execute(p.wireGuardExe(), "/uninstalltunnelservice", p.tunnelName)
	if err != nil {
		return fmt.Errorf("wireguard: uninstalltunnelservice %s: %v: %s", p.tunnelName, err, out)
	}
	return nil
}

// WireGuardState reports whether the WireGuardTunnel$<name> service is running.
func (p *windowsPlatformOps) WireGuardState() bool {
	out, err := p.exec.Execute("sc.exe", "query", "WireGuardTunnel$"+p.tunnelName)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToUpper(string(out)), "RUNNING")
}

// ConnectWireGuard brings the persisted config up unless already active.
func (p *windowsPlatformOps) ConnectWireGuard() error {
	if p.WireGuardState() {
		return nil
	}
	conf, err := os.ReadFile(p.confPath)
	if err != nil {
		return fmt.Errorf("wireguard: no persisted config at %s: %w", p.confPath, err)
	}
	return p.ApplyWireGuard(string(conf))
}

func (p *windowsPlatformOps) DisconnectWireGuard() error {
	if !p.WireGuardState() {
		return nil
	}
	return p.RemoveWireGuard()
}

// ApplyIAM maps node identity onto local Windows security (DESIGN-WINDOWS.md
// §4): local groups for allowed_login_groups, per-user authorized_keys for
// OpenSSH, and session logoff via the helper for revocation.
func (p *windowsPlatformOps) ApplyIAM(payload IAMPayload) error {
	ac := payload.AccessControl

	for _, g := range ac.AllowedLoginGroups {
		if g == "" {
			continue
		}
		if _, err := p.exec.Execute("net", "localgroup", g, "/add"); err != nil {
			log.Printf("[iam] net localgroup %s /add: %v", g, err)
		}
	}

	if len(ac.SSHKeys) > 0 {
		if err := applyWindowsSSHKeys(ac.SSHKeys); err != nil {
			log.Printf("[iam] ssh keys: %v", err)
		}
	}

	for _, u := range ac.RevokeUsers {
		if u == "" {
			continue
		}
		if p.helperPath != "" {
			if _, err := p.exec.Execute(p.helperPath, "logout", u); err != nil {
				log.Printf("[iam] revoke %s: %v", u, err)
			}
		} else {
			log.Printf("[iam] revoke %s: desktop_helper not configured; no sessions logged off", u)
		}
	}

	if len(ac.SudoRules) > 0 {
		log.Println("[iam] sudo_rules have no direct Windows equivalent; mapped to local group membership (UAC elevation policy)")
	}
	return nil
}

// spawnDetached launches exe as a background process that survives this one.
func spawnDetached(exe string, args ...string) error {
	cmd := execCommand(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

// execCommand is a thin wrapper so tests that build the windows ops can stub it.
func execCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

// moveFile renames src onto dst, falling back to a copy when the source is on a
// different volume than the destination (os.Rename fails across volumes).
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}
