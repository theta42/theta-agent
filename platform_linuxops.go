package main

// linuxPlatformOps implements PlatformOps for Linux (and any POSIX host).
// The commands mirror what websocket.go executed before the PlatformOps split;
// behaviour is unchanged. Deliberately NOT build-tagged: it compiles on every
// OS (it only shells out to systemctl/journalctl/bash), so the shared command
// dispatch tests can pin it and run identically on Windows CI.

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type linuxPlatformOps struct {
	exec       Executor
	tunnelName string // WireGuard interface/tunnel name
	confPath   string // persisted peer config path
}

func (p *linuxPlatformOps) Reboot() ([]byte, error) {
	return p.exec.Execute("reboot")
}

func (p *linuxPlatformOps) Shutdown() ([]byte, error) {
	out, err := p.exec.Execute("shutdown", "-h", "now")
	if err != nil {
		return p.exec.Execute("poweroff")
	}
	return out, nil
}

func (p *linuxPlatformOps) FetchLogs(service string, lines int) ([]byte, error) {
	return p.exec.Execute("journalctl", "-u", service, "-n", fmt.Sprintf("%d", lines), "--no-pager")
}

func (p *linuxPlatformOps) ServiceControl(service, action string) ([]byte, error) {
	return p.exec.Execute("systemctl", action, service)
}

func (p *linuxPlatformOps) RunScript(script string) ([]byte, error) {
	return p.exec.Execute("bash", "-c", script)
}

// desktopSession is one logind session, as reported by `loginctl`.
type desktopSession struct {
	ID      string
	User    string
	UID     string
	Type    string // "x11", "wayland", "tty", ...
	Display string // X11 display (":0"), empty under Wayland
	Active  bool
}

// graphical reports whether this session can carry a lock/logout that a user
// would actually see.
func (s desktopSession) graphical() bool {
	return s.Type == "x11" || s.Type == "wayland" || s.Type == "mir"
}

// listSessions enumerates logind sessions. The daemon runs as root outside any
// session, so it cannot infer a target from its own environment -- every
// desktop action has to resolve one explicitly. Returns an empty slice (not an
// error) when loginctl is missing or there are no sessions, so callers can give
// a precise "no graphical session" message instead of a raw exec failure.
func (p *linuxPlatformOps) listSessions(targetUser string) []desktopSession {
	out, err := p.exec.Execute("loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return nil
	}
	var sessions []desktopSession
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		id, uid, user := fields[0], fields[1], fields[2]
		if targetUser != "" && user != targetUser {
			continue
		}
		s := desktopSession{ID: id, UID: uid, User: user}
		props, perr := p.exec.Execute("loginctl", "show-session", id,
			"--property=Type", "--property=Active", "--property=Display")
		if perr == nil {
			for _, kv := range strings.Split(string(props), "\n") {
				k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
				if !ok {
					continue
				}
				switch k {
				case "Type":
					s.Type = v
				case "Active":
					s.Active = v == "yes"
				case "Display":
					s.Display = v
				}
			}
		}
		sessions = append(sessions, s)
	}
	return sessions
}

// graphicalSessions returns the graphical sessions, active ones first.
func (p *linuxPlatformOps) graphicalSessions(targetUser string) []desktopSession {
	var active, idle []desktopSession
	for _, s := range p.listSessions(targetUser) {
		if !s.graphical() {
			continue
		}
		if s.Active {
			active = append(active, s)
		} else {
			idle = append(idle, s)
		}
	}
	return append(active, idle...)
}

// DesktopControl drives lock/logout/display/suspend on the host's desktop
// sessions.
//
// The previous implementation shelled out to `DISPLAY=:0 xset` and
// `xdg-screensaver`, which cannot work from this daemon: it runs as root under
// systemd with no session of its own, so it has neither the user's XAUTHORITY
// (root cannot open another user's X display without it) nor any display at all
// under Wayland, which is the default on current GNOME and KDE. It also called
// `loginctl terminate-session` with no session ID -- invalid usage that always
// failed into a `pkill -f session-child` fallback matching nothing.
//
// Everything now goes through logind, which is display-server agnostic: it
// signals the desktop over D-Bus and works identically on X11 and Wayland.
// Failures are reported rather than masked, so the Directory shows what
// actually happened instead of a success for work that never occurred.
func (p *linuxPlatformOps) DesktopControl(subAction, targetUser string) ([]byte, error) {
	switch subAction {
	case "lock_session", "lock":
		sessions := p.graphicalSessions(targetUser)
		if len(sessions) == 0 {
			// lock-sessions still reaches sessions loginctl did not enumerate
			// for us (an unreadable seat, a non-systemd container); try it
			// before declaring there is nothing to lock.
			out, err := p.exec.Execute("loginctl", "lock-sessions")
			if err != nil {
				return out, fmt.Errorf("no graphical session to lock: %w", err)
			}
			return out, nil
		}
		var b strings.Builder
		var firstErr error
		for _, s := range sessions {
			out, err := p.exec.Execute("loginctl", "lock-session", s.ID)
			fmt.Fprintf(&b, "session %s (%s, %s): %s\n", s.ID, s.User, s.Type, strings.TrimSpace(string(out)))
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("lock-session %s: %w", s.ID, err)
			}
		}
		return []byte(b.String()), firstErr

	case "logout_user", "logout":
		if targetUser != "" {
			out, err := p.exec.Execute("loginctl", "terminate-user", targetUser)
			if err != nil {
				return out, fmt.Errorf("terminate-user %s: %w", targetUser, err)
			}
			return out, nil
		}
		// No user named: terminate the graphical sessions by ID. The old code
		// ran `terminate-session` with no argument, which loginctl rejects.
		sessions := p.graphicalSessions("")
		if len(sessions) == 0 {
			return nil, fmt.Errorf("no graphical session to log out")
		}
		var b strings.Builder
		var firstErr error
		for _, s := range sessions {
			out, err := p.exec.Execute("loginctl", "terminate-session", s.ID)
			fmt.Fprintf(&b, "session %s (%s): %s\n", s.ID, s.User, strings.TrimSpace(string(out)))
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("terminate-session %s: %w", s.ID, err)
			}
		}
		return []byte(b.String()), firstErr

	case "display_off":
		// DPMS is an X11 concept. Under Wayland the compositor owns power
		// management and there is no portable way in -- locking is the closest
		// honest equivalent, so say so rather than silently doing something else.
		sessions := p.graphicalSessions(targetUser)
		for _, s := range sessions {
			if s.Type != "x11" || s.Display == "" {
				continue
			}
			// Run xset as the session's own user so it can reach that display.
			out, err := p.exec.Execute("runuser", "-u", s.User, "--",
				"env", "DISPLAY="+s.Display, "xset", "dpms", "force", "off")
			if err == nil {
				return out, nil
			}
		}
		out, err := p.exec.Execute("loginctl", "lock-sessions")
		if err != nil {
			return out, fmt.Errorf("no X11 session for DPMS and lock fallback failed: %w", err)
		}
		return append([]byte("no X11 session for DPMS (Wayland?); locked instead\n"), out...), nil

	case "sleep_host", "sleep":
		return p.exec.Execute("systemctl", "suspend")
	default:
		return nil, fmt.Errorf("unknown desktop action '%s'", subAction)
	}
}

// ConfigureLDAP reproduces the original SSSD/nsswitch/PAM configuration flow.
func (p *linuxPlatformOps) ConfigureLDAP(configData string) error {
	log.Println("Pushing updated SSSD configuration...")
	_ = os.MkdirAll("/etc/sssd", 0755)
	if err := p.exec.WriteFile("/etc/sssd/sssd.conf", []byte(configData), 0600); err != nil {
		return fmt.Errorf("failed to write SSSD config: %w", err)
	}

	// Ensure /etc/nsswitch.conf enables sss for passwd, group, shadow, sudoers
	if nssBytes, err := os.ReadFile("/etc/nsswitch.conf"); err == nil {
		nssContent := string(nssBytes)
		updatedNss := false
		lines := strings.Split(nssContent, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if (strings.HasPrefix(trimmed, "passwd:") || strings.HasPrefix(trimmed, "group:") || strings.HasPrefix(trimmed, "shadow:") || strings.HasPrefix(trimmed, "sudoers:")) && !strings.Contains(trimmed, "sss") {
				lines[i] = line + " sss"
				updatedNss = true
			}
		}
		if updatedNss {
			_ = os.WriteFile("/etc/nsswitch.conf", []byte(strings.Join(lines, "\n")), 0644)
		}
	}

	log.Println("Restarting SSSD service...")
	if _, err := p.exec.Execute("systemctl", "restart", "sssd"); err != nil {
		log.Printf("SSSD restart failed (%v), attempting auto-install of missing packages...", err)
		if _, err2 := p.exec.Execute("sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get update -y -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sssd sssd-ldap libnss-sss libpam-sss libsss-sudo libpam-runtime || dnf install -y sssd sssd-ldap sssd-tools || yum install -y sssd sssd-ldap sssd-tools"); err2 == nil {
			_, _ = p.exec.Execute("sh", "-c", "pam-auth-update --package --enable mkhomedir sss || true")
			if _, err3 := p.exec.Execute("systemctl", "restart", "sssd"); err3 == nil {
				writeSSSDSshConf(p.exec)
				return nil
			}
		}
		return fmt.Errorf("failed to restart sssd")
	}

	writeSSSDSshConf(p.exec)
	return nil
}

// writeSSSDSshConf installs the AuthorizedKeysCommand config sshd needs to look
// up LDAP-backed SSH keys.
func writeSSSDSshConf(exec Executor) {
	_ = os.MkdirAll("/etc/ssh/sshd_config.d", 0755)
	sshConfPath := "/etc/ssh/sshd_config.d/theta-sssd.conf"
	sshConfContent := "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys %u\nAuthorizedKeysCommandUser nobody\n"
	if err := os.WriteFile(sshConfPath, []byte(sshConfContent), 0644); err == nil {
		_, _ = exec.Execute("systemctl", "reload", "sshd")
	}
	if sshdBytes, err2 := os.ReadFile("/etc/ssh/sshd_config"); err2 == nil {
		sshdStr := string(sshdBytes)
		if !strings.Contains(sshdStr, "sss_ssh_authorizedkeys") {
			sshdStr += "\nAuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys %u\nAuthorizedKeysCommandUser nobody\n"
			_ = os.WriteFile("/etc/ssh/sshd_config", []byte(sshdStr), 0644)
			_, _ = exec.Execute("systemctl", "reload", "sshd")
		}
	}
	_, _ = exec.Execute("sh", "-c", "pam-auth-update --package --enable mkhomedir sss || true")
}

func (p *linuxPlatformOps) ApplyUpdate(downloadURL, checksum string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to resolve current binary path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(selfPath); err == nil {
		selfPath = resolved
	}

	// Stage next to the destination so the rename stays on one filesystem.
	tmpPath, err := downloadBinary(downloadURL, checksum, filepath.Dir(selfPath))
	if err != nil {
		return err
	}

	if err := os.Rename(tmpPath, selfPath); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}
	return nil
}

func (p *linuxPlatformOps) SelfRestart() {
	os.Exit(0)
}

// ApplyWireGuard persists the peer config and brings the tunnel up with
// wg-quick (wg-quick reads /etc/wireguard/<name>.conf by interface name).
// PersistWireGuard writes the peer config where wg-quick will find it by
// interface name, and does nothing else.
func (p *linuxPlatformOps) PersistWireGuard(conf string) error {
	// Checked before the config is written, so a host without the tools says
	// what is wrong instead of leaving a config behind that nothing can run.
	if err := checkWireGuardTools(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.confPath), 0700); err != nil {
		return fmt.Errorf("wireguard: create config dir: %w", err)
	}
	if err := os.WriteFile(p.confPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("wireguard: persist config: %w", err)
	}
	return nil
}

func (p *linuxPlatformOps) ApplyWireGuard(conf string) error {
	if err := p.PersistWireGuard(conf); err != nil {
		return err
	}
	// `wg-quick up` refuses an interface that already exists, so re-applying
	// over a live tunnel used to fail outright -- which is exactly what
	// changing your exit does. Cycle it instead.
	if p.WireGuardState() {
		if out, err := p.exec.Execute("wg-quick", "down", p.tunnelName); err != nil {
			return fmt.Errorf("wireguard: wg-quick down %s (before re-applying): %v: %s", p.tunnelName, err, out)
		}
	}
	out, err := p.exec.Execute("wg-quick", "up", p.tunnelName)
	if err != nil {
		return fmt.Errorf("wireguard: wg-quick up %s: %v: %s", p.tunnelName, err, out)
	}
	return nil
}

func (p *linuxPlatformOps) RemoveWireGuard() error {
	if err := checkWireGuardTools(); err != nil {
		return err
	}
	out, err := p.exec.Execute("wg-quick", "down", p.tunnelName)
	if err != nil {
		return fmt.Errorf("wireguard: wg-quick down %s: %v: %s", p.tunnelName, err, out)
	}
	return nil
}

// WireGuardState reports whether the tunnel interface exists.
func (p *linuxPlatformOps) WireGuardState() bool {
	out, err := p.exec.Execute("ip", "link", "show", p.tunnelName)
	return err == nil && len(out) > 0
}

// ConnectWireGuard brings the persisted config up unless already active.
func (p *linuxPlatformOps) ConnectWireGuard() error {
	if p.WireGuardState() {
		return nil
	}
	conf, err := os.ReadFile(p.confPath)
	if err != nil {
		return fmt.Errorf("wireguard: no persisted config at %s: %w", p.confPath, err)
	}
	return p.ApplyWireGuard(string(conf))
}

func (p *linuxPlatformOps) DisconnectWireGuard() error {
	if !p.WireGuardState() {
		return nil
	}
	return p.RemoveWireGuard()
}

// ApplyIAM is the Linux node-identity engine (sudoers.d, SSH keys, PAM access,
// SSSD cache flush + session kill).
func (p *linuxPlatformOps) ApplyIAM(payload IAMPayload) error {
	return applyIAM(payload, p.exec)
}

// ZpoolScrub starts a scrub on the named zpool. The pool name is validated
// by the caller (websocket.go) before reaching here.
func (p *linuxPlatformOps) ZpoolScrub(pool string) ([]byte, error) {
	return p.exec.Execute("zpool", "scrub", pool)
}
