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

func (p *linuxPlatformOps) DesktopControl(subAction, targetUser string) ([]byte, error) {
	switch subAction {
	case "lock_session", "lock":
		out, err := p.exec.Execute("loginctl", "lock-sessions")
		if err != nil {
			return p.exec.Execute("sh", "-c", "DISPLAY=:0 xdg-screensaver lock || DISPLAY=:0 xset dpms force off")
		}
		return out, nil
	case "logout_user", "logout":
		if targetUser != "" {
			out, err := p.exec.Execute("loginctl", "terminate-user", targetUser)
			if err != nil {
				return p.exec.Execute("pkill", "-KILL", "-u", targetUser)
			}
			return out, nil
		}
		out, err := p.exec.Execute("loginctl", "terminate-session")
		if err != nil {
			return p.exec.Execute("pkill", "-9", "-f", "session-child")
		}
		return out, nil
	case "display_off":
		return p.exec.Execute("sh", "-c", "DISPLAY=:0 xset dpms force off || loginctl lock-sessions")
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
	tmpPath, err := downloadBinary(downloadURL, checksum)
	if err != nil {
		return err
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to resolve current binary path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(selfPath); err == nil {
		selfPath = resolved
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
func (p *linuxPlatformOps) ApplyWireGuard(conf string) error {
	if err := os.MkdirAll(filepath.Dir(p.confPath), 0700); err != nil {
		return fmt.Errorf("wireguard: create config dir: %w", err)
	}
	if err := os.WriteFile(p.confPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("wireguard: persist config: %w", err)
	}
	out, err := p.exec.Execute("wg-quick", "up", p.tunnelName)
	if err != nil {
		return fmt.Errorf("wireguard: wg-quick up %s: %v: %s", p.tunnelName, err, out)
	}
	return nil
}

func (p *linuxPlatformOps) RemoveWireGuard() error {
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
