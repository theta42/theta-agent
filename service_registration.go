package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// systemdUnitExists reports whether a systemd unit (by name, .service suffix
// optional) is present. Used by the CLI to refuse to register a service that
// does not exist -- a typo should fail loudly at registration time, not silently
// produce a dead child resource.
func systemdUnitExists(exec Executor, name string) bool {
	if !strings.HasSuffix(name, ".service") {
		name += ".service"
	}
	_, err := exec.Execute("systemctl", "list-unit-files", name)
	return err == nil
}

// dockerContainerExists reports whether a docker container by name exists,
// running or not. Uses `docker inspect` which resolves a name exactly.
func dockerContainerExists(exec Executor, name string) bool {
	_, err := exec.Execute("docker", "inspect", name)
	return err == nil
}

// validateServiceExists checks that the named unit/container/process exists for
// the given subtype, refusing to register a typo as a dead child resource.
func validateServiceExists(exec Executor, subtype, name string) error {
	switch subtype {
	case "docker":
		if dockerContainerExists(exec, name) {
			return nil
		}
		return fmt.Errorf("docker container %q does not exist", name)
	case "podman":
		if _, err := exec.Execute("podman", "inspect", name); err == nil {
			return nil
		}
		return fmt.Errorf("podman container %q does not exist", name)
	case "process":
		if _, err := exec.Execute("pgrep", "-x", name); err == nil {
			return nil
		}
		return fmt.Errorf("no running process named %q", name)
	case "systemd-timer":
		if systemdUnitExists(exec, name) || systemdUnitExists(exec, name+".timer") {
			return nil
		}
		return fmt.Errorf("systemd timer %q does not exist", name)
	case "cron":
		// Accept a cron entry identified by /etc/cron.d/<name>, the system
		// crontab, or a user spool table named <name>.
		if len(cronConfigLines(name)) > 0 {
			return nil
		}
		return fmt.Errorf("cron entry %q not found (looked in /etc/cron.d/%s, /etc/crontab, /var/spool/cron/%s)", name, name, name)
	case "lxc":
		if _, err := exec.Execute("lxc-info", "-n", name); err == nil {
			return nil
		}
		return fmt.Errorf("LXC container %q does not exist", name)
	case "kvm", "libvirt":
		if _, err := exec.Execute("virsh", "domname", name); err == nil {
			return nil
		}
		return fmt.Errorf("libvirt domain %q does not exist", name)
	default: // systemd
		if systemdUnitExists(exec, name) {
			return nil
		}
		return fmt.Errorf("systemd unit %q does not exist", name)
	}
}

// listServiceNames returns the candidate names for a subtype, for
// tab-completion.
func listServiceNames(exec Executor, subtype string) []string {
	switch subtype {
	case "docker":
		return listDockerContainerNames(exec)
	case "podman":
		out, err := exec.Execute("podman", "ps", "-a", "--format", "{{.Names}}")
		if err != nil {
			return nil
		}
		var names []string
		for _, l := range strings.Split(string(out), "\n") {
			if n := strings.TrimSpace(l); n != "" {
				names = append(names, n)
			}
		}
		return names
	case "systemd":
		return listSystemdServiceNames(exec)
	case "systemd-timer":
		out, err := exec.Execute("systemctl", "list-timers", "--no-legend", "--no-pager")
		if err != nil {
			return nil
		}
		var names []string
		for _, l := range strings.Split(string(out), "\n") {
			fields := strings.Fields(l)
			if len(fields) == 0 {
				continue
			}
			// list-timers prints NEXT LAST PASSED UNIT ACTIVATES; unit is the
			// 6th field. Take the last token if it ends with .timer.
			tok := fields[len(fields)-1]
			if strings.HasSuffix(tok, ".timer") {
				names = append(names, strings.TrimSuffix(tok, ".timer"))
			}
		}
		return names
	case "process":
		out, err := exec.Execute("ps", "-eo", "comm=")
		if err != nil {
			return nil
		}
		seen := map[string]bool{}
		var names []string
		for _, l := range strings.Split(string(out), "\n") {
			c := strings.TrimSpace(l)
			if c != "" && !seen[c] {
				seen[c] = true
				names = append(names, c)
			}
		}
		return names
	case "lxc":
		out, err := exec.Execute("lxc-ls", "-1")
		if err != nil {
			return nil
		}
		var names []string
		for _, l := range strings.Split(string(out), "\n") {
			if n := strings.TrimSpace(l); n != "" {
				names = append(names, n)
			}
		}
		return names
	case "kvm", "libvirt":
		out, err := exec.Execute("virsh", "list", "--all", "--name")
		if err != nil {
			return nil
		}
		var names []string
		for _, l := range strings.Split(string(out), "\n") {
			if n := strings.TrimSpace(l); n != "" {
				names = append(names, n)
			}
		}
		return names
	case "cron":
		var names []string
		if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					names = append(names, e.Name())
				}
			}
		}
		return names
	}
	return nil
}

// listDockerContainerNames returns the names of every docker container (running
// or stopped), for tab-completion.
func listDockerContainerNames(exec Executor) []string {
	out, err := exec.Execute("docker", "ps", "-a", "--format", "{{.Names}}")
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if n := strings.TrimSpace(line); n != "" {
			names = append(names, n)
		}
	}
	return names
}

// listSystemdServiceNames returns the names of every installed systemd unit of
// the given type (default "service"), minus the trailing ".service" suffix so
// the CLI argument reads cleanly. Drives tab-completion.
func listSystemdServiceNames(exec Executor) []string {
	out, err := exec.Execute("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".service")
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func runRegisterService(args []string) {
	subtype, name, err := parseServiceArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	registerService(subtype, name, false)
}

func runUnregisterService(args []string) {
	subtype, name, err := parseServiceArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	registerService(subtype, name, true)
}

func runListServices(args []string) {
	configPath := defaultConfigPath()
	cm, err := NewConfigManager(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot read config %s: %v\n", configPath, err)
		os.Exit(1)
	}
	cfg := cm.Get()
	if len(cfg.Services) == 0 {
		fmt.Println("No services registered with Theta Directory.")
		os.Exit(0)
	}
	for _, s := range cfg.Services {
		fmt.Printf("%-12s %s\n", s.SubTypeOr("systemd"), s.Name)
	}
	os.Exit(0)
}

// runInstallCompletions writes the bash/zsh completion scripts into the
// system-wide completion dirs. Requires root on Linux.
func runInstallCompletions(args []string) {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "[!] Tab-completion installation is only supported on Linux.")
		os.Exit(1)
	}

	// Embedded copies of the completion scripts, installed to the standard
	// locations. Kept in-sync with the files under completions/.
	bashScript := `# bash completion for theta-agent
_theta_agent_completions() {
    local cur services types
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    types="systemd docker podman process systemd-timer cron lxc kvm libvirt"
    cmds="register unregister list-services get-secret get-secrets update reinitialize install-service remove-service configure-login config-set discover install-completions version help"
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
        return 0
    fi
    case "${COMP_WORDS[1]}" in
        register|unregister)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${types}" -- "${cur}") )
                return 0
            fi
            if [[ $COMP_CWORD -eq 3 ]]; then
                case "${COMP_WORDS[2]}" in
                    systemd)       services=$(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{sub(/\.service$/,"",$1); print $1}') ;;
                    docker)        services=$(docker ps -a --format '{{.Names}}' 2>/dev/null) ;;
                    podman)        services=$(podman ps -a --format '{{.Names}}' 2>/dev/null) ;;
                    process)       services=$(ps -eo comm= 2>/dev/null | sort -u) ;;
                    systemd-timer) services=$(systemctl list-timers --no-legend --no-pager 2>/dev/null | awk '{print $NF}' | sed 's/\.timer$//') ;;
                    cron)          services=$(ls /etc/cron.d 2>/dev/null) ;;
                    lxc)           services=$(lxc-ls -1 2>/dev/null) ;;
                    kvm|libvirt)   services=$(virsh list --all --name 2>/dev/null) ;;
                esac
                COMPREPLY=( $(compgen -W "${services}" -- "${cur}") )
                return 0
            fi
            ;;
    esac
    return 0
}
complete -F _theta_agent_completions theta-agent
`
	zshScript := `#compdef theta-agent
_theta_agent() {
    local -a cmds services
    cmds=(
        'register:Register a service as a child of this host'
        'unregister:Remove a registered service'
        'list-services:List registered services'
        'install-completions:Install shell tab-completion'
        'get-secret:Fetch a single secret value'
        'get-secrets:Fetch all host/resource secrets'
        'update:Self-update binary'
        'reinitialize:Reset enrollment credentials'
        'config-set:Merge settings into agent.yml'
        'discover:List theta-suite sites on the local network'
        'version:Show version'
        'help:Show help'
    )
    if (( CURRENT == 2 )); then
        _describe 'command' cmds
        return
    fi
    case "$words[2]" in
        register|unregister)
            if (( CURRENT == 3 )); then
                _values 'service type' 'systemd' 'docker' 'podman' 'process' 'systemd-timer' 'cron' 'lxc' 'kvm' 'libvirt'
                return
            fi
            if (( CURRENT == 4 )); then
                case "$words[3]" in
                    systemd)       services=(${(f)"$(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{sub(/\.service$/,"",$1); print $1}')"}) ;;
                    docker)        services=(${(f)"$(docker ps -a --format '{{.Names}}' 2>/dev/null)"}) ;;
                    podman)        services=(${(f)"$(podman ps -a --format '{{.Names}}' 2>/dev/null)"}) ;;
                    process)       services=(${(f)"$(ps -eo comm= 2>/dev/null | sort -u)"}) ;;
                    systemd-timer) services=(${(f)"$(systemctl list-timers --no-legend --no-pager 2>/dev/null | awk '{print $NF}' | sed 's/\.timer$//')"}) ;;
                    cron)          services=(${(f)"$(ls /etc/cron.d 2>/dev/null)"}) ;;
                    lxc)           services=(${(f)"$(lxc-ls -1 2>/dev/null)"}) ;;
                    kvm|libvirt)   services=(${(f)"$(virsh list --all --name 2>/dev/null)"}) ;;
                esac
                _describe 'service' services
                return
            fi
            ;;
    esac
}
_theta_agent "$@"
`

	bashPath := "/usr/share/bash-completion/completions/theta-agent"
	zshPath := "/usr/share/zsh/site-functions/_theta-agent"

	if err := os.MkdirAll(filepath.Dir(bashPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(bashPath, []byte(bashScript), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Could not write %s: %v\n", bashPath, err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(zshPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(zshPath, []byte(zshScript), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Could not write %s: %v\n", zshPath, err)
		os.Exit(1)
	}

	if runtime.GOOS == "linux" {
		exec := &SystemExecutor{}
		_, _ = exec.Execute("ln", "-sf", bashPath, "/etc/bash_completion.d/theta-agent")
	}

	fmt.Println("[+] Installed bash and zsh tab-completion for theta-agent.")
	os.Exit(0)
}

// parseServiceArgs validates the `register/unregister <subtype> <name>` form.
func parseServiceArgs(args []string) (subtype, name string, err error) {
	if len(args) < 2 {
		return "", "", fmt.Errorf("usage: theta-agent <register|unregister> <type> <name>")
	}
	subtype = strings.ToLower(args[0])
	if !validServiceType(subtype) {
		return "", "", fmt.Errorf("unsupported service type %q: use systemd, docker, podman, process, systemd-timer, cron, lxc, or kvm/libvirt", args[0])
	}
	name = strings.TrimSpace(args[1])
	if name == "" {
		return "", "", fmt.Errorf("service name is required")
	}
	return subtype, name, nil
}

// validServiceType reports whether a subtype is one the agent can register and
// probe.
func validServiceType(subtype string) bool {
	switch subtype {
	case "systemd", "docker", "podman", "process", "systemd-timer", "cron", "lxc", "kvm", "libvirt":
		return true
	}
	return false
}

// registerService validates the unit/container/process, updates agent.yml, and
// pushes a one-shot register_service / unregister_service message over a
// short-lived WebSocket so the directory reflects the change immediately
// (idempotent -- safe to re-run).
func registerService(subtype, name string, remove bool) {
	exec := &SystemExecutor{}

	// Only meaningful on Linux.
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "[!] Service registration is only supported on Linux.")
		os.Exit(1)
	}
	if !remove {
		if err := validateServiceExists(exec, subtype, name); err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			os.Exit(1)
		}
	}

	configPath := defaultConfigPath()
	cm, err := NewConfigManager(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot read config %s: %v\n", configPath, err)
		os.Exit(1)
	}

	if err := cm.PersistService(name, subtype, remove); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	if err := pushServiceRegistration(cm, name, subtype, remove); err != nil {
		// The config change is already persisted; report the push failure so
		// the operator knows the directory is out of sync but can re-run.
		fmt.Fprintf(os.Stderr, "[!] Config updated, but could not notify Theta Directory: %v\n", err)
		fmt.Fprintln(os.Stderr, "    The running agent will retry on its next connect/reload.")
		os.Exit(1)
	}

	if remove {
		fmt.Printf("[+] Unregistered %s service %q with Theta Directory.\n", subtype, name)
	} else {
		fmt.Printf("[+] Registered %s service %q with Theta Directory.\n", subtype, name)
	}
	os.Exit(0)
}

// pushServiceRegistration opens a one-shot WebSocket to the directory, sends the
// registration message, waits for the response, and closes. It reuses the same
// enrollment credential and signing channel as the daemon, so no separate secret
// is needed.
func pushServiceRegistration(cm *ConfigManager, name, subtype string, remove bool) error {
	cfg := cm.Get()
	if cfg.ServerURL == "" {
		return fmt.Errorf("server_url is empty in %s", cm.configPath)
	}

	msgType := "register_service"
	if remove {
		msgType = "unregister_service"
	}

	// Short-lived, single round-trip: connect, send, wait for a response frame,
	// then close. 15s covers a slow directory.
	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	conn, _, err := dialer.Dial(serviceWSURL(cfg), nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))

	// Wait for the initial config/welcome frame before sending.
	if _, _, err := conn.ReadMessage(); err != nil {
		return fmt.Errorf("read welcome: %w", err)
	}

	msg := map[string]interface{}{
		"type": msgType,
		"payload": map[string]interface{}{
			"service": name,
			"subtype": subtype,
		},
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return fmt.Errorf("send %s: %w", msgType, err)
	}

	// Read the response frame (the server answers every command with a response).
	if _, resp, err := conn.ReadMessage(); err != nil {
		return fmt.Errorf("read response: %w", err)
	} else {
		var r struct {
			Type    string                 `json:"type"`
			Payload map[string]interface{} `json:"payload"`
		}
		if err := json.Unmarshal(resp, &r); err == nil {
			if r.Type == "response" {
				if s, _ := r.Payload["status"].(string); s == "error" {
					return fmt.Errorf("directory: %v", r.Payload["message"])
				}
			}
		}
	}
	return nil
}

// serviceWSURL builds the same /api/agent/ws?token=... URL the daemon uses.
func serviceWSURL(cfg *Config) string {
	serverURL := strings.Replace(cfg.ServerURL, "http://", "ws://", 1)
	serverURL = strings.Replace(serverURL, "https://", "wss://", 1)
	u, _ := url.Parse(serverURL)
	u.Path = "/api/agent/ws"
	q := url.Values{}
	q.Set("token", cfg.Credential())
	if hn, err := os.Hostname(); err == nil && hn != "" {
		q.Set("hostname", hn)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
