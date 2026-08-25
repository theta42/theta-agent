package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

func handleCLI(args []string) bool {
	if len(args) == 0 {
		return false
	}
	arg := strings.ToLower(args[0])

	// `<command> help` / `--help` / `-h` prints that command's documentation
	// rather than running it. This used to fall through into each command's own
	// argument parsing, so `theta-agent register help` answered with the usage
	// error -- one line, no types, no examples. `help` and `version` are
	// excluded: for them the argument IS the subject.
	if arg != "help" && arg != "--help" && arg != "-h" && arg != "version" {
		if c := lookupCommand(arg); c != nil && wantsHelp(args[1:]) {
			printCommandHelp(c, os.Stdout)
			return true
		}
	}

	switch arg {
	case "get-secret", "secret-get":
		runGetSecret(args[1:])
		return true
	case "get-secrets", "secret-list", "secrets":
		runGetSecrets(args[1:])
		return true
	case "--update", "update":
		runSelfUpdate(args[1:])
		return true
	case "--reinitialize", "reinitialize", "--reinit", "reinit":
		runReinitialize(args[1:])
		return true
	case "install-service":
		handleServiceCommand(args[1:])
		return true
	case "remove-service", "uninstall-service":
		handleServiceCommand(append([]string{"remove"}, args[1:]...))
		return true
	case "configure-login":
		runConfigureLogin(args[1:])
		return true
	case "register":
		runRegisterService(args[1:])
		return true
	case "unregister":
		runUnregisterService(args[1:])
		return true
	case "list-services":
		runListServices(args[1:])
		return true
	case "config-set":
		runConfigSet(args[1:])
		return true
	case "install-completions":
		runInstallCompletions(args[1:])
		return true
	case "discover":
		runDiscover(args[1:])
		return true
	case "--version", "version", "-v":
		fmt.Println("Theta Agent " + AgentVersion)
		return true
	case "--help", "help", "-h":
		runHelp(args[1:])
		return true
	case "run":
		// Named so it can be documented and completed like any other command;
		// bare `theta-agent` still does the same thing.
		return false
	case "verify":
		runVerify(args[1:])
		return true
	case "reset-enrollment", "reset-enrolment", "reenroll", "re-enroll":
		runResetEnrollment(args[1:])
		return true
	}
	return false
}

func runConfigureLogin(args []string) {
	configPath := defaultConfigPath()
	if len(args) > 0 && args[0] != "" && !strings.HasPrefix(args[0], "-") {
		configPath = args[0]
	}
	cm, err := NewConfigManager(configPath)
	if err != nil {
		log.Fatalf("configure-login: %v", err)
	}
	if err := configureLogin(cm); err != nil {
		log.Fatalf("configure-login: %v", err)
	}
}

func runSelfUpdate(args []string) {
	configPath := defaultConfigPath()
	cm, err := NewConfigManager(configPath)
	if err != nil {
		log.Fatalf("[!] Update failed: cannot read config from %s: %v", configPath, err)
	}
	_ = cm.Get()

	// Binaries are GitHub release artifacts (DESIGN-WINDOWS.md §9); nothing
	// binary is served from the SSO's /resources anymore.
	arch := "amd64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	artifact := fmt.Sprintf("theta-agent-%s-%s%s", runtime.GOOS, arch, ext)
	downloadURL := releaseAssetURL(artifact)
	log.Printf("[+] Downloading latest Theta Agent binary from %s...", downloadURL)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil || resp.StatusCode != 200 {
		log.Fatalf("[!] Failed to download update binary from %s (HTTP %d): %v", downloadURL, resp.StatusCode, err)
	}
	defer resp.Body.Close()

	binPath := "/usr/local/bin/theta-agent"
	if selfPath, err := os.Executable(); err == nil && selfPath != "" {
		binPath = selfPath
	}

	tmpPath := binPath + ".tmp"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		log.Fatalf("[!] Cannot write binary to %s: %v", tmpPath, err)
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		log.Fatalf("[!] Error writing binary update: %v", err)
	}
	out.Close()

	// Platform-specific install: unix renames over the running binary; Windows
	// must stage <self>.new and hand the swap to the session helper because
	// the service holds the exe image locked (update_windows.go).
	restarted, err := swapUpdatedBinary(cm.Get(), tmpPath, binPath)
	if err != nil {
		os.Remove(tmpPath)
		log.Fatalf("[!] Cannot install updated binary at %s: %v", binPath, err)
	}

	log.Printf("[+] Binary updated successfully at %s.", binPath)
	if !restarted {
		exec := &SystemExecutor{}
		restartAffectedServices(exec)
	}
	os.Exit(0)
}

func runReinitialize(args []string) {
	configPath := defaultConfigPath()
	joinKey := ""
	for i := 0; i < len(args); i++ {
		if (args[i] == "--join-key" || args[i] == "-j") && i+1 < len(args) {
			joinKey = args[i+1]
			i++
		}
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("[!] Cannot read %s: %v", configPath, err)
	}

	content := string(raw)
	// Clear auth_token
	reToken := regexp.MustCompile(`(?m)^auth_token:.*$`)
	content = reToken.ReplaceAllString(content, `auth_token: ""`)

	if joinKey != "" {
		reKey := regexp.MustCompile(`(?m)^join_key:.*$`)
		if reKey.MatchString(content) {
			content = reKey.ReplaceAllString(content, fmt.Sprintf(`join_key: "%s"`, joinKey))
		} else {
			content += fmt.Sprintf("\njoin_key: \"%s\"\n", joinKey)
		}
	}

	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		log.Fatalf("[!] Failed to update %s: %v", configPath, err)
	}

	log.Printf("[+] Cleared token in %s and reset enrollment status.", configPath)
	exec := &SystemExecutor{}
	restartAffectedServices(exec)
	os.Exit(0)
}

// runDiscover browses for theta-suite sites announced on the local network
// (AGENT_LOCAL_DISCOVERY_SPEC.md's "fresh/unenrolled agent" case) and prints
// them. Read-only -- never writes agent.yml or touches enrollment itself;
// install.sh is what turns a `--urls-only` result into a --url argument, and
// only when there is exactly one unambiguous candidate.
func runDiscover(args []string) {
	timeout := 3 * time.Second
	urlsOnly := false
	jsonMode := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--urls-only":
			urlsOnly = true
		case "--json":
			jsonMode = true
		case "--timeout":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil {
					timeout = d
				}
				i++
			}
		}
	}

	sites := browseAnnouncements(timeout)

	if jsonMode {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(sites)
		os.Exit(0)
	}

	if urlsOnly {
		for _, s := range sites {
			fmt.Printf("https://%s\n", s.DirectoryHost)
		}
		os.Exit(0)
	}

	if len(sites) == 0 {
		fmt.Println("No theta-suite sites found on the local network.")
		os.Exit(0)
	}
	fmt.Printf("Found %d site(s) on the local network:\n\n", len(sites))
	for i, s := range sites {
		fmt.Printf("  [%d] site=%s\n", i+1, s.Site)
		fmt.Printf("      url:     https://%s\n", s.DirectoryHost)
		fmt.Printf("      version: %s\n", s.Version)
	}
	fmt.Println()
}

// releaseAssetURL returns the GitHub release download URL for a theta-agent
// artifact (e.g. "theta-agent-linux-amd64"). Binaries are built by CI and
// attached to the release; nothing binary lives in the repos (DESIGN-WINDOWS.md §9).
func releaseAssetURL(artifact string) string {
	return "https://github.com/theta42/theta-agent/releases/latest/download/" + artifact
}

func restartAffectedServices(exec Executor) {
	log.Printf("[+] Restarting theta-agent service...")
	if runtime.GOOS == "windows" {
		// sc.exe has no one-shot restart.
		_, _ = exec.Execute("sc", "stop", "theta-agent")
		_, _ = exec.Execute("sc", "start", "theta-agent")
		return
	}
	_, _ = exec.Execute("systemctl", "restart", "theta-agent")

	if _, err := exec.Execute("systemctl", "is-active", "sssd"); err == nil {
		log.Printf("[+] Restarting sssd service...")
		_, _ = exec.Execute("systemctl", "restart", "sssd")
	}

	if _, err := exec.Execute("systemctl", "is-active", "sshd"); err == nil {
		log.Printf("[+] Reloading sshd service...")
		_, _ = exec.Execute("systemctl", "reload", "sshd")
	} else if _, err := exec.Execute("systemctl", "is-active", "ssh"); err == nil {
		log.Printf("[+] Reloading ssh service...")
		_, _ = exec.Execute("systemctl", "reload", "ssh")
	}
}

func runGetSecret(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "[!] Error: secret key name required (e.g. theta-agent get-secret DB_PASSWORD)\n")
		os.Exit(1)
	}
	key := args[0]

	secrets, err := fetchAgentSecrets()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error fetching secrets: %v\n", err)
		os.Exit(1)
	}

	val, exists := secrets[key]
	if !exists {
		fmt.Fprintf(os.Stderr, "[!] Error: secret '%s' not found for this host/resource\n", key)
		os.Exit(1)
	}

	// Print raw secret value to stdout without trailing newline
	fmt.Print(val)
	os.Exit(0)
}

func runGetSecrets(args []string) {
	jsonMode := false
	envMode := false
	for _, arg := range args {
		if arg == "--json" {
			jsonMode = true
		} else if arg == "--env" {
			envMode = true
		}
	}

	secrets, err := fetchAgentSecrets()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error fetching secrets: %v\n", err)
		os.Exit(1)
	}

	if jsonMode {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(secrets); err != nil {
			fmt.Fprintf(os.Stderr, "[!] JSON encode error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if envMode {
		for k, v := range secrets {
			escaped := strings.ReplaceAll(v, `"`, `\"`)
			fmt.Printf("%s=\"%s\"\n", k, escaped)
		}
		os.Exit(0)
	}

	if len(secrets) == 0 {
		fmt.Println("No secrets configured for this host/resource.")
		os.Exit(0)
	}
	fmt.Printf("%-30s %s\n", "SECRET KEY", "VALUE STATUS")
	fmt.Println(strings.Repeat("-", 60))
	for k, v := range secrets {
		status := fmt.Sprintf("Configured (%d chars)", len(v))
		fmt.Printf("%-30s %s\n", k, status)
	}
	os.Exit(0)
}

func fetchAgentSecrets() (map[string]string, error) {
	configPath := defaultConfigPath()
	cm, err := NewConfigManager(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read config %s: %w", configPath, err)
	}
	cfg := cm.Get()
	serverURL := strings.TrimRight(cfg.ServerURL, "/")
	if serverURL == "" {
		return nil, fmt.Errorf("server_url is empty in %s", configPath)
	}
	token := cfg.AuthToken
	if token == "" {
		return nil, fmt.Errorf("agent is not enrolled (auth_token empty in %s)", configPath)
	}

	reqBody, _ := json.Marshal(map[string]interface{}{})

	url := fmt.Sprintf("%s/api/v1/agent/secrets", serverURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var resData struct {
		Status  string                            `json:"status"`
		Secrets map[string]map[string]interface{} `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&resData); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	mergedSecrets := make(map[string]string)
	for _, pathMap := range resData.Secrets {
		for k, v := range pathMap {
			if strV, ok := v.(string); ok {
				mergedSecrets[k] = strV
			} else if v != nil {
				mergedSecrets[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	return mergedSecrets, nil
}

// runConfigSet merges `key=value` pairs into agent.yml without disturbing
// anything else in the file. Used by install.sh so a re-install can update an
// existing config in place instead of requiring the operator to delete it.
//
//	theta-agent config-set server_url=https://sso.example.com location=nyc
//	theta-agent config-set --path /etc/theta42/agent.yml auto_vpn=true
func runConfigSet(args []string) {
	path := defaultConfigPath()
	pairs := map[string]string{}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--path" || a == "-c" {
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "config-set: --path needs a value")
				os.Exit(2)
			}
			path = args[i+1]
			i++
			continue
		}
		k, v, ok := strings.Cut(a, "=")
		if !ok || k == "" {
			fmt.Fprintf(os.Stderr, "config-set: expected key=value, got %q\n", a)
			os.Exit(2)
		}
		// An empty value is a legitimate way to blank a field (auth_token=""),
		// so only the key is required.
		pairs[k] = v
	}

	if len(pairs) == 0 {
		fmt.Fprintln(os.Stderr, "config-set: nothing to set")
		os.Exit(2)
	}
	if err := ApplyConfigValues(path, pairs); err != nil {
		fmt.Fprintf(os.Stderr, "config-set: %v\n", err)
		os.Exit(1)
	}
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("Updated %s (%s)\n", path, strings.Join(keys, ", "))
}
