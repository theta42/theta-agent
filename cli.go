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
	"strings"
	"time"
)

func handleCLI(args []string) bool {
	if len(args) == 0 {
		return false
	}
	arg := strings.ToLower(args[0])
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
	case "--version", "version", "-v":
		fmt.Println("Theta Agent " + AgentVersion)
		return true
	case "--help", "help", "-h":
		printUsage()
		return true
	}
	return false
}

func printUsage() {
	fmt.Println("Theta Agent - Unified Endpoint Management CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  theta-agent                         Run agent daemon in foreground")
	fmt.Println("  theta-agent get-secret <key>        Fetch single secret value from OpenBao")
	fmt.Println("  theta-agent get-secrets [flags]     Fetch all host/resource secrets (flags: --json, --env)")
	fmt.Println("  theta-agent update                  Self-update binary from Theta Directory")
	fmt.Println("  theta-agent reinitialize [flags]   Reset enrollment credentials & re-register")
	fmt.Println("  theta-agent install-service        (Windows) register the agent as a service")
	fmt.Println("  theta-agent remove-service         (Windows) unregister the agent service")
	fmt.Println("  theta-agent configure-login        (Windows) wire OpenCredential to the agent's LDAP tunnel")
	fmt.Println("  theta-agent version                 Show version info")
	fmt.Println()
	fmt.Println("Reinitialize Flags:")
	fmt.Println("  --join-key <key>                    Supply new join key for re-enrollment")
	fmt.Println()
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

	if err := os.Rename(tmpPath, binPath); err != nil {
		log.Fatalf("[!] Cannot replace binary at %s: %v", binPath, err)
	}

	log.Printf("[+] Binary updated successfully at %s.", binPath)
	exec := &SystemExecutor{}
	restartAffectedServices(exec)
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
