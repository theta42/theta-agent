package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Secrets engine (DESIGN.md §5). The agent renders local templates that embed
// OpenBao secrets, e.g.:
//
//	# /etc/theta/templates/db.env.tpl
//	DB_USER="{{ bao "secret/data/nodes/node-42/db#username" }}"
//	DB_PASS="{{ bao "secret/data/nodes/node-42/db#password" }}"
//
// The agent parses the `{{ bao "path#key" }}` placeholders, fetches the secret
// values from the SSO (which holds the OpenBao access), renders each template to
// its target atomically (0600), and runs the configured reload. The agent never
// holds a Vault token.

var baoRe = regexp.MustCompile(`\{\{\s*bao\s+"([^"]+)"\s*\}\}`)

// renderSecrets renders every configured secret template. Called on a
// `render_secrets` command (signed) and on boot.
func renderSecrets(cfg *Config, exec Executor) error {
	if len(cfg.Secrets) == 0 {
		return nil
	}

	// Collect the unique secret paths referenced across all templates.
	pathSet := map[string]bool{}
	var paths []string
	for _, t := range cfg.Secrets {
		content, err := os.ReadFile(t.Template)
		if err != nil {
			log.Printf("Secrets: cannot read template %s: %v", t.Template, err)
			continue
		}
		for _, m := range baoRe.FindAllStringSubmatch(string(content), -1) {
			path := refPath(m[1])
			if !pathSet[path] {
				pathSet[path] = true
				paths = append(paths, path)
			}
		}
	}
	if len(paths) == 0 {
		return nil
	}

	secrets, err := fetchSecrets(cfg, paths)
	if err != nil {
		return err
	}

	for _, t := range cfg.Secrets {
		if err := renderOne(t, secrets, exec); err != nil {
			log.Printf("Secrets: render %s failed: %v", t.Template, err)
		}
	}
	return nil
}

func renderOne(t SecretTarget, secrets map[string]map[string]interface{}, exec Executor) error {
	content, err := os.ReadFile(t.Template)
	if err != nil {
		return err
	}

	out := baoRe.ReplaceAllStringFunc(string(content), func(match string) string {
		ref := baoRe.FindStringSubmatch(match)[1]
		path, key := refPath(ref), refKey(ref)
		if v, ok := secrets[path][key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	})

	// Atomic write: temp file in the target's directory, then rename. 0600 — the
	// rendered file holds secrets.
	tmp, err := os.CreateTemp(filepath.Dir(t.Target), ".theta-secret-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := io.WriteString(tmp, out); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	tmp.Close()
	os.Chmod(tmpName, 0600)
	if err := os.Rename(tmpName, t.Target); err != nil {
		os.Remove(tmpName)
		return err
	}

	if t.Reload != "" {
		if _, err := exec.Execute("sh", "-c", t.Reload); err != nil {
			log.Printf("Secrets: reload %q failed: %v", t.Reload, err)
		}
	}
	return nil
}

// fetchSecrets asks the SSO for the given node-scoped secret paths.
func fetchSecrets(cfg *Config, paths []string) (map[string]map[string]interface{}, error) {
	base := strings.Replace(cfg.ServerURL, "wss://", "https://", 1)
	base = strings.Replace(base, "ws://", "http://", 1)
	url := strings.TrimRight(base, "/") + "/api/v1/agent/secrets"

	body, _ := json.Marshal(map[string]interface{}{"paths": paths})
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Credential())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("secrets fetch failed: %s", resp.Status)
	}

	var out struct {
		Secrets map[string]map[string]interface{} `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Secrets, nil
}

// refPath returns the secret path from a `path#key` reference.
func refPath(ref string) string {
	if i := strings.Index(ref, "#"); i >= 0 {
		return ref[:i]
	}
	return ref
}

// refKey returns the key from a `path#key` reference.
func refKey(ref string) string {
	if i := strings.Index(ref, "#"); i >= 0 {
		return ref[i+1:]
	}
	return ""
}
