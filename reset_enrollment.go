package main

// `theta-agent reset-enrollment` -- discard the credentials this host holds so
// it enrols again from its join key.
//
// THE BUG THIS EXISTS TO FIX
//
// Re-running install.sh with a fresh --join-key against a rebuilt directory
// left the host talking to nothing. Config.Credential() prefers auth_token
// over join_key, and config-set only ever WRITES the values it is given -- so
// the stale auth_token from the previous directory stayed in agent.yml, won
// the preference, and was rejected on every connect. The join key that would
// have worked was sitting in the same file, never used. The same is true of
// public_key: it is the directory's Ed25519 signing key, so a directory
// rebuilt from scratch has a new one and every signed command the agent
// receives fails verification against the key it kept.
//
// ConfigManager.ClearEnrollment() already did exactly the right thing, but the
// only way to reach it was the tray's "re-enroll" menu item -- unavailable on
// a headless host, which is where re-keying actually happens.

import (
	"flag"
	"fmt"
	"os"
)

// resetEnrollment blanks the credentials at configPath, and with removeMeshKey
// also deletes this host's WireGuard private key.
//
// The mesh key is deliberately NOT part of the default: it is this host's own
// identity, the directory only ever stores its public half, and re-enrolment
// registers the same public key again quite happily. Throwing it away orphans
// the peer entry the directory built and forces a new address allocation, so
// it happens only when asked for.
func resetEnrollment(configPath, meshKeyPath string, removeMeshKey bool) ([]string, error) {
	cm, err := NewConfigManager(configPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", configPath, err)
	}
	before := cm.Get()
	if before.JoinKey == "" && before.AuthToken != "" {
		// Clearing the token with no join key to fall back on leaves the host
		// with no way to authenticate at all -- worse than the stale
		// credential it replaced.
		return nil, fmt.Errorf("refusing to clear the enrollment: %s has an auth_token but no join_key, "+
			"so the agent would have nothing left to authenticate with -- set join_key first "+
			"(theta-agent config-set --path %s join_key=<key>)", configPath, configPath)
	}
	if err := cm.ClearEnrollment(); err != nil {
		return nil, err
	}
	cleared := []string{"auth_token", "public_key"}

	if removeMeshKey {
		if meshKeyPath == "" {
			meshKeyPath = defaultWireGuardKeyPath()
		}
		if err := os.Remove(meshKeyPath); err == nil {
			cleared = append(cleared, meshKeyPath)
		} else if !os.IsNotExist(err) {
			return cleared, fmt.Errorf("remove %s: %w", meshKeyPath, err)
		}
	}
	return cleared, nil
}

func runResetEnrollment(args []string) {
	fs := flag.NewFlagSet("reset-enrollment", flag.ExitOnError)
	path := fs.String("path", defaultConfigPath(), "config file to reset")
	keys := fs.Bool("keys", false, "also delete this host's WireGuard private key (forces a new mesh identity)")
	quiet := fs.Bool("quiet", false, "print nothing; report only through the exit status")
	_ = fs.Parse(args)

	cleared, err := resetEnrollment(*path, wgKeyPathOverride, *keys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset-enrollment: %v\n", err)
		os.Exit(1)
	}
	if !*quiet {
		for _, c := range cleared {
			fmt.Printf("  cleared %s\n", c)
		}
		fmt.Printf("This host will enroll again from its join key on the next connect.\n")
	}
}
