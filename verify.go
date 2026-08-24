package main

// `theta-agent verify` -- check that this host's configuration and key
// material are actually usable, without changing anything.
//
// install.sh runs it after writing configuration. Re-running the installer on
// a host that already has an agent is the normal way to re-point or re-key it,
// and until now nothing checked the result: a config carrying a public_key
// that does not decode, or a credential for a different directory, produced a
// service that started, connected, and then failed every signed command --
// visible only in the journal, on a host the operator had just been told was
// installed successfully.

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
)

// verifyProblem is one thing wrong with the configuration. Fatal problems mean
// the agent cannot work; the rest are worth saying but do not fail the check.
type verifyProblem struct {
	Fatal   bool
	Message string
}

// verifyConfigAt runs every check and returns what it found. Split from the
// CLI wrapper so tests can assert on the findings rather than on stdout.
func verifyConfigAt(path string) (problems []verifyProblem, checked []string) {
	add := func(fatal bool, format string, a ...interface{}) {
		problems = append(problems, verifyProblem{Fatal: fatal, Message: fmt.Sprintf(format, a...)})
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		add(true, "cannot read %s: %v", path, err)
		return problems, checked
	}
	checked = append(checked, "config parses")

	if cfg.ServerURL == "" {
		add(true, "server_url is empty -- the agent has no directory to connect to")
	} else if u, err := url.Parse(cfg.ServerURL); err != nil || u.Host == "" {
		add(true, "server_url %q is not a usable URL", cfg.ServerURL)
	} else {
		checked = append(checked, "server_url is a URL with a host")
	}

	switch {
	case cfg.AuthToken != "":
		checked = append(checked, "auth_token present (this host has enrolled)")
	case cfg.JoinKey != "":
		checked = append(checked, "join_key present (this host has not enrolled yet)")
	default:
		add(true, "neither auth_token nor join_key is set -- there is nothing to authenticate with")
	}

	// public_key is the DIRECTORY's Ed25519 signing key, and every signed
	// command is checked against it. A malformed one is silent: the agent
	// connects, and then rejects everything the directory asks it to do.
	if cfg.PublicKey == "" {
		add(true, "public_key is empty -- signed commands from the directory cannot be verified, so none will run")
	} else if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.PublicKey)); err != nil {
		add(true, "public_key is not valid base64: %v", err)
	} else if len(raw) != 32 {
		add(true, "public_key decodes to %d bytes, not the 32 an Ed25519 public key needs", len(raw))
	} else {
		checked = append(checked, "public_key is a 32-byte Ed25519 key")
	}

	problems = append(problems, verifyWireGuardKey()...)
	if len(problems) == 0 || !anyMentions(problems, "WireGuard") {
		checked = append(checked, "WireGuard identity")
	}

	return problems, checked
}

func anyMentions(ps []verifyProblem, s string) bool {
	for _, p := range ps {
		if strings.Contains(p.Message, s) {
			return true
		}
	}
	return false
}

// verifyWireGuardKey checks the host's WireGuard private key if one has been
// generated. Absent is fine -- it is created on first use. Present and wrong is
// not: a truncated or corrupt key produces a tunnel that never comes up, and
// the failure surfaces as "the mesh does not work" rather than as anything
// pointing at the key.
func verifyWireGuardKey() []verifyProblem {
	path := wgKeyPathOverride
	if path == "" {
		path = defaultWireGuardKeyPath()
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil // not generated yet
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return []verifyProblem{{Fatal: true, Message: fmt.Sprintf("WireGuard key %s cannot be read: %v", path, err)}}
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return []verifyProblem{{Fatal: true, Message: fmt.Sprintf("WireGuard key %s is not valid base64: %v", path, err)}}
	}
	if len(raw) != 32 {
		return []verifyProblem{{Fatal: true, Message: fmt.Sprintf("WireGuard key %s decodes to %d bytes, not 32", path, len(raw))}}
	}
	// Windows has no POSIX mode bits -- Go reports 0666 for anything it
	// created, whatever mode it was given, so the check would always fire.
	// Confidentiality there comes from the ACL the installer sets on
	// %ProgramData%\Theta42.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return []verifyProblem{{Fatal: false, Message: fmt.Sprintf("WireGuard key %s is mode %04o -- it should be 0600, readable only by root", path, perm)}}
		}
	}
	return nil
}

func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	path := fs.String("path", defaultConfigPath(), "config file to check")
	quiet := fs.Bool("quiet", false, "print nothing; report only through the exit status")
	_ = fs.Parse(args)

	problems, checked := verifyConfigAt(*path)

	fatal := 0
	for _, p := range problems {
		if p.Fatal {
			fatal++
		}
	}

	if !*quiet {
		fmt.Printf("Checking %s\n", *path)
		for _, c := range checked {
			fmt.Printf("  ok    %s\n", c)
		}
		for _, p := range problems {
			label := "warn "
			if p.Fatal {
				label = "FAIL "
			}
			fmt.Printf("  %s %s\n", label, p.Message)
		}
		if fatal == 0 && len(problems) == 0 {
			fmt.Println("\nConfiguration looks usable.")
		} else if fatal == 0 {
			fmt.Println("\nUsable, with warnings above.")
		} else {
			fmt.Printf("\n%d problem(s) will stop this agent working.\n", fatal)
		}
	}

	if fatal > 0 {
		os.Exit(1)
	}
}
