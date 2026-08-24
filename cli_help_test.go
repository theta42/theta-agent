package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every command must be documented well enough to be worth reading. The
// reported symptom was `theta-agent register help` answering with a usage
// line, so "has a Detail" is the property that matters, not just "exists".
func TestEveryCommandIsDocumented(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range commands {
		if c.Name == "" {
			t.Fatal("a command has no name")
		}
		if seen[c.Name] {
			t.Fatalf("duplicate command %q", c.Name)
		}
		seen[c.Name] = true
		if strings.TrimSpace(c.Summary) == "" {
			t.Errorf("%s: no Summary, so it cannot appear in the command list", c.Name)
		}
		if len(strings.TrimSpace(c.Detail)) < 40 {
			t.Errorf("%s: Detail is too thin to be documentation", c.Name)
		}
		// A reader arriving from an error message needs to see it used.
		if !strings.Contains(c.Detail, "theta-agent "+c.Name) {
			t.Errorf("%s: Detail shows no example invocation", c.Name)
		}
	}
}

// `<command> help`, `--help` and `-h` must all reach the command's own
// documentation. Falling through to the command's argument parser is what
// produced "[!] usage: theta-agent <register|unregister> <type> <name>".
func TestHelpArgsAreRecognised(t *testing.T) {
	for _, a := range []string{"help", "--help", "-h", "-help"} {
		if !isHelpArg(a) {
			t.Errorf("%q should be recognised as a request for help", a)
		}
	}
	for _, a := range []string{"systemd", "nginx", "--path", ""} {
		if isHelpArg(a) {
			t.Errorf("%q must not be treated as a request for help", a)
		}
	}
	if !wantsHelp([]string{"systemd", "help"}) {
		t.Error("help after a positional argument should still be recognised")
	}
	if wantsHelp([]string{"systemd", "nginx"}) {
		t.Error("a normal invocation was mistaken for a help request")
	}
}

func TestLookupResolvesAliases(t *testing.T) {
	if c := lookupCommand("--version"); c == nil || c.Name != "version" {
		t.Fatalf("--version did not resolve to the version command")
	}
	if lookupCommand("nonsuch") != nil {
		t.Fatal("an unknown command resolved to something")
	}
}

// The four command lists that used to be maintained by hand had already
// drifted: config-set and discover were missing from both files under
// completions/, so neither ever completed. Both are generated from the
// registry now; this holds the checked-in copies to it.
func TestCheckedInCompletionsMatchTheRegistry(t *testing.T) {
	bash, err := os.ReadFile("completions/theta-agent.bash")
	if err != nil {
		t.Fatalf("reading bash completion: %v", err)
	}
	m := regexp.MustCompile(`(?m)^\s*cmds="([^"]*)"`).FindSubmatch(bash)
	if m == nil {
		t.Fatal("bash completion has no cmds= line")
	}
	if got, want := string(m[1]), completionCommandList(); got != want {
		t.Errorf("completions/theta-agent.bash is out of date.\n got: %s\nwant: %s\n\nRegenerate it from cli_help.go's registry.", got, want)
	}

	zsh, err := os.ReadFile("completions/theta-agent.zsh")
	if err != nil {
		t.Fatalf("reading zsh completion: %v", err)
	}
	for _, c := range commands {
		if c.Name == "run" {
			continue
		}
		if !strings.Contains(string(zsh), "'"+c.Name+":") {
			t.Errorf("completions/theta-agent.zsh does not offer %q", c.Name)
		}
	}
}

// A zsh entry is single-quoted, so a summary containing an apostrophe would
// terminate it early and break the whole completion file.
func TestZshCommandListIsQuotable(t *testing.T) {
	if strings.Count(completionZshCommandList(), "'")%2 != 0 {
		t.Fatal("unbalanced quotes in the generated zsh command list")
	}
}

// The man page is generated from the same registry, so it cannot fall behind
// the CLI -- but it does have to be valid roff.
func TestManPageIsWellFormed(t *testing.T) {
	page := renderManPage()
	for _, want := range []string{".TH THETA-AGENT 8", ".SH NAME", ".SH SYNOPSIS", ".SH DESCRIPTION", ".SH COMMANDS", ".SH FILES"} {
		if !strings.Contains(page, want) {
			t.Errorf("man page is missing %s", want)
		}
	}
	for _, c := range commands {
		if !strings.Contains(page, ".B "+c.Name) {
			t.Errorf("man page does not document %q", c.Name)
		}
	}
	// .nf/.fi must balance or everything after an example stays preformatted.
	if strings.Count(page, "\n.nf\n") != strings.Count(page, "\n.fi\n") {
		t.Fatalf("unbalanced .nf/.fi in the man page: %d vs %d",
			strings.Count(page, "\n.nf\n"), strings.Count(page, "\n.fi\n"))
	}
}

func TestManEscapeProtectsControlCharacters(t *testing.T) {
	// A line starting with '.' or '\'' is read as a roff request.
	if got := manEscape(".service"); !strings.HasPrefix(got, `\&`) {
		t.Errorf("a leading dot was not escaped: %q", got)
	}
	if got := manEscape("'quoted"); !strings.HasPrefix(got, `\&`) {
		t.Errorf("a leading apostrophe was not escaped: %q", got)
	}
	if got := manEscape(`C:\Theta42`); strings.Contains(got, `\T`) {
		t.Errorf("a backslash was left to start an escape sequence: %q", got)
	}
}
