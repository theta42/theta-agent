package main

// One description of the CLI, used for three things: the top-level summary,
// per-command detailed help, and the man page.
//
// It replaces three hand-maintained copies that had already drifted apart --
// printUsage(), the bash/zsh completions, and nothing at all for man. Commands
// went missing from one and not the others (`config-set` was absent from help
// and both completions; `discover` was absent from the completions), and
// asking for help on a subcommand printed a single usage line:
//
//     $ theta-agent register help
//     [!] usage: theta-agent <register|unregister> <type> <name>
//
// which is the error message, not documentation -- it does not say what the
// types mean, what gets created in the Directory, or how to undo it.

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// command is one CLI verb. Summary is the one-liner in the command list;
// Detail is everything a reader needs once they have chosen it.
type command struct {
	Name    string
	Args    string // argument sketch shown after the name, e.g. "<type> <name>"
	Summary string
	Detail  string // free text: what it does, flags, examples
	Aliases []string
}

// commands is the registry. Keep Detail written for someone who has just hit a
// problem: what it does, what it touches on disk, and a real example.
var commands = []command{
	{
		Name:    "run",
		Summary: "Run the agent daemon in the foreground",
		Detail: `Run the agent in the foreground, logging to stdout.

This is what the theta-agent systemd unit executes. Running it by hand is
useful when the service will not start and you want the failure on your
terminal instead of in the journal.

Invoking theta-agent with no arguments at all does the same thing.

Reads /etc/theta42/agent.yml (%ProgramData%\Theta42\agent.yml on Windows).

  theta-agent run
  journalctl -u theta-agent -f      # the same output, once it is a service`,
	},
	{
		Name:    "register",
		Args:    "<type> <name>",
		Summary: "Register a service on this host into the Directory",
		Detail: `Register a service running on this host as a child resource of the host in
the Theta Directory.

TYPES
  systemd          a systemd unit          (name: the unit, with or without .service)
  systemd-timer    a systemd timer         (name: the timer unit)
  docker           a Docker container      (name: the container name)
  podman           a Podman container      (name: the container name)
  process          a bare process          (name: matched against the process name)
  cron             a cron job              (name: a label you choose)
  lxc              an LXC container        (name: the container name)
  kvm, libvirt     a libvirt domain        (name: the domain name)

The agent probes the named service and reports its state to the Directory
with its regular telemetry, so it appears under this host and its status
stays current. Registration is recorded in agent.yml under services:, so it
survives restarts and upgrades.

  theta-agent register systemd nginx
  theta-agent register docker plex
  theta-agent list-services
  theta-agent unregister systemd nginx`,
	},
	{
		Name:    "unregister",
		Args:    "<type> <name>",
		Summary: "Remove a registered service from the Directory",
		Detail: `Stop reporting a service and remove it from this host in the Directory.

Takes the same type and name that were used to register it -- see
'theta-agent help register' for the list of types.

Removes the entry from services: in agent.yml. It does not stop, disable or
otherwise touch the service itself.

  theta-agent unregister systemd nginx`,
	},
	{
		Name:    "list-services",
		Summary: "List the services registered on this host",
		Detail: `Print the services this agent reports on, as recorded in agent.yml.

  theta-agent list-services`,
	},
	{
		Name:    "get-secret",
		Args:    "<key>",
		Summary: "Fetch one secret value from OpenBao",
		Detail: `Print a single secret value this host is entitled to.

The agent asks the Directory, which reads OpenBao with its own credentials --
this host never holds a Vault token. Only secrets scoped to this node or
shared with it are readable.

  theta-agent get-secret db_password`,
	},
	{
		Name:    "get-secrets",
		Args:    "[flags]",
		Summary: "Fetch every secret this host may read",
		Detail: `Print all secrets scoped to this host and the resources it is granted.

FLAGS
  --json    print as a JSON object
  --env     print as KEY=value lines, suitable for sourcing

  theta-agent get-secrets --json
  eval "$(theta-agent get-secrets --env)"`,
	},
	{
		Name:    "verify",
		Args:    "[flags]",
		Summary: "Check that this host's configuration and keys are usable",
		Detail: `Validate the agent's configuration without changing anything.

Checks, in order:
  - agent.yml exists and parses
  - server_url is a URL with a host
  - a credential is present (auth_token, or join_key before first enrolment)
  - public_key -- the Directory's signing key -- decodes to a 32-byte Ed25519
    key, so signed commands can actually be verified
  - the WireGuard private key, if one has been generated, is a well-formed
    32-byte Curve25519 key and is not world-readable

Exits non-zero if anything is wrong, so it can gate a script. install.sh runs
it after writing configuration.

FLAGS
  --path <file>    config to check (default /etc/theta42/agent.yml)
  --quiet          print nothing; report only through the exit status

  theta-agent verify
  theta-agent verify --path ./agent.yml`,
	},
	{
		Name:    "config-set",
		Args:    "<key>=<value>...",
		Summary: "Merge settings into agent.yml",
		Detail: `Set one or more TOP-LEVEL keys in agent.yml, in place.

Keys that are already present are updated; keys that are missing are appended.
Comments and every other setting are preserved, and the result is parsed before
the file is replaced -- so a bad value fails without leaving a broken config.

Only top-level keys. A nested key (anything under capabilities:, for example)
is refused rather than silently written at the wrong indentation, which would
move it out of its parent and quietly drop the setting.

FLAGS
  --path <file>    config to edit (default /etc/theta42/agent.yml)

  theta-agent config-set server_url=https://sso.example.com
  theta-agent config-set auth_token=... location=rack-3`,
	},
	{
		Name:    "reinitialize",
		Args:    "[flags]",
		Summary: "Reset enrolment credentials and register again",
		Detail: `Discard this host's issued credentials and enrol again from scratch.

Use it when the Directory no longer recognises this agent -- the device was
deleted at the far end, or the token was revoked.

FLAGS
  --join-key <key>    join key to enrol with

  theta-agent reinitialize --join-key tjk_...`,
	},
	{
		Name:    "discover",
		Args:    "[flags]",
		Summary: "List theta-suite sites announced on this network",
		Detail: `Browse for theta-suite sites announcing themselves over mDNS on the local
network segment, and print what is found.

This only ever prints candidates. The agent never switches the Directory it
talks to based on an announcement: mDNS is unauthenticated, so choosing a
directory stays a human decision. mDNS is link-local -- it does not cross
routers or VLANs -- so nothing will be found from another subnet.

FLAGS
  --timeout <duration>    browse window (default 3s)
  --urls-only             print just https://<directoryHost>, one per line
  --json                  print the full announcement list as JSON

  theta-agent discover
  theta-agent discover --urls-only --timeout 5s`,
	},
	{
		Name:    "update",
		Summary: "Self-update this binary from the Directory",
		Detail: `Download the current release binary for this platform and replace this one.

  theta-agent update`,
	},
	{
		Name:    "install-completions",
		Summary: "Install bash/zsh tab-completion",
		Detail: `Write shell completion for this CLI.

  theta-agent install-completions`,
	},
	{
		Name:    "install-service",
		Summary: "(Windows) register the agent as a service",
		Detail: `Register theta-agent as a Windows service.

Windows only; on Linux the installer writes a systemd unit instead.

  theta-agent install-service`,
	},
	{
		Name:    "remove-service",
		Summary: "(Windows) unregister the agent service",
		Detail: `Remove the theta-agent Windows service.

  theta-agent remove-service`,
	},
	{
		Name:    "configure-login",
		Summary: "(Windows) wire OpenCredential to the LDAP tunnel",
		Detail: `Point the Windows credential provider at the agent's LDAP tunnel, so domain
users can sign in to this host against the Directory.

Windows only.

  theta-agent configure-login`,
	},
	{
		Name:    "version",
		Summary: "Show version information",
		Aliases: []string{"--version", "-v"},
		Detail: `Print the agent version.

  theta-agent version`,
	},
	{
		Name:    "help",
		Args:    "[command]",
		Summary: "Show help; 'help <command>' for one command in detail",
		Aliases: []string{"--help", "-h"},
		Detail: `Show help.

With no argument, list every command. With a command name, print that
command's full help -- the same text as 'theta-agent <command> --help'.

FLAGS
  --man    write this CLI's man page (roff) to stdout

  theta-agent help
  theta-agent help register
  theta-agent register --help`,
	},
}

func lookupCommand(name string) *command {
	for i := range commands {
		if commands[i].Name == name {
			return &commands[i]
		}
		for _, a := range commands[i].Aliases {
			if a == name {
				return &commands[i]
			}
		}
	}
	return nil
}

// isHelpArg reports whether an argument is asking for help rather than being a
// value. Accepts the three spellings people actually type; `theta-agent
// register help` used to fall through to the argument parser and print a usage
// error, which is how this was reported.
func isHelpArg(a string) bool {
	switch a {
	case "help", "--help", "-h", "-help":
		return true
	}
	return false
}

// wantsHelp reports whether the argument list is a request for help on the
// command rather than an invocation of it.
func wantsHelp(args []string) bool {
	for _, a := range args {
		if isHelpArg(a) {
			return true
		}
	}
	return false
}

func (c *command) invocation() string {
	if c.Args == "" {
		return "theta-agent " + c.Name
	}
	return "theta-agent " + c.Name + " " + c.Args
}

// printCommandHelp writes one command's detailed help.
func printCommandHelp(c *command, w *os.File) {
	fmt.Fprintf(w, "%s\n\n", c.invocation())
	fmt.Fprintf(w, "%s\n", strings.TrimRight(c.Detail, "\n"))
	if len(c.Aliases) > 0 {
		fmt.Fprintf(w, "\nAlso accepted as: %s\n", strings.Join(c.Aliases, ", "))
	}
	fmt.Fprintln(w)
}

// printUsage lists every command. Kept to one line each: the detail lives
// behind `help <command>` so this stays readable as commands are added.
func printUsage() {
	fmt.Println("Theta Agent " + AgentVersion + " - Unified Endpoint Management CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  theta-agent [command] [arguments]")
	fmt.Println()
	fmt.Println("Running theta-agent with no command runs the agent daemon in the foreground.")
	fmt.Println()
	fmt.Println("Commands:")

	width := 0
	for _, c := range commands {
		if n := len(c.Name); n > width {
			width = n
		}
	}
	for _, c := range commands {
		fmt.Printf("  %-*s  %s\n", width, c.Name, c.Summary)
	}
	fmt.Println()
	fmt.Println("Run 'theta-agent help <command>' for a command's full documentation,")
	fmt.Println("or read the man page with 'man theta-agent'.")
	fmt.Println()
}

// runHelp implements `theta-agent help [command]` and `help --man`.
func runHelp(args []string) {
	for _, a := range args {
		if a == "--man" {
			fmt.Print(renderManPage())
			return
		}
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if c := lookupCommand(a); c != nil {
			printCommandHelp(c, os.Stdout)
			return
		}
		fmt.Fprintf(os.Stderr, "theta-agent: unknown command %q\n\n", a)
		printUsage()
		os.Exit(1)
	}
	printUsage()
}

// renderManPage emits the man page in roff, from the same registry the
// interactive help uses, so the two cannot drift. install.sh writes the output
// to /usr/share/man/man8/theta-agent.8.
func renderManPage() string {
	var b strings.Builder
	b.WriteString(`.\" Generated by 'theta-agent help --man' -- do not edit by hand.` + "\n")
	fmt.Fprintf(&b, ".TH THETA-AGENT 8 \"\" \"Theta Agent %s\" \"System Administration\"\n", AgentVersion)
	b.WriteString(".SH NAME\ntheta-agent \\- Theta Suite endpoint management agent\n")
	b.WriteString(".SH SYNOPSIS\n.B theta-agent\n[\\fIcommand\\fR] [\\fIarguments\\fR]\n")
	b.WriteString(`.SH DESCRIPTION
.B theta-agent
runs on a managed host and connects outbound to a Theta Directory over a
persistent WebSocket. It reports telemetry and the state of registered
services, executes signed commands, brokers secrets from OpenBao without ever
holding a Vault token, and can carry the host onto the site's WireGuard mesh.
.PP
With no command it runs the daemon in the foreground; that is what the
systemd unit executes.
.SH FILES
.TP
.I /etc/theta42/agent.yml
Configuration: directory URL, credentials, capabilities, registered services.
.TP
.I /etc/theta42/wg_private.key
This host's WireGuard private key, mode 0600. Generated on first use and never
sent anywhere \\-- only the public half is registered with the Directory. Back
it up alongside agent.yml.
.TP
.I /etc/systemd/system/theta-agent.service
The unit installed by install.sh.
.SH COMMANDS
`)
	sorted := append([]command(nil), commands...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, c := range sorted {
		fmt.Fprintf(&b, ".TP\n.B %s\n", manEscape(strings.TrimPrefix(c.invocation(), "theta-agent ")))
		b.WriteString(manBody(c.Detail))
	}
	b.WriteString(`.SH EXIT STATUS
Zero on success. Non-zero on failure;
.B theta-agent verify
in particular is meant to gate scripts.
.SH SEE ALSO
.BR systemctl (1),
.BR journalctl (1),
.BR wg-quick (8)
.PP
https://github.com/theta42/theta-agent
`)
	return b.String()
}

// manBody turns a Detail block into roff: blank lines become paragraph breaks,
// and indented lines (examples, flag tables) are set literally so they keep
// their spacing.
func manBody(detail string) string {
	var b strings.Builder
	lines := strings.Split(strings.TrimRight(detail, "\n"), "\n")
	literal := false
	for _, line := range lines {
		indented := strings.HasPrefix(line, "  ")
		switch {
		case strings.TrimSpace(line) == "":
			if literal {
				b.WriteString(".fi\n")
				literal = false
			}
			b.WriteString(".PP\n")
		case indented && !literal:
			b.WriteString(".nf\n")
			literal = true
			b.WriteString(manEscape(line) + "\n")
		default:
			b.WriteString(manEscape(line) + "\n")
		}
	}
	if literal {
		b.WriteString(".fi\n")
	}
	return b.String()
}

// manEscape protects roff's control characters. A line starting with '.' or
// '\” would be read as a request, and a bare backslash starts an escape.
func manEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\e`)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}

// completionCommandList renders the bash completion's command list from the
// registry. `run` is left out: it is the implicit default, and offering it as
// a completion suggests it is something you have to type.
func completionCommandList() string {
	var names []string
	for _, c := range commands {
		if c.Name == "run" {
			continue
		}
		names = append(names, c.Name)
	}
	return strings.Join(names, " ")
}

// completionZshCommandList renders zsh's 'name:description' pairs, reusing the
// same one-line summaries the top-level help prints.
func completionZshCommandList() string {
	var b strings.Builder
	for _, c := range commands {
		if c.Name == "run" {
			continue
		}
		// Single quotes delimit each entry, so a summary may not contain one.
		fmt.Fprintf(&b, "        '%s:%s'\n", c.Name, strings.ReplaceAll(c.Summary, "'", ""))
	}
	return strings.TrimRight(b.String(), "\n")
}
