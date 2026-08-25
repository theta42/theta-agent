package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withLookPath describes a host that has exactly the named binaries.
func withLookPath(t *testing.T, present ...string) {
	t.Helper()
	have := map[string]bool{}
	for _, p := range present {
		have[p] = true
	}
	prev := wgLookPath
	wgLookPath = func(name string) (string, error) {
		if have[name] {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("executable file not found in $PATH")
	}
	t.Cleanup(func() { wgLookPath = prev })
}

func withOSRelease(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := wgOSReleasePath
	wgOSReleasePath = path
	t.Cleanup(func() { wgOSReleasePath = prev })
}

// The regression: the tools were never checked for, so a host without them
// looked identical to a working one until wg-quick was executed.
func TestCheckWireGuardToolsDetectsMissingBinaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows drives wireguard.exe, not wg-quick")
	}
	cases := []struct {
		name    string
		present []string
		wantErr bool
	}{
		{"nothing installed", nil, true},
		{"kernel module only, no tools", []string{"ip"}, true},
		{"wg but no wg-quick", []string{"wg"}, true},
		{"wg-quick but no wg", []string{"wg-quick"}, true},
		{"both installed", []string{"wg", "wg-quick"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withLookPath(t, tc.present...)
			err := checkWireGuardTools()
			if tc.wantErr != (err != nil) {
				t.Fatalf("checkWireGuardTools() = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrWireGuardToolsMissing) {
				t.Errorf("error does not wrap the sentinel: %v", err)
			}
			if got := WireGuardToolsReady(); got == tc.wantErr {
				t.Errorf("WireGuardToolsReady() = %v, want %v", got, !tc.wantErr)
			}
		})
	}
}

// The whole point of the check is that the message names the package. The raw
// exec error ("executable file not found in $PATH") named nothing and was what
// the tray showed the user.
func TestCheckWireGuardToolsErrorIsActionable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows drives wireguard.exe, not wg-quick")
	}
	withLookPath(t)
	withOSRelease(t, "ID=ubuntu\nID_LIKE=debian\n")
	err := checkWireGuardTools()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"wg-quick", "wireguard-tools", "apt-get install"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestWireGuardInstallHintPerDistro(t *testing.T) {
	cases := []struct {
		osRelease string
		want      string
	}{
		{"ID=ubuntu\nID_LIKE=debian\n", "apt-get"},
		{"ID=debian\n", "apt-get"},
		// A derivative names its parent only in ID_LIKE.
		{"ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n", "apt-get"},
		{"ID=rocky\nID_LIKE=\"rhel centos fedora\"\n", "dnf"},
		{"ID=fedora\n", "dnf"},
		{"ID=arch\n", "pacman"},
		{"ID=manjaro\nID_LIKE=arch\n", "pacman"},
		{"ID=alpine\n", "apk"},
		{"ID=opensuse-leap\nID_LIKE=\"suse opensuse\"\n", "zypper"},
		{"ID=plan9\n", "wireguard-tools"},
	}
	for _, tc := range cases {
		withOSRelease(t, tc.osRelease)
		if got := wireguardInstallHint(); !strings.Contains(got, tc.want) {
			t.Errorf("os-release %q -> hint %q, want it to mention %q", tc.osRelease, got, tc.want)
		}
	}
}

// An unreadable /etc/os-release must still produce advice, not an empty string
// or a panic.
func TestWireGuardInstallHintWithoutOSRelease(t *testing.T) {
	prev := wgOSReleasePath
	wgOSReleasePath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { wgOSReleasePath = prev })
	if got := wireguardInstallHint(); got == "" {
		t.Error("no install hint at all")
	}
}

// ApplyWireGuard used to write the config and only then discover it could not
// run it, leaving a file behind on a host with no way to use it.
func TestApplyWireGuardRefusesWithoutToolsAndWritesNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows drives wireguard.exe, not wg-quick")
	}
	withLookPath(t)
	rec := &argvRecorder{}
	conf := filepath.Join(t.TempDir(), "wg", "theta-mesh.conf")
	ops := &linuxPlatformOps{exec: rec, tunnelName: "theta-mesh", confPath: conf}

	err := ops.ApplyWireGuard("[Interface]\n")
	if !errors.Is(err, ErrWireGuardToolsMissing) {
		t.Fatalf("ApplyWireGuard() = %v, want the missing-tools sentinel", err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("ran %v; nothing should have been executed", rec.calls)
	}
	if _, statErr := os.Stat(conf); !os.IsNotExist(statErr) {
		t.Errorf("a config was persisted at %s despite no way to bring it up", conf)
	}
}

func TestApplyWireGuardRunsWgQuickWhenToolsPresent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows drives wireguard.exe, not wg-quick")
	}
	withLookPath(t, "wg", "wg-quick")
	// A host where `ip link show` fails is a host with no tunnel yet.
	rec := &argvRecorder{fail: map[string]bool{"ip": true}}
	conf := filepath.Join(t.TempDir(), "wg", "theta-mesh.conf")
	ops := &linuxPlatformOps{exec: rec, tunnelName: "theta-mesh", confPath: conf}

	if err := ops.ApplyWireGuard("[Interface]\nPrivateKey = x\n"); err != nil {
		t.Fatalf("ApplyWireGuard() = %v", err)
	}
	if got := argvLines(rec); len(got) != 2 || got[1] != "wg-quick up theta-mesh" {
		t.Fatalf("ran %v, want a state probe then [wg-quick up theta-mesh]", got)
	}
	body, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("config not persisted: %v", err)
	}
	if !strings.Contains(string(body), "PrivateKey = x") {
		t.Errorf("persisted config is %q", body)
	}
}

// `wg-quick up` refuses an interface that already exists, so re-applying over
// a live tunnel used to fail outright -- which is exactly what changing your
// exit does.
func TestApplyWireGuardCyclesALiveTunnel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows drives wireguard.exe, not wg-quick")
	}
	withLookPath(t, "wg", "wg-quick")
	rec := &argvRecorder{} // everything succeeds: the interface is up
	ops := &linuxPlatformOps{
		exec:       rec,
		tunnelName: "theta-mesh",
		confPath:   filepath.Join(t.TempDir(), "wg", "theta-mesh.conf"),
	}
	if err := ops.ApplyWireGuard("[Interface]\n"); err != nil {
		t.Fatalf("ApplyWireGuard() = %v", err)
	}
	got := argvLines(rec)
	want := []string{"ip link show theta-mesh", "wg-quick down theta-mesh", "wg-quick up theta-mesh"}
	if strings.Join(got, " | ") != strings.Join(want, " | ") {
		t.Errorf("ran %v, want %v", got, want)
	}
}

// PersistWireGuard is the half that must never touch the interface.
func TestPersistWireGuardRunsNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows drives wireguard.exe, not wg-quick")
	}
	withLookPath(t, "wg", "wg-quick")
	rec := &argvRecorder{}
	conf := filepath.Join(t.TempDir(), "wg", "theta-mesh.conf")
	ops := &linuxPlatformOps{exec: rec, tunnelName: "theta-mesh", confPath: conf}

	if err := ops.PersistWireGuard("[Interface]\nAddress = 10.1.128.2/32\n"); err != nil {
		t.Fatalf("PersistWireGuard() = %v", err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("ran %v; persisting must not touch the interface", rec.calls)
	}
	body, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("config not persisted: %v", err)
	}
	if !strings.Contains(string(body), "10.1.128.2/32") {
		t.Errorf("persisted config is %q", body)
	}
}

func argvLines(r *argvRecorder) []string {
	out := make([]string, 0, len(r.calls))
	for _, c := range r.calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}
