package main

import (
	"testing"
)

func TestHandleCLIHelpAndVersion(t *testing.T) {
	if !handleCLI([]string{"version"}) {
		t.Errorf("expected handleCLI('version') to return true")
	}
	if !handleCLI([]string{"--help"}) {
		t.Errorf("expected handleCLI('--help') to return true")
	}
	if handleCLI([]string{"unknown-command"}) {
		t.Errorf("expected handleCLI('unknown-command') to return false")
	}
}
