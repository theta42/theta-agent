package main

import (
	"testing"

	"github.com/hashicorp/mdns"
)

func TestTxtField(t *testing.T) {
	entry := &mdns.ServiceEntry{InfoFields: []string{
		"hosts=sso.example.com,proxy.example.com",
		"site=staten-island",
		"directoryHost=sso.example.com",
		"directoryAddr=10.0.0.5:80",
		"version=v3.12.0",
	}}

	cases := map[string]string{
		"hosts":         "sso.example.com,proxy.example.com",
		"site":          "staten-island",
		"directoryHost": "sso.example.com",
		"directoryAddr": "10.0.0.5:80",
		"version":       "v3.12.0",
		"missing":       "",
	}
	for key, want := range cases {
		if got := txtField(entry, key); got != want {
			t.Errorf("txtField(%q) = %q, want %q", key, got, want)
		}
	}
}
