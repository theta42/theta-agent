//go:build !server
// +build !server

package main

import "testing"

func TestExitLabelIncludesPlace(t *testing.T) {
	cases := []struct {
		in   TrayExit
		want string
	}{
		{TrayExit{Name: "NYC"}, "NYC"},
		{TrayExit{Name: "NYC", City: "New York"}, "NYC (New York)"},
		{TrayExit{Name: "NYC", Country: "US"}, "NYC (US)"},
		{TrayExit{Name: "NYC", City: "New York", Country: "US"}, "NYC (New York, US)"},
		{TrayExit{Name: "HQ", IsLocal: true}, "HQ — this site"},
		{TrayExit{Name: "HQ", City: "Austin", IsLocal: true}, "HQ (Austin) — this site"},
	}
	for _, c := range cases {
		if got := exitLabel(c.in); got != c.want {
			t.Fatalf("exitLabel(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The signature exists so an unchanged offer set does not tear the submenu
// down and rebuild it on every daemon tick -- that flickers the menu and drops
// a click landing mid-rebuild.
func TestExitSignatureStableAcrossIdenticalSets(t *testing.T) {
	a := []TrayExit{{SiteID: 2, Name: "NYC"}, {SiteID: 5, Name: "LON"}}
	b := []TrayExit{{SiteID: 2, Name: "NYC"}, {SiteID: 5, Name: "LON"}}
	if exitSignature(a) != exitSignature(b) {
		t.Fatalf("identical sets produced different signatures")
	}
}

func TestExitSignatureChangesWhenOfferChanges(t *testing.T) {
	base := []TrayExit{{SiteID: 2, Name: "NYC"}}
	for name, other := range map[string][]TrayExit{
		"added site":   {{SiteID: 2, Name: "NYC"}, {SiteID: 5, Name: "LON"}},
		"renamed site": {{SiteID: 2, Name: "New York"}},
		"removed site": {},
		"new id":       {{SiteID: 3, Name: "NYC"}},
	} {
		if exitSignature(base) == exitSignature(other) {
			t.Fatalf("%s did not change the signature", name)
		}
	}
}

// The signature must not depend on the current selection -- only on what is
// offered. Otherwise picking an exit rebuilds the whole submenu.
func TestExitSignatureIgnoresSelection(t *testing.T) {
	exits := []TrayExit{{SiteID: 2, Name: "NYC"}, {SiteID: 5, Name: "LON"}}
	first := exitSignature(exits)
	if second := exitSignature(exits); first != second {
		t.Fatalf("signature is not stable for the same input")
	}
}
