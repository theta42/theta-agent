//go:build windows

package main

import "testing"

// TestCollectLoggedUsersWindows is a smoke test for the WTS path: it must not
// crash, must return only non-empty usernames, and on a machine with at least
// one interactive session (like this one) should find at least one user. It
// never asserts on exact names so it stays valid across environments.
func TestCollectLoggedUsersWindows(t *testing.T) {
	users := collectLoggedUsers()
	for _, u := range users {
		if u.User == "" {
			t.Errorf("logged user with empty name: %+v", u)
		}
	}
	// The test host is an interactive desktop; there should be a console/active
	// session to report. This catches the "always empty" regression.
	if len(users) == 0 {
		t.Errorf("no logged-in users detected on an interactive host")
	}
}
