//go:build !server
// +build !server

package main

// The "Internet exit" submenu.
//
// The Directory has always computed which exits a device may use "so the UI and
// the agent tray render the same set" (routes/api_mesh.js) -- but the tray half
// did not exist, so the data was unreachable from the desktop and an exit could
// only be chosen from the web UI. This is that half.
//
// The submenu is rebuilt only when the offered set actually changes: status
// arrives on every daemon tick, and tearing menu items down and recreating them
// on each one makes the menu flicker and drops a click that lands mid-rebuild.

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"fyne.io/systray"
)

var exitMenu struct {
	mu sync.Mutex
	// Parent item; its submenu holds the choices.
	root *systray.MenuItem
	// "Local breakout", always first and always offered.
	local *systray.MenuItem
	// One item per site, keyed by site id.
	items map[int]*systray.MenuItem
	// Closed when the current set of items is torn down, so their click
	// goroutines exit instead of leaking one per rebuild.
	done chan struct{}
	// Signature of the set currently rendered, to skip needless rebuilds.
	sig string
}

// initExitMenu creates the parent item. Called once from onReady.
func initExitMenu() {
	exitMenu.mu.Lock()
	defer exitMenu.mu.Unlock()
	exitMenu.root = systray.AddMenuItem("Internet exit", "Route this device's internet traffic through another site")
	exitMenu.items = map[int]*systray.MenuItem{}
	exitMenu.root.Hide() // nothing to offer until the daemon says otherwise
}

// exitLabel renders one choice. Country/city are what the Directory stores for
// exactly this purpose, so show them when present.
func exitLabel(e TrayExit) string {
	label := e.Name
	var where []string
	if e.City != "" {
		where = append(where, e.City)
	}
	if e.Country != "" {
		where = append(where, e.Country)
	}
	if len(where) > 0 {
		label += " (" + strings.Join(where, ", ") + ")"
	}
	if e.IsLocal {
		label += " — this site"
	}
	return label
}

// exitSignature identifies the offered set, so an unchanged set is not rebuilt.
func exitSignature(exits []TrayExit) string {
	var b strings.Builder
	for _, e := range exits {
		fmt.Fprintf(&b, "%d:%s|", e.SiteID, exitLabel(e))
	}
	return b.String()
}

// syncExitMenu reconciles the submenu with the status the daemon pushed.
func syncExitMenu(s TrayStatus) {
	exitMenu.mu.Lock()
	defer exitMenu.mu.Unlock()

	if exitMenu.root == nil {
		return
	}
	if len(s.Exits) == 0 {
		// No mesh device yet, or a directory too old to offer exits. Hiding
		// beats showing an empty menu that looks broken.
		exitMenu.root.Hide()
		return
	}
	exitMenu.root.Show()

	if sig := exitSignature(s.Exits); sig != exitMenu.sig {
		exitMenu.sig = sig
		rebuildExitItemsLocked(s.Exits)
	}
	markCurrentExitLocked(s.CurrentExitSiteID)
}

// rebuildExitItemsLocked tears the choices down and builds them again.
// Caller holds exitMenu.mu.
func rebuildExitItemsLocked(exits []TrayExit) {
	if exitMenu.done != nil {
		close(exitMenu.done) // stop the previous items' click goroutines
	}
	exitMenu.done = make(chan struct{})
	done := exitMenu.done

	for _, item := range exitMenu.items {
		item.Remove()
	}
	exitMenu.items = map[int]*systray.MenuItem{}
	if exitMenu.local != nil {
		exitMenu.local.Remove()
	}

	exitMenu.local = exitMenu.root.AddSubMenuItemCheckbox(
		"Local breakout (no exit)",
		"Send internet traffic out of this device's own connection",
		false)
	go watchExitClick(exitMenu.local, nil, done)

	for _, e := range exits {
		site := e.SiteID
		item := exitMenu.root.AddSubMenuItemCheckbox(exitLabel(e), "Route internet traffic through this site", false)
		exitMenu.items[site] = item
		go watchExitClick(item, &site, done)
	}
}

// markCurrentExitLocked ticks whichever choice is live. Caller holds the mutex.
func markCurrentExitLocked(current *int) {
	if exitMenu.local != nil {
		if current == nil {
			exitMenu.local.Check()
		} else {
			exitMenu.local.Uncheck()
		}
	}
	for site, item := range exitMenu.items {
		if current != nil && *current == site {
			item.Check()
		} else {
			item.Uncheck()
		}
	}
}

// watchExitClick sends the daemon a set_exit for one choice until the menu is
// rebuilt. siteID nil means local breakout.
//
// The checkmark is deliberately NOT set here: the daemon re-reads the selection
// from the Directory after applying it and pushes the result back, so the tick
// reflects what actually took effect rather than what was clicked.
func watchExitClick(item *systray.MenuItem, siteID *int, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case _, ok := <-item.ClickedCh:
			if !ok {
				return
			}
			if siteID == nil {
				log.Println("theta-agent-tray: requesting local breakout")
			} else {
				log.Printf("theta-agent-tray: requesting exit via site %d", *siteID)
			}
			sendCmd(TrayCommand{Command: "set_exit", SiteID: siteID})
		}
	}
}
