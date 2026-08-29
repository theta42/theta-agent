//go:build !linux

package main

// Non-Linux half of the tray IPC peer-credential check. The generic
// tray_server.go calls peerEuid for every mutating command.

import (
	"net"
	"runtime"
)

// peerEuid returns the euid of the process on the other end of the tray IPC
// connection.
//
// Linux is the only platform that offers SO_PEERCRED; this build carries the
// fallback. On Windows AF_UNIX (Win10 1803+) exposes no credential-passing
// interface at all, so there is nothing to read — and the tray there is a
// legitimate everyday client: it runs as the logged-in user while the daemon
// runs as SYSTEM, and the gate is the ACL on %ProgramData%\Theta42 where the
// socket lives (tray_ipc.go), not peer credentials. Mutating commands are
// therefore accepted on Windows exactly as they were before v2.21.0. Every
// other platform takes the safe default: refuse, by reporting "not root".
func peerEuid(conn net.Conn) int64 {
	if runtime.GOOS == "windows" {
		return 0
	}
	return -1
}
