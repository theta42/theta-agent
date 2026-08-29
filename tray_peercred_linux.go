package main

// Linux half of the tray IPC peer-credential check. The generic
// tray_server.go calls peerEuid for every mutating command; this file carries
// the SO_PEERCRED implementation, which exists only on Linux (see
// tray_peercred_other.go for the rest of the world).

import (
	"net"
	"syscall"
)

// peerEuid returns the euid of the process on the other end of a Unix socket
// using SO_PEERCRED. Returns -1 if the credential cannot be read — callers
// must treat -1 as "not root" so the safe default is to refuse the mutating
// command.
func peerEuid(conn net.Conn) int64 {
	sc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return -1
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1
	}
	if credErr != nil {
		return -1
	}
	return int64(cred.Uid)
}
