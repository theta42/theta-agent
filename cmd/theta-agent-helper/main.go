//go:build windows

// theta-agent-helper — session-aware companion for the theta-agent Windows
// service (DESIGN-WINDOWS.md §4 and §8).
//
// The agent service runs in session 0 with no interactive desktop. Operations
// that need an interactive session (lock, display off, logout) or that must
// outlive the service process (staged self-update: swap the locked exe and
// restart the service) run here instead.
//
//   theta-agent-helper lock
//   theta-agent-helper display_off
//   theta-agent-helper logout [user]
//   theta-agent-helper update <newExe> <currentExe> <serviceName>
//
// Sleep is handled in-process by the service (SetSuspendState works from
// session 0); it is also exposed here for manual use.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	wmSyscommand      = 0x0112
	scMonitorpower    = 0xF170
	sleepHwnd         = ^uintptr(0) // HWND_BROADCAST
	monitorPowerOff   = 2

	wtsCurrentServerHandle = 0
	wtsUserName            = 5
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	wtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")
	powrprof = syscall.NewLazyDLL("powrprof.dll")

	procLockWorkStation     = user32.NewProc("LockWorkStation")
	procSendMessageW        = user32.NewProc("SendMessageW")
	procWTSLogoffSession    = wtsapi32.NewProc("WTSLogoffSession")
	procWTSEnumerateSessionsW = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory       = wtsapi32.NewProc("WTSFreeMemory")
	procSetSuspendState     = powrprof.NewProc("SetSuspendState")
)

type wtsSessionInfo struct {
	SessionID    uint32
	WinStation   *uint16
	ConnectState uint32
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: theta-agent-helper <lock|display_off|logout|update|sleep> [args...]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "lock":
		lockSession()
	case "display_off":
		displayOff()
	case "logout":
		logoutSession(argOrEmpty(2))
	case "sleep":
		sleepHost()
	case "update":
		if len(os.Args) < 5 {
			fmt.Fprintln(os.Stderr, "usage: theta-agent-helper update <newExe> <currentExe> <serviceName>")
			os.Exit(1)
		}
		doUpdate(os.Args[2], os.Args[3], os.Args[4])
	default:
		fmt.Fprintf(os.Stderr, "unknown action %q\n", os.Args[1])
		os.Exit(1)
	}
}

func argOrEmpty(i int) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return ""
}

func lockSession() {
	r, _, err := procLockWorkStation.Call()
	if r == 0 {
		fmt.Fprintf(os.Stderr, "LockWorkStation failed: %v\n", err)
		os.Exit(1)
	}
}

func displayOff() {
	r, _, err := procSendMessageW.Call(sleepHwnd, wmSyscommand, scMonitorpower, monitorPowerOff)
	if r == 0 {
		fmt.Fprintf(os.Stderr, "SendMessage(SC_MONITORPOWER) failed: %v\n", err)
		os.Exit(1)
	}
}

func sleepHost() {
	r, _, err := procSetSuspendState.Call(0, 0, 0)
	if r == 0 {
		fmt.Fprintf(os.Stderr, "SetSuspendState failed: %v\n", err)
		os.Exit(1)
	}
}

// logoutSession logs off the active console session, or the session of the
// given user (matched by WTS session enumeration).
func logoutSession(user string) {
	sessionID := activeConsoleSessionID()
	if user != "" {
		id, err := sessionForUser(user)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logout: %v\n", err)
			os.Exit(1)
		}
		sessionID = id
	}
	if sessionID == 0 {
		fmt.Fprintln(os.Stderr, "logout: no active session to log off")
		os.Exit(1)
	}

	r, _, err := procWTSLogoffSession.Call(wtsCurrentServerHandle, uintptr(sessionID), 0)
	if r == 0 {
		fmt.Fprintf(os.Stderr, "WTSLogoffSession(%d) failed: %v\n", sessionID, err)
		os.Exit(1)
	}
	fmt.Printf("logged off session %d\n", sessionID)
}

func activeConsoleSessionID() uint32 {
	id, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("WTSGetActiveConsoleSessionId").Call()
	return uint32(id)
}

func sessionForUser(user string) (uint32, error) {
	var pInfo *wtsSessionInfo
	var count uint32

	r, _, err := procWTSEnumerateSessionsW.Call(wtsCurrentServerHandle, 0, 1, uintptr(unsafe.Pointer(&pInfo)), uintptr(unsafe.Pointer(&count)))
	if r == 0 {
		return 0, fmt.Errorf("WTSEnumerateSessionsW: %v", err)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pInfo)))

	want := strings.ToLower(user)
	for i := uint32(0); i < count; i++ {
		info := (*wtsSessionInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(pInfo)) + uintptr(i)*unsafe.Sizeof(*pInfo)))
		name := wtsSessionUsername(info.SessionID)
		if name != "" && strings.ToLower(name) == want {
			return info.SessionID, nil
		}
	}
	return 0, fmt.Errorf("no active session for user %q", user)
}

func wtsSessionUsername(sessionID uint32) string {
	var pBuf *uint16
	var bytes uint32
	r, _, _ := procWTSQuerySessionInformationW.Call(wtsCurrentServerHandle, uintptr(sessionID), wtsUserName, uintptr(unsafe.Pointer(&pBuf)), uintptr(unsafe.Pointer(&bytes)))
	if r == 0 || pBuf == nil {
		return ""
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pBuf)))
	return syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(pBuf))[:bytes/2])
}

// doUpdate swaps the staged new binary over the running one and restarts the
// service. The service that spawned us stops itself (stopAgent) once we are
// launched; we wait for it to actually stop (the exe is locked while running),
// swap, and start it again.
func doUpdate(newExe, currentExe, serviceName string) {
	if serviceName == "" {
		serviceName = "theta-agent"
	}

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if !serviceRunning(serviceName) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// The file can stay locked a moment after the SCM reports STOPPED, so retry.
	swapped := false
	for i := 0; i < 40; i++ {
		if err := os.Rename(newExe, currentExe); err == nil {
			swapped = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !swapped {
		fmt.Fprintf(os.Stderr, "update: could not replace %s (is the service still running?)\n", currentExe)
		os.Exit(1)
	}

	cmd := exec.Command("sc", "start", serviceName)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "update: sc start %s: %v: %s\n", serviceName, err, out)
		os.Exit(1)
	}
	fmt.Printf("update: swapped %s and restarted %s\n", currentExe, serviceName)
}

func serviceRunning(name string) bool {
	out, err := exec.Command("sc", "query", name).CombinedOutput()
	if err != nil {
		return false
	}
	text := strings.ToUpper(string(out))
	return strings.Contains(text, "RUNNING") || strings.Contains(text, "START_PENDING")
}
