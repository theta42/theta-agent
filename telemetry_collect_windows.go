//go:build windows

package main

import (
	"os"
	"strings"
	"unsafe"

	"github.com/shirou/gopsutil/v3/disk"
	"golang.org/x/sys/windows"
)

// WTS (wtsapi32) constants/functions not exposed by x/sys. Shelling out to
// `query user` was rejected: query.exe/quser.exe are RDS tools that do not
// ship on every Windows edition (confirmed absent on a live Windows 11 host),
// and parsing its localized table is fragile. The WTS API is always present,
// locale-independent, and works from the SYSTEM service context.
var (
	procWTSQuerySessionInformationW = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSQuerySessionInformationW")
)

const (
	wtsUserName       = 5 // WTSUserName: username of the session
	wtsWinStationName = 7 // WTSWinStationName: "Console", "RDP-Tcp#3", ...
)

// collectLoggedUsers enumerates who is logged in on Windows via the Terminal
// Services API. Active, connected and disconnected sessions all count as a
// logged-in user (the latter covers a locked/away session).
func collectLoggedUsers() []LoggedUser {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	// NULL server handle (0) = the local terminal server.
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))

	var list []LoggedUser
	seen := make(map[string]bool)
	for i := uint32(0); i < count; i++ {
		s := (*windows.WTS_SESSION_INFO)(unsafe.Pointer(uintptr(unsafe.Pointer(sessions)) + uintptr(i)*unsafe.Sizeof(windows.WTS_SESSION_INFO{})))
		if s.State != windows.WTSActive && s.State != windows.WTSConnected && s.State != windows.WTSDisconnected {
			continue
		}
		user := wtsSessionString(0, s.SessionID, wtsUserName)
		if user == "" || seen[user] {
			continue
		}
		seen[user] = true
		list = append(list, LoggedUser{
			User:     user,
			Terminal: wtsSessionString(0, s.SessionID, wtsWinStationName),
			Host:     "",
		})
	}
	return list
}

// wtsSessionString queries a per-session UTF-16 string (username, station
// name) and returns it decoded. Empty on any error.
func wtsSessionString(server windows.Handle, sessionID uint32, infoClass uint32) string {
	var buf *uint16
	var bytesReturned uint32
	r1, _, _ := procWTSQuerySessionInformationW.Call(
		uintptr(server),
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r1 == 0 || buf == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16ToString(unsafe.Slice(buf, bytesReturned/2))
}

// collectDiskItems reports logical drives with usage on Windows. Windows has no
// /dev devices and no mountpoints in the Unix sense; gopsutil returns each
// logical drive as Device "C:\" / Mountpoint "C:\". We normalize the path
// separators to forward slashes so the Directory UI shows "C:/" instead of the
// old Unix-flavored "/ /" fallback.
func collectDiskItems() []DiskItem {
	var items []DiskItem
	partitions, err := disk.Partitions(true)
	if err != nil {
		return items
	}

	seen := make(map[string]bool)
	for _, p := range partitions {
		if p.Mountpoint == "" || seen[p.Mountpoint] {
			continue
		}
		seen[p.Mountpoint] = true
		u, err := disk.Usage(p.Mountpoint)
		if err != nil || u.Total == 0 {
			continue
		}
		fstype := p.Fstype
		if fstype == "" {
			fstype = u.Fstype
		}
		if isOpticalFstype(fstype) {
			continue // CD/DVD drives are noise in a host disk overview
		}
		items = append(items, DiskItem{
			Mountpoint:   normalizeWinPath(p.Mountpoint),
			Device:       normalizeWinPath(p.Device),
			FSType:       fstype,
			DriveType:    getDriveType(p.Device),
			TotalBytes:   u.Total,
			UsedBytes:    u.Used,
			FreeBytes:    u.Free,
			UsagePercent: u.UsedPercent,
		})
	}

	if len(items) == 0 {
		// Nothing came back from the volume enumeration (defensive); report the
		// system drive rather than the Unix "/".
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		if d, err2 := disk.Usage(drive); err2 == nil {
			items = append(items, DiskItem{
				Mountpoint:   normalizeWinPath(drive),
				Device:       normalizeWinPath(d.Path),
				FSType:       d.Fstype,
				DriveType:    getDriveType(drive),
				TotalBytes:   d.Total,
				UsedBytes:    d.Used,
				FreeBytes:    d.Free,
				UsagePercent: d.UsedPercent,
			})
		}
	}
	return items
}

// normalizeWinPath turns a Windows path into the forward-slash form the UI
// expects ("C:\" -> "C:/").
func normalizeWinPath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// isOpticalFstype reports whether a filesystem is optical media (CD/DVD),
// which the disk overview should skip.
func isOpticalFstype(fs string) bool {
	switch strings.ToUpper(fs) {
	case "CDFS", "UDF", "ISO9660", "ISOFS":
		return true
	}
	return false
}
