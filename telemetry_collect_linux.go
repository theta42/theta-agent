//go:build !windows

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
)

// collectLoggedUsers enumerates who is logged in. Linux uses loginctl (systemd
// logind), falling back to gopsutil's utmp reader, then `who`. Windows has its
// own implementation in telemetry_collect_windows.go.
func collectLoggedUsers() []LoggedUser {
	var list []LoggedUser
	seen := make(map[string]bool)

	// 1. Try loginctl list-sessions --no-legend (systemd logind)
	exec := SystemExecutor{}
	if out, err := exec.Execute("loginctl", "list-sessions", "--no-legend"); err == nil && len(out) > 0 {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			// Format: SESSION UID USER SEAT TTY STATE IDLE SINCE
			// e.g. c2 1000 william seat0 tty7 active no -
			if len(fields) >= 3 {
				user := fields[2]
				term := ""
				if len(fields) >= 5 && fields[4] != "-" {
					term = fields[4]
				}
				key := fmt.Sprintf("%s@%s", user, term)
				if !seen[key] && user != "" {
					seen[key] = true
					list = append(list, LoggedUser{
						User:     user,
						Terminal: term,
						Host:     "localhost",
						Started:  time.Now().Unix(),
					})
				}
			}
		}
	}

	// 2. Fallback to gopsutil / who if loginctl returned nothing
	if len(list) == 0 {
		users, err := host.Users()
		if err == nil {
			for _, u := range users {
				key := fmt.Sprintf("%s@%s:%s", u.User, u.Terminal, u.Host)
				if !seen[key] {
					seen[key] = true
					list = append(list, LoggedUser{
						User:     u.User,
						Terminal: u.Terminal,
						Host:     u.Host,
						Started:  int64(u.Started),
					})
				}
			}
		}
		if len(list) == 0 {
			out, err := exec.Execute("who")
			if err == nil && len(out) > 0 {
				lines := strings.Split(string(out), "\n")
				for _, line := range lines {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						user := fields[0]
						term := fields[1]
						hostStr := ""
						if len(fields) >= 5 {
							hostStr = strings.Trim(fields[4], "()")
						}
						key := fmt.Sprintf("%s@%s:%s", user, term, hostStr)
						if !seen[key] {
							seen[key] = true
							list = append(list, LoggedUser{
								User:     user,
								Terminal: term,
								Host:     hostStr,
								Started:  time.Now().Unix(),
							})
						}
					}
				}
			}
		}
	}
	return list
}

// collectDiskItems reports physical block partitions with usage. The /dev
// filter (and the /dev/loop exclusion) is Linux-specific; Windows enumerates
// logical drives instead (telemetry_collect_windows.go).
func collectDiskItems() []DiskItem {
	var items []DiskItem
	partitions, err := disk.Partitions(true)
	if err != nil || len(partitions) == 0 {
		d, err2 := disk.Usage("/")
		if err2 == nil {
			items = append(items, DiskItem{
				Mountpoint:   "/",
				Device:       d.Path,
				FSType:       d.Fstype,
				DriveType:    getDriveType(d.Path),
				TotalBytes:   d.Total,
				UsedBytes:    d.Used,
				FreeBytes:    d.Free,
				UsagePercent: d.UsedPercent,
			})
		}
		return items
	}
	seen := make(map[string]bool)

	for _, p := range partitions {
		if !strings.HasPrefix(p.Device, "/dev/") || strings.HasPrefix(p.Device, "/dev/loop") {
			continue
		}
		if seen[p.Mountpoint] {
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
		items = append(items, DiskItem{
			Mountpoint:   p.Mountpoint,
			Device:       p.Device,
			FSType:       fstype,
			DriveType:    getDriveType(p.Device),
			TotalBytes:   u.Total,
			UsedBytes:    u.Used,
			FreeBytes:    u.Free,
			UsagePercent: u.UsedPercent,
		})
	}
	if len(items) == 0 {
		d, err2 := disk.Usage("/")
		if err2 == nil {
			items = append(items, DiskItem{
				Mountpoint:   "/",
				Device:       d.Path,
				FSType:       d.Fstype,
				DriveType:    getDriveType(d.Path),
				TotalBytes:   d.Total,
				UsedBytes:    d.Used,
				FreeBytes:    d.Free,
				UsagePercent: d.UsedPercent,
			})
		}
	}
	return items
}
