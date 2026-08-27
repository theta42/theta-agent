//go:build !server
// +build !server

// theta-agent-tray — desktop system tray companion for the theta-agent daemon.
//
// Auto-detects a graphical session (DISPLAY or WAYLAND_DISPLAY) and exits
// silently if neither is present (so it's safe to install on all hosts and
// only activates on desktops).
//
// Communicates with the running theta-agent daemon via the Unix socket at
// /run/theta/tray.sock (set up by the daemon). The daemon streams JSON status
// updates; the tray sends JSON commands back.
//
// Build:
//   go build -o dist/theta-agent-tray ./cmd/theta-agent-tray
//
// Linux: requires libappindicator or the GTK3 systray dbus protocol.
// The fyne.io/systray library handles the platform details.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"fyne.io/systray"
)

// ── IPC types (duplicated from the main agent package; tray is its own binary) ──

// traySocketPaths returns the daemon IPC socket paths for this platform, in
// the same order the daemon tries to bind them. Windows has no /run or /tmp and
// the daemon runs as a SYSTEM service, so both sides use the shared
// %ProgramData%\Theta42\tray.sock (installer creates the dir with a
// Users-writable ACL); Linux keeps the original pair.
func traySocketPaths() []string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return []string{filepath.Join(pd, "Theta42", "tray.sock")}
	}
	return []string{"/run/theta/tray.sock", "/tmp/theta-tray.sock"}
}

type TrayColor string

const (
	ColorRed    TrayColor = "red"
	ColorYellow TrayColor = "yellow"
	ColorGreen  TrayColor = "green"
	ColorBlue   TrayColor = "blue"
)

type TrayStatus struct {
	Color            TrayColor `json:"color"`
	Connected        bool      `json:"connected"`
	IsHome           bool      `json:"is_home"`
	VPNActive        bool      `json:"vpn_active"`
	AutoVPN          bool      `json:"auto_vpn"`
	SiteName         string    `json:"site_name"`
	AgentPublicIP    string    `json:"agent_public_ip"`
	HomePublicIP     string    `json:"home_public_ip"`
	OrganizationName string    `json:"organization_name"`
	StatusText       string    `json:"status_text"`
	ConfigPath       string    `json:"config_path"`

	Exits             []TrayExit `json:"exits,omitempty"`
	CurrentExitSiteID *int       `json:"current_exit_site_id,omitempty"`
}

// TrayExit is one site this device may route its internet traffic through.
type TrayExit struct {
	SiteID  int    `json:"site_id"`
	Name    string `json:"name"`
	Country string `json:"country"`
	City    string `json:"city"`
	IsLocal bool   `json:"is_local"`
}

type TrayCommand struct {
	Command string `json:"command"`
	Value   bool   `json:"value"`
	SiteID  *int   `json:"site_id,omitempty"`
}


// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	// Silent exit if no graphical session is available. Only meaningful on
	// X11/Wayland: Windows never sets these variables and the tray is simply
	// always a valid thing to run there.
	if runtime.GOOS != "windows" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		log.Println("theta-agent-tray: no graphical session detected (DISPLAY/WAYLAND_DISPLAY not set), exiting")
		os.Exit(0)
	}

	systray.Run(onReady, onExit)
}

func onExit() {
	log.Println("theta-agent-tray: exiting")
}

// ── Menu items ────────────────────────────────────────────────────────────────

var (
	mStatus     *systray.MenuItem
	mAutoVPN    *systray.MenuItem
	mVPNToggle  *systray.MenuItem
	mSeparator  *systray.MenuItem
	mOpenConfig *systray.MenuItem
	mReinit     *systray.MenuItem
	mQuit       *systray.MenuItem

	currentStatus TrayStatus
	ipcConn       net.Conn
)

func orgTitle() string {
	if currentStatus.OrganizationName != "" {
		return currentStatus.OrganizationName
	}
	return "Theta Agent"
}

func onReady() {
	// Initial icon — red until we hear from the daemon.
	systray.SetIcon(toWindowsIcon(iconRed))
	systray.SetTitle("Theta Agent")
	systray.SetTooltip("Theta Agent — connecting…")

	// ── Menu ──
	mStatus    = systray.AddMenuItem("Connecting to directory…", "Current connection status")
	mStatus.Disable()
	systray.AddSeparator()
	mAutoVPN   = systray.AddMenuItemCheckbox("Auto-connect VPN when away", "Automatically connect to home via WireGuard when not on the home LAN", false)
	mVPNToggle = systray.AddMenuItem("Connect VPN", "Manually connect or disconnect the WireGuard tunnel")
	initExitMenu()
	systray.AddSeparator()
	mOpenConfig = systray.AddMenuItem("Open Config", "Open agent.yml in the default editor")
	mReinit     = systray.AddMenuItem("Clear enrollment…", "Blank auth_token/public_key so the agent re-enrolls on reconnect")
	mQuit       = systray.AddMenuItem("Quit Tray", "Exit the tray icon (daemon keeps running)")

	// ── IPC loop — connect with retry ──
	go connectWithRetry()

	// ── Menu event loop ──
	go func() {
		for {
			select {
			case <-mAutoVPN.ClickedCh:
				newVal := !currentStatus.AutoVPN
				currentStatus.AutoVPN = newVal
				if newVal {
					mAutoVPN.Check()
				} else {
					mAutoVPN.Uncheck()
				}
				sendCmd(TrayCommand{Command: "set_auto_vpn", Value: newVal})

			case <-mVPNToggle.ClickedCh:
				if currentStatus.VPNActive {
					sendCmd(TrayCommand{Command: "vpn_disconnect"})
				} else {
					sendCmd(TrayCommand{Command: "vpn_connect"})
				}

			case <-mOpenConfig.ClickedCh:
				openConfigLocally()

			case <-mReinit.ClickedCh:
				sendCmd(TrayCommand{Command: "reinit"})

			case <-mQuit.ClickedCh:
				systray.Quit()
			}
		}
	}()
}

// openConfigLocally opens agent.yml with the desktop's default handler.
//
// This deliberately runs in the tray process rather than asking the daemon to
// do it. The daemon is a root systemd service on Linux -- no DISPLAY, no
// session bus, wrong user -- and on Windows a SYSTEM service in session 0,
// which Windows isolates from the interactive desktop. Launching a viewer from
// there could never put a window on the user's screen, which is why "Open
// Config" appeared to do nothing on both platforms. The tray, by contrast, is
// already running inside the session that owns the display.
func openConfigLocally() {
	path := currentStatus.ConfigPath
	if path == "" {
		// Older daemon that does not publish the path yet.
		path = defaultConfigPathForOS()
	}
	if _, err := os.Stat(path); err != nil {
		log.Printf("theta-agent-tray: config not found at %s: %v", path, err)
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// explorer /select,<path> opens the parent folder with the file
		// selected. explorer is a GUI app, so no console window appears.
		cmd = exec.Command("explorer", "/select,"+path)
	case "darwin":
		cmd = exec.Command("open", "-R", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("theta-agent-tray: could not open %s: %v", path, err)
		return
	}
	// Reap the child so it does not linger as a zombie; the viewer itself is
	// detached and keeps running.
	go func() { _ = cmd.Wait() }()
	log.Printf("theta-agent-tray: opened %s", path)
}

// defaultConfigPathForOS mirrors the daemon's own default, used only when the
// daemon is too old to send ConfigPath.
func defaultConfigPathForOS() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "Theta42", "agent.yml")
	}
	return "/etc/theta42/agent.yml"
}

// connectWithRetry repeatedly tries to connect to the daemon socket, waiting 5s
// between attempts. On connect it streams status updates until the connection
// drops, then retries.
func connectWithRetry() {
	socketPaths := traySocketPaths()
	for {
		var conn net.Conn
		var err error
		for _, p := range socketPaths {
			conn, err = net.Dial("unix", p)
			if err == nil {
				break
			}
		}
		if err != nil {
			log.Printf("theta-agent-tray: daemon socket not available (%v), retrying in 5s…", err)
			updateUI(TrayStatus{Color: ColorRed, StatusText: "Daemon not running"})
			time.Sleep(5 * time.Second)
			continue
		}
		ipcConn = conn
		log.Println("theta-agent-tray: connected to daemon IPC socket")
		streamStatus(conn)
		conn.Close()
		ipcConn = nil
		log.Println("theta-agent-tray: lost daemon connection, retrying in 5s…")
		time.Sleep(5 * time.Second)
	}
}

func streamStatus(conn net.Conn) {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var s TrayStatus
		if err := json.Unmarshal(scanner.Bytes(), &s); err == nil {
			updateUI(s)
		}
	}
}

func updateUI(s TrayStatus) {
	currentStatus = s

	// Exit picker. Cheap when the offered set has not changed.
	syncExitMenu(s)

	// Icon color. fyne.io/systray needs .ico on Windows; the PNG icons are
	// wrapped in an ICO container (Windows Vista+ supports PNG-in-ICO).
	icon := iconRed
	switch s.Color {
	case ColorRed:
		icon = iconRed
	case ColorYellow:
		icon = iconYellow
	case ColorGreen:
		icon = iconGreen
	case ColorBlue:
		icon = iconBlue
	}
	systray.SetIcon(toWindowsIcon(icon))

	// Tooltip.
	tooltip := s.StatusText
	if s.AgentPublicIP != "" {
		tooltip += fmt.Sprintf(" (IP: %s)", s.AgentPublicIP)
	}
	systray.SetTooltip(orgTitle() + " — " + tooltip)

	// Update title if organization name changed.
	if s.OrganizationName != "" {
		systray.SetTitle(s.OrganizationName)
	}

	// Status menu item.
	mStatus.SetTitle(s.StatusText)

	// Auto-VPN checkbox.
	if s.AutoVPN {
		mAutoVPN.Check()
	} else {
		mAutoVPN.Uncheck()
	}

	// VPN toggle label.
	if s.IsHome {
		// On home LAN — hide VPN toggle (not needed).
		mVPNToggle.Hide()
	} else {
		mVPNToggle.Show()
		if s.VPNActive {
			mVPNToggle.SetTitle("Disconnect VPN")
		} else {
			mVPNToggle.SetTitle("Connect VPN")
		}
	}
}

func sendCmd(cmd TrayCommand) {
	if ipcConn == nil {
		log.Println("theta-agent-tray: no daemon connection, cannot send command")
		return
	}
	b, _ := json.Marshal(cmd)
	b = append(b, '\n')
	_, err := ipcConn.Write(b)
	if err != nil {
		log.Printf("theta-agent-tray: send command error: %v", err)
	}
}

// toWindowsIcon converts PNG bytes into a Windows .ico for fyne.io/systray,
// which requires .ico content on Windows (LoadImage cannot read PNG-in-ICO).
// On non-Windows the PNG is returned untouched.
func toWindowsIcon(pngBytes []byte) []byte {
	if runtime.GOOS != "windows" {
		return pngBytes
	}
	return pngToIco(pngBytes)
}

// iconSizes are the sizes embedded in the Windows ICO. The 256px source PNG
// is a multiple of every entry, so each is an exact box-filter downscale.
var iconSizes = []int{16, 24, 32, 48, 64, 128, 256}

// pngToIco decodes a PNG and re-encodes it as classic BMP (XOR + AND mask)
// entries at every icon size from 16 to 256 — the format LoadImage has always
// supported. The source PNG is rendered at 256px (a multiple of every target
// size), so scaleBox is an exact box filter: no nearest-neighbour jaggies.
func pngToIco(pngBytes []byte) []byte {
	src, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return pngBytes // give systray the raw bytes; it will log and continue
	}

	sizes := iconSizes
	var dir []byte
	var payload []byte
	offset := 6 + len(sizes)*16 // ICONDIR + all ICONDIRENTRYs

	// ICONDIR: reserved(2)=0 type(2)=1 count(2)
	dir = append(dir, 0, 0, 1, 0, byte(len(sizes)), 0)

	for _, s := range sizes {
		bmp := rgbaToDIB(scaleBox(src, s))
		dw, dh := byte(s), byte(s)
		if s >= 256 {
			dw, dh = 0, 0
		}
		entry := []byte{dw, dh, 0, 0, 1, 0, 32, 0}
		entry = append(entry, putU32le(len(bmp))...)
		entry = append(entry, putU32le(offset+len(payload))...)
		dir = append(dir, entry...)
		payload = append(payload, bmp...)
	}
	return append(dir, payload...)
}

// scaleBox resizes src to w x w with an exact box (area-average) filter. Only
// correct when src's dimensions are an integer multiple of w — which 256 is
// for every icon size above — so no interpolation blur is introduced.
func scaleBox(src image.Image, w int) *image.RGBA {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	fx := sw / w
	fy := sh / w
	dst := image.NewRGBA(image.Rect(0, 0, w, w))
	for y := 0; y < w; y++ {
		for x := 0; x < w; x++ {
			var r, g, bl, a int64
			for sy := 0; sy < fy; sy++ {
				yy := b.Min.Y + y*fy + sy
				for sx := 0; sx < fx; sx++ {
					xx := b.Min.X + x*fx + sx
					cr, cg, cb, ca := src.At(xx, yy).RGBA()
					r += int64(cr >> 8)
					g += int64(cg >> 8)
					bl += int64(cb >> 8)
					a += int64(ca >> 8)
				}
			}
			n := int64(fx * fy)
			dst.SetRGBA(x, y, color.RGBA{
				R: uint8(r / n),
				G: uint8(g / n),
				B: uint8(bl / n),
				A: uint8(a / n),
			})
		}
	}
	return dst
}

// rgbaToDIB encodes an image as a 32-bit bottom-up DIB with an all-transparent
// AND mask — the classic icon bitmap LoadImage understands.
func rgbaToDIB(img image.Image) []byte {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()

	hdr := make([]byte, 40)
	copy(hdr, putU32le(40))              // biSize
	copy(hdr[4:], putU32le(w))           // biWidth
	copy(hdr[8:], putU32le(h*2))         // biHeight (XOR + AND)
	copy(hdr[12:], putU16le(1))          // biPlanes
	copy(hdr[14:], putU16le(32))         // biBitCount
	andRow := ((w + 31) / 32) * 4        // AND mask row, padded to 32 bits
	copy(hdr[20:], putU32le(w*h*4+andRow*h)) // biSizeImage

	xor := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		srcY := b.Min.Y + (h - 1 - y) // DIB rows are bottom-up
		for x := 0; x < w; x++ {
			r, g, bl, a := img.At(b.Min.X+x, srcY).RGBA()
			o := y*w*4 + x*4
			xor[o+0] = byte(bl >> 8) // B
			xor[o+1] = byte(g >> 8)  // G
			xor[o+2] = byte(r >> 8)  // R
			xor[o+3] = byte(a >> 8)  // A
		}
	}
	and := make([]byte, andRow*h) // all zeros: no transparency holes
	return append(append(hdr, xor...), and...)
}

func putU32le(v int) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func putU16le(v int) []byte {
	return []byte{byte(v), byte(v >> 8)}
}
