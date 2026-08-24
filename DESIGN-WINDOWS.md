# theta-agent on Windows — design

Status: **shipped** (most sections implemented; remaining gaps tracked in §2 and
docs/KNOWN_ISSUES.md). Companion to `DESIGN.md`, which describes the
Linux-first agent. This document covers bringing the agent to Windows as a first-class
platform, optimized for **air-gapped** deployment: everything the host needs ships in
one installer, and nothing on the target machine requires internet access.

## 1. Goals

1. **Parity, not a port.** Every capability Linux has, Windows has too: telemetry,
   remote operations (reboot/shutdown, service control, desktop control, arbitrary
   commands, logs, IAM, self-update), LDAP-backed directory logins, secrets, and a
   WireGuard mesh client. The capability matrix and Ed25519 signature model from
   `DESIGN.md` apply unchanged; only the executors change.
2. **One installer, fully offline.** A single Inno Setup `.exe` installs everything the
   Windows host needs — agent service, tray, credential provider, WireGuard client,
   runtime dependencies. No downloads at install time and no internet calls at runtime.
3. **Single outbound connection preserved.** The agent still dials one persistent WSS
   connection to the SSO. No inbound ports, no firewall rules.
4. **The SSO holds all resources.** The Windows installer, loose binaries, and the
   self-update feed are served from the SSO, mirroring the existing
   `/resources/theta-agent/...` tree.

## 2. Current Windows compatibility status

The agent already compiles, runs, and enrolls on Windows. Validated against a live SSO
(`sso.suite.vm42.us`):

- `go build` for `windows/amd64` succeeds; the agent enrolls via join key, persists its
  issued token + the SSO's Ed25519 public key to `agent.yml`, and streams discovery /
  telemetry over WSS.
- Unix-domain sockets work on Windows (Go ≥ 1.18, needs Win10 1803+); the LDAP byte-pump
  and tray IPC both bind and accept connections under the per-user temp dir.
- Two unit tests assert POSIX `0600` modes that Windows does not implement; they are the
  only failures and are not runtime defects (`go test` gate must be made Windows-aware).

### Changes already merged

- **Tray IPC socket paths are platform-aware.** Linux keeps `/run/theta/tray.sock` +
  `/tmp/theta-tray.sock`; Windows uses a Unix socket under the per-user temp dir
  (`tray_ipc.go`). The tray companion dials the same path.
- **The tray no longer exits on Windows.** The `DISPLAY`/`WAYLAND_DISPLAY` graphical
  session guard is now non-Windows only (`cmd/theta-agent-tray/main.go`).

## 3. Process & services layout

| Component | Runs as | Purpose |
| :--- | :--- | :--- |
| `theta-agent` | Windows service (SYSTEM, auto-start) | WSS to SSO, command dispatch, telemetry, LDAP byte-pump, loopback `/bind`, IAM, WG control |
| `theta-agent-tray` | Per-user, logon autostart (Windows); systemd **user** unit (Linux) | Status icon, enrollment dialog, VPN control, auto-VPN, internet-exit picker, opening `agent.yml` |
| `theta-agent-helper` (new) | Per-interactive-session, spawned by the service | Desktop controls that cannot run from session 0 |
| OpenCredential CP DLL | Loaded by `LogonUI.exe` (Winlogon) | LDAP-backed Windows logon |
| `WireGuardTunnel$<name>` | Service installed by WireGuard client | Mesh tunnel |

The service is the lynchpin: it is up before any user session, which is what lets the
credential provider validate logins at Ctrl+Alt+Del.

## 4. Remote operations (full parity)

Command dispatch, capability gating, and Ed25519 verification in `websocket.go` are
platform-neutral. A `executor_windows.go` (plus a small `executor_linux.go` containing
today's Linux mapping) selects the underlying implementation.

| Command | Linux (today) | Windows |
| :--- | :--- | :--- |
| `reboot` | `reboot` | `shutdown.exe /r /t 0` |
| `shutdown` | `shutdown -h now` / `poweroff` | `shutdown.exe /s /t 0` |
| `service_restart` | `systemctl restart <svc>` | `sc.exe stop/start <svc>` (allowed-list unchanged) |
| `systemd_action` | `systemctl <action> <svc>` | `sc.exe <action> <svc>`; `status` → `sc.exe query` |
| `arbitrary_bash` | `bash -c <script>` | `powershell -NoProfile -Command <script>` |
| `fetch_logs` | `journalctl -u <svc>` | `Get-WinEvent -LogName <svc logs>` (application/system log for the service) |
| `configure_ldap` | write `/etc/sssd/sssd.conf`, restart sssd | N/A on Windows — see §6 |
| `render_secrets` | render templates atomically | identical (Go is cross-platform) |
| `iam_apply` | sudoers.d, `authorized_keys`, access.conf | local groups + Windows OpenSSH `authorized_keys` (see below) |
| `update_binary` | download → verify SHA256 → rename | download → verify → **staged rename** (running exe is locked; write `.new`, stop service, replace, start) |
| `reboot`-gated desktop ops | `loginctl`/`xset` | see desktop control below |

### Desktop control (session 0 problem)

A SYSTEM service runs in session 0, which has no interactive desktop. Ops that need an
interactive session must run in the user's session:

- `lock_session` → `LockWorkStation` — must run in the interactive session → **helper**.
- `display_off` → `SC_MONITORPOWER` broadcast — needs a window station → **helper**.
- `logout_user` → `logoff.exe <session-id>` via `WTSEnumerateSessions` — service can do it.
- `sleep_host` → `SetSuspendState` (needs `SeShutdownPrivilege`) — service can do it.

The service launches the helper in the interactive session (`CreateProcessAsUser` /
WTS), passing the action as an argument; the helper performs the op and exits. The helper
is installed by the installer and is a tiny self-contained exe.

### IAM on Windows

`iam_apply` semantics map to local-account security:

- `allowed_login_groups` → local groups (create/ensure membership on the mapped local
  accounts), consumed by OpenCredential authorization rules.
- `ssh_keys` → per-user `%ProgramData%\ssh\administrators_authorized_keys` or per-profile
  `.ssh\authorized_keys` depending on OpenSSH server configuration.
- `revoke_users` → terminate sessions (`logoff <id>` / `rwinsta`) and disable the mapped
  local account.
- `sudo_rules` → no direct equivalent; mapped to local group membership / UAC elevation
  policy, or ignored with a logged warning.

## 5. WireGuard mesh client

### Server side (jump-host) — already complete

jump-host mints peers and exit sites, renders standard `wg0.conf`
(`nodejs/utils/wg_conf.js`), and serves `/api/wireguard/peers/:id/conf` + QR. The
generated config is compatible with the WireGuard Windows client.

### Agent side — built

Implemented as described below, plus two things the original sketch left out:

- **The agent holds its own key.** It generates a Curve25519 keypair on first
  connect and registers only the public half (PROTOCOL.md §6). The Directory
  renders configs with a `PrivateKey = <generated on this device>` placeholder,
  which the agent substitutes locally — the server never holds a client private
  key. The original plan had the server "include the peer conf" with no account
  of where the private half came from.
- **Exit selection from the tray**, not only from the web UI (PROTOCOL.md §7).

1. **Delivery:** new signed command `wireguard_apply` pushed over the existing WSS
   channel (same model as `iam_apply`): server includes the peer conf; agent verifies the
   Ed25519 signature, persists it, and applies it. `wireguard_remove` tears it down. No
   new outbound ports or HTTP endpoints.
2. **Apply/teardown (Windows):** official WireGuard client, bundled:
   - install: `wireguard.exe /installtunnelservice "<name>" <conf>`
   - remove: `wireguard.exe /uninstalltunnelservice "<name>"`
   - (Linux would use `wg-quick up|down`.)
3. **State detection:** poll `sc.exe query "WireGuardTunnel$<name>"` (or adapter
   existence) → set `vpn_active` → tray turns blue; drives the existing auto-VPN logic in
   `home_detect.go`.
4. **Auto-VPN:** when away-from-home and `auto_vpn` is set, bring the tunnel up; the tray
   checkbox persists the preference to `agent.yml`.

   Away-from-home is decided by reachability first — a TCP probe of the site's
   resolver at its *physical* LAN address, which only answers on that LAN — and
   falls back to comparing public IPs. With no signal at all the agent assumes
   **away**: a false "home" silently disables auto-VPN, while a false "away"
   only costs a tunnel. See `home_reach.go`.

## 6. LDAP: directory logins and the byte-pump

### The byte-pump tunnel (already Windows-portable)

The LDAP tunnel is a pure byte pump (`ldap_tunnel.go`) and is transport-agnostic. On
Windows it binds `127.0.0.1:389` (fallback `3890`) — the same TCP loopback path Linux
falls back to. Gated by the existing `ldap_tunnel` / `configure_ldap` capability flags.

### Windows logon via OpenCredential (vendored pGina fork)

Windows has no native OpenLDAP logon (AD only). The plan is the **credential-provider
pattern**, using **OpenCredential**, a maintained BSD-3 fork of pGina
(`github.com/pedropablobm/OpenCredential`), vendored as a submodule and built from source
in CI:

```
LogonUI (Secure Desktop)
   │  OpenCredential LDAP auth plugin
   ▼
127.0.0.1:389  ──►  theta-agent byte-pump  ──►  WSS (ldap_tunnel)  ──►  SSO  ──►  OpenLDAP bind
```

- **Zero custom CP code.** OpenCredential's LDAP auth plugin points at `127.0.0.1:389`
  (simple bind, TLS off). The installer pre-seeds its plugin config (server, username and
  group attributes matching the OpenLDAP schema) so logon works unattended.
- **Local-account bridge.** OpenLDAP cannot mint a Windows token; OpenCredential performs
  the standard bridge — validate against LDAP, then log into a mapped local account
  (auto-provisioned on first logon), applying LDAP group membership to local groups.
- **Offline cache.** OpenCredential ships a SQLite offline auth cache, which addresses
  first-boot / SSO-unreachable logon.
- **Security note.** The password crosses loopback as a plaintext LDAP simple bind, then
  rides the already-TLS WSS tunnel; the agent never parses or stores it. Loopback-only
  listener, no inbound exposure.
- **White-labeling (shipped).** The text under the logon tile is the default value of
  the provider's registration key under `HKLM\...\Authentication\Credential Providers\<CLSID>`;
  the agent rewrites it from `credential_provider_name` in `agent.yml` (or the installer's
  `/CP_NAME=` parameter) after every seed. The tile bitmap is a DLL resource and needs a
  provider rebuild — see `docs/WHITE_LABELING.md`.

### Alternative (documented, not chosen)

A thin managed .NET OpenCredential plugin that `POST /bind`s to an agent loopback HTTP
endpoint (mirroring DESIGN.md §3's `POST /api/v1/ldap/bind`), giving the agent control of
the transport and caching. Kept as a fallback if the LDAP plugin's TLS expectations prove
inflexible.

## 7. Tray companion (enriched)

`cmd/theta-agent-tray` gains:

- **Enrollment dialog** — server URL + join key entry; writes `agent.yml` (or a
  user-scoped config) and signals the service to reload.
- **Status panel** — connection state, home/away, VPN, public IP.
- **VPN control** — connect/disconnect, auto-VPN checkbox now persisted.
- Rendered with the existing systray stack (`fyne.io/systray` supports Windows natively).

## 8. Installer (Inno Setup, fully offline)

One `.exe`, built on a connected machine, runnable on an air-gapped one. Bundles:

- `theta-agent-windows-amd64.exe` (+ arm64) and `theta-agent-tray-windows-amd64.exe`
- `theta-agent-helper.exe` (desktop-control helper)
- OpenCredential CP installer + **VC++ v14 redistributable** (its native runtime; .NET
  Framework 4.8 is built into Windows 10/11 so needs no bundle)
- The official, vendor-signed WireGuard for Windows client (signed drivers install
  offline without signature phone-home)
- OpenCredential's pre-seeded LDAP plugin config
- Agent `agent.yml` template + self-signed CP cert installed into the machine trusted root

The build environment is bootstrapped idempotently by
`scripts/setup-build-env.ps1` (pinned Go version, per-user Inno Setup install, and
vendor assets fetched into `installer/windows/vendor/` — verified against the pinned
sha256 in `installer/windows/vendor-manifest.json`). The CI workflow calls the same
script, so a local build and CI/CD cannot drift.

Install-time behavior:

- `/SILENT` supported; `SERVER_URL=` and `JOIN_KEY=` as install parameters (the SSO's
  "Install Agent" modal emits the Windows command instead of the bash one).
- Creates the `theta-agent` service (SYSTEM, auto-start), registers the tray for logon
  autostart, registers the CP with Winlogon, installs the WireGuard service components.
- Writes `agent.yml`; a blank join key leaves enrollment to the first service start.

## 9. Build & release (GitHub Actions + Azure Trusted Signing)

- **No binaries live in the repos.** Every artifact is built on GitHub Actions and
  attached to the release (`releases/latest/download/<artifact>`) — see
  `.github/workflows/release.yml`. Consumers download from there:
  - `install.sh` (Linux) already fetches the agent/tray from `releases/latest/download/`.
  - The SSO's Install Agent modal emits a PowerShell one-liner that downloads the
    Windows `setup.exe` from `releases/latest/download/`.
- **Production builds** run in GitHub Actions:
  - Matrix: agent for `linux`(amd64/arm64/armv7), `windows`(amd64/arm64), `darwin`(amd64/arm64);
    tray for linux/windows; helper for windows.
  - The fully-offline Inno installer compiles on a `windows-latest` runner via
    `scripts/setup-build-env.ps1 -SkipGo -Build -CI` (which also runs `go test ./...`).
  - **Azure Trusted Signing** optionally signs everything (workflow federated identity →
    AzureSignTool, gated on secrets). Authenticode chains verify offline, which suits
    air-gap; SmartScreen reputation simply won't accumulate, which is expected.
  - Release tags (e.g. `v2.1.0`) name the artifacts; a `SHA256SUMS` manifest is attached.
- **Self-update** uses the existing signed `update_binary` flow; the agent's fetch is
  platform-aware. On an air-gapped LAN the SSO can mirror the release artifacts into
  `/resources/theta-agent/` at deploy time; nothing on the target host hits the internet.

## 10. Air-gap considerations

- **No internet calls at runtime.** The only external-internet dependency in the agent
  today is public-IP detection (`telemetry.go`, `home_detect.go` hit ipify/icanhazip
  etc.); on an air-gapped host these fail and degrade silently (accepted behavior).
  "Home/away" tray logic is meaningless without a public IP and must not flap.
- **Self-update is LAN-only** (SSO serves the binary), so it works inside the air-gap.
- **All runtime deps bundled:** VC++ redist, WireGuard client + driver, CP + cert,
  .NET 4.8 is OS-built-in.
- **No SmartScreen/driver phone-home** for bundled vendor-signed components.

## 11. Configuration additions (`agent.yml`)

```yaml
# Windows-specific
service_name: theta-agent            # windows service name
desktop_helper: "C:\\Program Files\\Theta42\\theta-agent-helper.exe"
public_ip_detect: true               # false disables external lookups (air-gap)
wireguard:
  tunnel_name: theta-mesh
  conf: "C:\\Program Files\\Theta42\\wg\\theta-mesh.conf"
# OpenCredential plugin config is managed by the installer, not agent.yml
```

## 12. Open questions

1. Desktop-control helper: one exe for all ops vs. per-op; interaction with multiple
   interactive sessions.
2. IAM `sudo_rules` on Windows: local-group mapping vs. explicit no-op.
3. Self-update of the *service* binary on Windows: staged rename requires the service
   to stop; whether the service restarts itself or defers to the tray.
4. OpenCredential: whether the LDAP plugin's schema expectations (username/group
   attributes) match the suite's OpenLDAP without a small config-only shim.
5. Air-gap first-boot logon: rely on OpenCredential's offline cache vs. pre-seeding
   local accounts at install time.

## 13. Build order

1. `executor_windows.go` (remote ops) + service wrapper — unlocks everything.
2. Tray enrichment + enrollment dialog + auto-VPN persistence.
3. WireGuard client (`wireguard_apply`/`remove` + state).
4. LDAP byte-pump on Windows (already portable; gate + verify).
5. Inno installer bundling the above; CI + Azure signing; SSO resource tree.
6. OpenCredential submodule + plugin config + logon validation.
