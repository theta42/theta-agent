# Changelog

All notable changes to the `theta-agent` daemon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Windows LDAP logon via OpenCredential** (`configure-login`) — wires the bundled OpenCredential credential provider to the agent's LDAP byte-pump tunnel (`127.0.0.1:389`, DESIGN-WINDOWS.md §6). It seeds OpenCredential's registry config (`HKLM\SOFTWARE\OpenCredential3`): the LDAP plugin authenticates a directory user by simple-bind as `uid=<user>,ou=people,<base>` and doubles as the gateway, so members of `ldap_admin_group` are granted local `Administrators` on the host; the LocalMachine plugin stays enabled as a fallback so a local admin can never be locked out. It also enables the `ldap_tunnel` capability in `agent.yml`. Runs automatically as a post-install step (OpenCredential's own installer deletes its registry config, so seeding must happen after it) and is re-runnable. Configured via `ldap_base_dn`, `ldap_admin_group`, `ldap_local_admin_group` in `agent.yml`. Until `ldap_base_dn` is set, the tunnel still enables and local logon keeps working.

### Fixed
- **Windows discovery/telemetry reported a bogus Unix disk and no logged-in user.** `collectDiskItems` filtered on `/dev/` device prefixes — every Windows drive (`C:`) was skipped, leaving the `/ /` fallback — and `collectLoggedUsers` only knew the Linux `loginctl`/`who`/utmp paths, so the list stayed empty on Windows. Both moved to platform files (`telemetry_collect_linux.go` / `telemetry_collect_windows.go`): Windows now enumerates logical drives (`C:`, NTFS with real usage, optical drives skipped) and lists logged-in users via the WTS API (`wtsapi32`), which is always present — `query.exe` was rejected because it's an RDS tool that doesn't ship on all Windows editions. Verified live: the Directory now shows `wmant` logged in and `C:` with real disk figures.

### Changed
- **New tray icon set** (`cmd/icon-gen`, generated `cmd/theta-agent-tray/icons.go`) — the state badges (Red/Yellow/Green/Blue) are now a rounded-square badge with a subtle vertical gradient and a crisp white theta glyph, rendered at 256px with 4x4 supersampling instead of the old flat 48px circle. Windows gets a proper multi-size ICO (16/24/32/48/64/128/256) built with an exact box filter (was nearest-neighbour over three sizes), so the tray/taskbar icon is sharp at every DPI.
- **Start menu / installer icon** — `installer/windows/theta-agent.ico` (multi-size, Blue badge) is bundled by the installer and used for the Start menu "Theta Agent Tray" shortcut, the setup.exe's own icon (`SetupIconFile`), and the uninstaller's display icon.
- Removed the dead duplicate icon byte arrays in the root package's `tray_icons.go` (nothing referenced them; the tray binary carries its own copy).

## [v2.2.0] - 2026-08-10

### Added
- **Windows mDNS local-discovery** (`hosts_override_windows.go`) — completes the Linux mechanism from v2.1.2 on Windows. The hosts override now runs on Windows: `%SystemRoot%\System32\drivers\etc\hosts` (reachable because the agent runs as a SYSTEM service), CRLF-aware read/write, and `ipconfig /flushdns` after every change so the override takes effect promptly despite the Windows DNS Client cache. Verified by the Windows CI leg, which now runs the real Windows hosts path against a temp file instead of skipping.
- **Local route pinning** (`local_route.go`, `local_route_windows.go`, `local_route_unix.go`) — the hosts override only fixes *name resolution*; the packet path is decided by the routing table. If the agent's WireGuard mesh tunnel is up with `AllowedIPs` covering the LAN subnet (or a full-tunnel `0.0.0.0/0`), the tunnel route would swallow the direct connection to the discovered LAN IP. Discovery now also pins a `/32` host route for the discovered IP via the owning local interface (`route.exe add ... metric 1` on Windows, `ip route replace` on Linux) and drops it again on revert. This closes a real gap in the shipped Linux path too.
- **Prompt reconnect on discovery change** — an apply/revert now signals the WebSocket loop, which reconnects immediately (skipping its 5s backoff) so the new resolution/routing is picked up right away.

### Changed
- `hosts_override.go` split into shared rewrite logic plus platform files; `hosts_override_test.go` no longer skips on non-Linux and covers the CRLF/Windows write path.

## [v2.1.3] - 2026-08-10

### Fixed
- **v2.1.2's release build failed on the Windows CI leg.** `TestApplyHostsOverride_*` call `applyHostsOverride()`, which correctly refuses unconditionally on non-Linux — but the tests didn't skip themselves there, so `go test ./...` failed on the Windows build job. v2.1.2's actual code (the mDNS local-discovery feature itself) was never broken; only that release's CI run was. Tests now skip cleanly on non-Linux with a clear reason.

## [v2.1.2] - 2026-08-10

### Added
- **Linux mDNS local-discovery** (`local_discovery.go`, `hosts_override.go`) — when a `theta-gateway`/`theta-proxy` on the local network segment announces itself as fronting this agent's `server_url` host, the agent skips the relay/WAN path and talks to it directly. Opt-in via `prefer_local_directory` (off by default, since it changes host name resolution). Presence/absence of the mDNS announcement is the "on this LAN or not" signal — no separate network detection needed. Never touches TLS/certificate validation: this only ever changes *where* the agent connects, never *whether* it trusts what answers, so a spoofed rogue announcement produces a TLS failure, not a silent MITM.
- Companion piece to `theta-gateway`'s new mDNS announcer (`services/mdns_announce.js`, `theta-gateway` v2.1.0).

### Fixed (found via real two-container testing over live multicast, not by inspection)
- The naive `mdns.Lookup()` call requests both IPv4 and IPv6 by default; the underlying client sends the v4 query (which got a real, valid response, confirmed with a packet capture) and then the v6 query, and if the v6 send fails — no IPv6 route, common on plain v4 hosts/containers — the whole `Query()` call returns that error synchronously before the response-listening loop ever starts, silently discarding the already-received v4 response. Fixed by disabling IPv6 querying explicitly rather than depending on IPv6 being configured.
- The hosts-file writer used write-tmp-then-rename for atomicity; `/etc/hosts` is frequently a bind mount (every container runtime does this), and `rename()` onto a bind-mounted file fails with `EBUSY` — you cannot atomically replace a mountpoint. Switched to truncate-and-rewrite in place.

Windows/macOS local-discovery remain unbuilt — needs platform-native testing (hosts-file vs. stub-resolver tradeoff, elevation, DNS-cache behavior per OS) that wasn't available for this pass. See `theta-suite`'s `docs/AGENT_LOCAL_DISCOVERY_SPEC.md`.

## [v2.1.1] - 2026-08-10 (undocumented at the time; recorded retroactively)

### Fixed
- **Windows silent install** kept an empty `server_url`; the tray now actually starts after a silent install; self-update now uses GitHub releases instead of the prior mechanism.

## [v2.1.0] - 2026-08-10 (undocumented at the time; recorded retroactively)

### Added
- **Windows agent**: platform ops, Windows service wrapper, desktop helper, air-gap paths.
- **Windows WireGuard client**: auto-VPN (connect when away from home), IAM enrichment, tray integration.
- **Windows installer**: idempotent setup script, verified vendor manifest, GUI tray, Theta Directory branding, visible URL/join-key fields, service autostart.
- **CI**: builds every platform's binaries on GitHub and attaches them to releases; Windows PE files are signed (hash computed after signing, not before).

### Fixed
- Tray icon now loads correctly on Windows (PNG→ICO conversion was missing proper BMP entries).
- Tray companion supports Windows socket paths and always runs on Windows.

## [v2.0.1] - 2026-08-09

### Fixed
- **CLI version reporting**: Expose correct version string (`v2.0.0` / `AgentVersion`) dynamically via CLI command flags.
- **Secrets access for non-root users**: Configure `theta-secrets` and `theta` groups with appropriate directory permissions (`0750` / `0640` on `/etc/theta42/agent.yml`) to allow authorized non-root users to retrieve secrets.
- **Autostart Tray Icon Companion**: Install tray icon companion app and configure `/etc/xdg/autostart/theta-agent-tray.desktop` entry for desktop environments.

## [v2.0.0] - 2026-08-09

### Added
- **Full-Color Desktop System Tray Companion.** Built `theta-agent-tray` with full-color rasterized `theta42.svg` status badges (🔴 Disconnected, 🟡 Away/WAN, 🟢 Home LAN, 🔵 WireGuard Active) and Unix socket IPC.
- **Systemd Logind User Session Detection.** Updated `collectLoggedUsers()` to query `loginctl list-sessions --no-legend` so active Wayland/GDM/LightDM desktop sessions are captured.
- **Full Telemetry Field Preservation.** Preserved `logged_users` and `host_details` in periodic telemetry stream payloads.

## [v1.8.0] - 2026-08-08

### Added
- **Active Logged-in User Sessions.** Added `collectLoggedUsers()` gathering terminal sessions (`who` / `host.Users()`) reported in discovery and live telemetry payloads.
- **Full Physical Partition & Filesystem Collection.** Switched to `disk.Partitions(true)` to list all physical drives, ZFS pools, and mount points while filtering pseudo/virtual filesystems.
- **Desktop Control Operations.** Implemented `desktop_control` WebSocket actions supporting `lock_session` (`loginctl lock-sessions`), `logout_user` (`pkill -u <user>`), `display_off` (`xset dpms force off`), and `sleep_host` (`systemctl suspend`).
- **Binary Version Reporting.** Included `AgentVersion` (`v1.8.0`) in discovery and telemetry frames.

## [v1.7.0] - 2026-08-08

### Added
- **Multi-Architecture & Multi-OS Binaries.** Built cross-platform targets for Linux ARM (arm64, armv7), Windows (amd64, arm64), and macOS (Intel, Apple Silicon M1/M2/M3/M4).
- **Cross-Compilation Pipeline (`build_all.sh`).** Automated Go build toolchain generating static binaries for all 7 target platforms.
- **Installer OS & Architecture Auto-Detection.** Updated `install.sh` to auto-detect `uname -s` and `uname -m` to download matching release binaries.

### Fixed
- **Systemd & Docker Command Dispatching.** Handled systemd actions (`start`, `stop`, `restart`, `reload`) and Docker container metrics/actions cleanly across Linux distributions.

## [v1.6.0] - 2026-08-07

### Added
- **On-demand CLI Secret Fetching (`theta-agent get-secret <key>`).** Fetch raw secret values directly over TLS without writing plaintext files to disk. Supports `theta-agent get-secrets --env` (formatted for Systemd `EnvironmentFile`) and `theta-agent get-secrets --json`.
- **CLI Self-Update and Re-enrollment Commands.** Added `theta-agent update` and `theta-agent reinitialize [--join-key <key>]` CLI options with automated service restarts (`sssd`, `sshd`).
- **Zero-Trust LDAP WebSocket Tunnel (`ldap_tunnel`).** Auto-starts local `/run/theta/ldap.sock` and `127.0.0.1:3890` loopback listeners.
- **Dynamic Site Matching.** Auto-detects WAN IP for public site matching and discovery.

### Fixed
- **SSSD Socket Activation Exit Code 17.** Removed legacy `services` key in generated `sssd.conf` to satisfy modern systemd socket activation requirements.

## [Unreleased] - LDAP byte-pump tunnel (DESIGN.md §4)

The agent now serves a local LDAP socket for SSSD/PAM. It is a **pure byte
pump**: it forwards raw LDAP bytes to the SSO over the WSS channel, and the SSO
relays them into its real OpenLDAP and pipes the response back. The agent never
parses LDAP.

### Added
- **`ldap_tunnel` capability + `ldap_socket` config.** When enabled, the agent
  binds a unix socket (default `/run/theta/ldap.sock`, root:theta `0660`) and
  relays bytes bidirectionally as `ldap_tunnel` messages over the existing WSS
  channel. Point SSSD at it with `ldap_uri = ldapi://%2frun%2ftheta%2fldap.sock`.
- **`safeWriter`** — serializes WebSocket writes. Gorilla allows only one
  concurrent writer, but telemetry, heartbeat, the LDAP tunnel and command
  responses all write to the same socket; without this, concurrent writes
  corrupt the stream.
- **Offline behavior:** when the WSS is down the agent cannot forward bytes, so
  it closes local socket connections; SSSD sees a connection failure and falls
  back to its local cache.

### Added — secrets engine (DESIGN.md §5)
- **`secrets` capability + `secrets` config.** The agent renders local templates
  that embed OpenBao secrets (`{{ bao "secret/data/nodes/<id>/<name>#<key>" }}`).
  It parses the placeholders, fetches the values from the SSO (which holds the
  OpenBao access; the agent never holds a Vault token), renders each target
  atomically at `0600`, and runs the configured reload. Triggered by a signed
  `render_secrets` command.

### Added — capability reporting
- **The agent reports its enabled capabilities in its `discovery` frame.** The
  SSO stores them and the Directory UI shows them as badges on the host's Metrics
  tab, so an operator can see at a glance what an agent is allowed to do
  (telemetry, LDAP tunnel, secrets, IAM, reboot, bash, service control).

### Added — IAM engine (DESIGN.md §6)
- **`iam` capability.** The SSO pushes node-scoped identity config as a signed
  `iam_apply` command; the agent verifies the Ed25519 signature (fail-closed) and
  applies it locally:
  - **Sudo rules** — writes `/etc/sudoers.d/theta-iam-<node_id>`, validates with
    `visudo -c`, atomic swap.
  - **SSH keys** — stores per-user keys and installs the `AuthorizedKeysCommand`
    script (`/usr/local/bin/theta-authorized-keys`) that sshd calls per login.
  - **Access control** — writes `/etc/security/access.conf` with allowed login
    groups.
  - **Revocation** — flushes the SSSD cache (`sss_cache -E`) and drops active
    sessions (`pkill -u`) for revoked users.

## [v1.5.1] - 2026-08-06

### Fixed
- **Rebuilt the prebuilt `theta-agent-linux-amd64`.** theta-suite's `setup.sh` installs that committed binary rather than building from source, so a stale one means the fix in this repo never reaches the host. The v1.5.0 binary predated join-key support: an install would have written a `join_key` into `agent.yml` that the running agent did not understand, and it would have looped on `close 4001: Unauthorized`. (Same trap as the v1.3.0 heartbeat fix.)

## [v1.5.0] - 2026-08-06

Join-key enrollment (protocol v1.2.0 §1.1). Installing the agent with one key is now all it takes to add a host.

### Added
- **`join_key` config field.** Presented while `auth_token` is empty. The SSO exchanges it for this agent's own token and the public key it must pin, both delivered in the `config` frame; the agent writes them into `agent.yml` and blanks the join key. No value has to be copied between two machines by hand any more.
- `ConfigManager.PersistEnrollment` rewrites only the credential lines, line-based rather than a YAML round-trip, so operator comments, the capability matrix and formatting survive. Re-reads the file afterwards, so the new credential is live without a restart, and keeps the file at `0600`.
- `Config.Credential()` — the agent's own token when it has one, otherwise the join key.
- The connect URL carries `?hostname=`, so a self-enrolling host is named after itself instead of a generated placeholder.
- `install.sh --join-key`.

### Fixed
- The agent now refuses to connect (with a clear message and a long back-off) when it has neither an `auth_token` nor a `join_key`, rather than repeatedly presenting an empty credential.

## [v1.4.0] - 2026-08-05

Implements **Protocol v1.2.0**. See `PROTOCOL.md` §1.1, §5.1–5.3.

### Security
- **Fail-closed signature verification.** `verifySignature` returned `true` when no `public_key` was configured, logging "skipping signature verification". Combined with an installer that never wrote a `public_key`, that meant a default install would execute `reboot`, `service_restart`, `configure_ldap`, `arbitrary_bash` and `update_binary` **unverified** from anything that could reach its socket. An agent that cannot verify a high-risk command now refuses it.
- **The token must be issued by the server.** The SSO now rejects tokens it did not mint (close code `4001`). Agents carrying a token generated by the old browser-side installer will not connect until re-enrolled.

### Fixed
- **Canonicalization mismatch broke signatures for most real scripts.** Go's `encoding/json` escapes `<`, `>` and `&` by default; the server's `JSON.stringify` does not. Any payload containing them — an `arbitrary_bash` script using `>` redirection or `&&`, which is most of them — hashed differently on each side and failed verification. `canonicalize()` now uses `json.Encoder` with `SetEscapeHTML(false)` and trims the encoder's trailing newline.
- **Auth failures no longer hot-loop.** A rejected credential was retried every 5 seconds forever, flooding the SSO and its audit log. Close codes `4001`/`4003`/`4004` now back off for 5 minutes and log what to do about it.
- **The auth token no longer appears in logs.** The connect line logged the full URL, including `?token=...`. It now logs only host + path, and the token is URL-escaped.

### Added
- Close-code handling for the SSO's enrollment signals: `4001` unauthorized, `4002` superseded, `4003` revoked, `4004` token rotated.
- `install.sh --public-key <base64>`, written into the generated `agent.yml`. The installer warns loudly when no public key is configured, since such an agent can report telemetry but will refuse every high-risk command.
- Tests: fail-closed with no key, wrong key, payload tampered after signing, shell metacharacters (`>`, `&&`, `<`) round-tripping, and canonical-form equality with the server. `interop_check_test.go` verifies a signature produced by the live SSO against the agent's own verifier (skipped unless `INTEROP_FIXTURE` is set).

### Changed
- Existing tests no longer rely on verification being skipped; high-risk cases now sign with a real test key.
- `agent.yml.example`, `README.md`, `INSTALL.md`: enrollment is a prerequisite, and `public_key` is the base64 of the **raw 32-byte** Ed25519 key — not a PEM body. The previous documented example (`MCowBQYDK2VwAyEA...`) decodes to 44 bytes and would have been rejected.

## [v1.3.0] - 2026-08-04

### Fixed
- **Silently ignore `heartbeat_ack`** — the server replies to the agent's own periodic heartbeat with `heartbeat_ack`. The agent had no case for it, so it fell through to the unknown-command handler, logged `Unknown command type: heartbeat_ack` every minute, and answered with a spurious error response. Heartbeat acks are fire-and-forget; the agent now ignores them silently.

## [v1.2.0] - 2026-08-03

### Added
- **Protocol v1.1.0 Compliance**: Full alignment with `PROTOCOL.md` (v1.1.0) specification.
- **Ed25519 Cryptographic Verification**: Verification of Ed25519 Base64 signatures for high-risk C2 commands (`reboot`, `service_restart`, `configure_ldap`, `arbitrary_bash`, `update_binary`).
- **Enhanced Journal Log Fetcher (`fetch_logs`)**: Support for querying service-specific systemd logs (`service` parameter) with configurable line count (`lines` parameter).
- **Pure Go Self-Update Engine (`update_binary`)**: Replaced shell script execution with pure Go HTTP client fetching, SHA256 verification, atomic file replacement, and clean daemon restart.

### Fixed
- **Goroutine Leak Prevention**: Added `stopCh` lifecycle management to terminate background telemetry and heartbeat tickers upon WebSocket disconnection.
- **Dynamic Config Rerenders**: Resolved data races when toggling capabilities or reloading `agent.yml` via `reload_config`.
- **Config Path Uniformity**: Standardized canonical configuration file path across codebase, installer, and documentation to `/etc/theta42/agent.yml`.

## [v0.1.0] - 2026-08-01

### Added
- Initial release of `theta-agent` Go daemon replacing legacy bash metric scripts.
- Persistent outbound WebSocket telemetry and local capability matrix enforcement.
