## [v2.11.1] - 2026-08-24

### Fixed
- **v2.11.0 shipped without any Windows artifacts.** A test added in that release asserted the WireGuard key file's Unix mode (`0600`) unconditionally. Windows has no POSIX mode bits — Go reports `0666` for any file it created, whatever mode `WriteFile` was given — so the assertion failed on the Windows build job, which runs `go test` before compiling the installer. The release published its Linux binaries and then stopped: no `theta-agent-*-windows-amd64-setup.exe`, no Windows agent, tray or helper executables.

  The check is now POSIX-only, matching the guard `config_test.go` already used for exactly this reason. On Windows the key's confidentiality comes from the ACL the installer sets on `%ProgramData%\Theta42`, not from mode bits.

  No code changed — v2.11.0's binaries are correct, they were simply never built. Anyone who installed on Linux from v2.11.0 is unaffected; Windows installs pointing at `releases/latest` were broken until this release.

## [v2.11.0] - 2026-08-24

### Added
- **The agent has a WireGuard identity of its own.** It generates a Curve25519 keypair (RFC 7748 clamping, as `wg genkey` does) on first connect, keeps the private half at `/etc/theta42/wg_private.key` — `0600`, root only; `%ProgramData%\Theta42\wg\private.key` on Windows — and registers only the **public** half with the Directory. Stdlib `crypto/ecdh`, so no new module dependency and nothing to keep in step with the pinned Go version.
- **Mesh self-enrolment.** `POST /api/v1/agent/mesh/enroll` on every connect, idempotent by agent id, so an installed agent appears as a device in the Directory and on its site gateway with nothing copied by hand — and reconnecting converges on one device row rather than exhausting the site's address pool.
- **Internet-exit picker in the tray.** A submenu listing every exit the device may use, plus local breakout, ticked to match what the Directory actually holds. Backed by `GET /api/v1/agent/mesh/exits` and `PUT /api/v1/agent/mesh/exit`; the Directory pushes the re-rendered peer config straight back down the WSS channel, so a change takes effect without visiting the web UI. The Directory had computed this set "so the UI and the agent tray render the same set" since the feature shipped — the tray half did not exist until now.
- `theta-agent config-set` now appears in `--help` and in both shell completions. `discover` was missing from the completions too.

### Fixed
- **"Auto-connect VPN when away" did nothing — two independent causes, either fatal on its own.**
  - The whole auto-VPN path is gated on `capabilities.wireguard`, and the installer never wrote that key, so it was false by omission rather than by anyone's decision. The field is now a pointer: **absent means enabled**, so an older `agent.yml` that never mentioned it gains the capability on upgrade, while an explicit `wireguard: false` is still honoured.
  - "Away" could never happen. `computeIsHome` returned true whenever the home public IP was unknown, and `site_public_ip` — the only thing that set it — appeared exactly once in the entire suite: the line here that *reads* it. Nothing ever sent it, so every agent believed it was permanently at home.
- **Home detection rewritten around reachability** (`home_reach.go`). The primary signal is a TCP probe of the site's resolver at its **physical** LAN address, which only answers on that LAN; the public-IP comparison is kept as a fallback but is wrong under CGNAT (unrelated sites share an egress address) and at multi-WAN sites. With no signal at all the agent now assumes **away**: a false "home" silently disables auto-VPN, while a false "away" only costs a tunnel.
- **The tray icon carried a second, identical copy of the broken rule**, so it showed green "Home" forever as well. `isHome` is computed once and passed in — one implementation instead of two that can drift.
- **A pushed WireGuard config could never come up.** The Directory renders an agent-owned device's config with `PrivateKey = <generated on this device>`, on the stated assumption that the agent "completes it with the key it already holds" — but no agent held one, so the placeholder reached `wg-quick` verbatim. The agent now substitutes its own key, and only touches the key file when the placeholder is actually present, so a fully rendered admin config passes through untouched.

### Documentation
- `PROTOCOL.md` → **v1.3.0** (additive; no coordinated upgrade needed). `wireguard_apply`, `wireguard_remove`, `desktop_control` and `shutdown` were live signed commands that had **never been documented**. Added those, the private-key placeholder contract (§4.3), desktop control via logind and its Wayland caveat (§4.4), the mesh REST endpoints (§6), and the tray IPC protocol (§7), which had no documentation anywhere.
- `README.md`: the capability matrix was missing **both** `wireguard` and `service_registration`. New Desktop tray and Mesh membership sections.
- `INSTALL.md`: merge-not-overwrite on re-install, the systemd user unit for the tray, and a note to back up `wg_private.key` alongside `agent.yml`.
- `DESIGN-WINDOWS.md` §5 said "Agent side — to build". It is built; the original sketch never said where the client private key came from.

### Tests
- 30 new tests. `wg_enroll.go` — the code that talks to the Directory — had none; it now has 10 against an `httptest` server, including one asserting the enrolment request **never carries the private key**, which is the promise that lets the Directory say it does not store them.
- Tray IPC contract tests pinning the wire field names. The tray is a separate binary with its own copy of `TrayStatus`/`TrayCommand`, so a field renamed on one side and not the other fails silently — the JSON simply does not decode.

## [v2.10.0] - 2026-08-23

### Added
- **`theta-agent config-set key=value ...`** merges values into `agent.yml` in place: it replaces keys that exist, appends keys that do not, preserves comments and nested blocks, and validates the result parses before replacing the file. It refuses a key that exists only nested (e.g. `reboot` under `capabilities`) rather than lifting it flush-left, which would silently drop the capability while still producing valid YAML.

### Fixed
- **Re-installing no longer requires deleting `agent.yml` first.** `install.sh` merged new settings with `sed -i "s|^key:.*|key: value|"` per key, which only substitutes a key that is **already present**. A config that never had `join_key`/`public_key` silently dropped them — the exact "repairing a config that never had one" case the code claimed to handle. The installer now shells out to `config-set`, which appends what is missing.
- **"Open Config" did nothing on Linux and Windows.** The tray sent an `open_config` IPC command and the *daemon* ran `xdg-open`/`explorer` — but the daemon is a root systemd service with no `DISPLAY` or session bus on Linux, and a SYSTEM service in **session 0** on Windows, which is isolated from the interactive desktop. Neither can put a window on screen. The tray now opens the file itself from the new `TrayStatus.ConfigPath`, running inside the session that owns the display. The daemon's handler remains only to log a clear message for older tray binaries, and its errors are no longer discarded.
- **The Linux installer left the machine with no tray until the next login.** It wrote only `/etc/xdg/autostart/theta-agent-tray.desktop`, which fires at desktop login — and over SSH there is no session to fire it at all. Replaced with a systemd **user** unit: `systemctl --global enable` for future sessions, plus starting it in the graphical sessions that already exist. Sessions come from `loginctl` rather than a guess at `DISPLAY`, users who already have a tray are skipped, and the old autostart file is removed so the two cannot both launch.
- **Desktop Session & Power Controls did nothing on Linux.** `DesktopControl` shelled out to `DISPLAY=:0 xset` and `xdg-screensaver`, which cannot work from this daemon: as root it has neither the user's `XAUTHORITY` nor any display at all under Wayland, the default on current GNOME and KDE. It also called `loginctl terminate-session` **with no session ID** — invalid usage that always failed into a `pkill -f session-child` fallback matching nothing. Everything now goes through logind, which is display-server agnostic: lock and logout resolve real session IDs and act on each, `display_off` runs `xset` as the session's own user against that session's real display and says so when it locks instead under Wayland, and failures are reported rather than masked — so the Directory stops showing success for work that never happened.
- **A just-restarted service reported an unknown uptime.** `processUptime` returned `now - startUnix` only when `now > startUnix`, so a process younger than one second fell through to the same `return 0` used for "could not determine". Now `>=`. This also fixed `TestProbeProcess`, which raced the second boundary and failed roughly two runs in three.
- **meta: `AgentVersion` now matches the release tag.** The constant still read `v2.8.1` at tag `v2.9.1`, so every agent under-reported its version in telemetry and in the Directory's host list. Now `v2.10.0`.

### Tests
- 15 new tests where there were none: 7 for `DesktopControl` (asserting it does *not* reach for `xset`/`DISPLAY=:0` under Wayland and does not fall back to `pkill`) and 8 for the config merge (missing-key append, comment/nesting preservation, unquoted booleans, nested-key refusal).

## [v2.9.1] - 2026-08-23

### Added
- **The installer now always bundles the current WireGuard for Windows
  release.** `setup-build-env.ps1` resolves the latest amd64 MSI from
  download.wireguard.com on every build (upstream keeps only the current
  version there), verifies its Authenticode signature against WireGuard's own
  certificate (they publish no hash files), computes the sha256, and re-pins
  it into vendor-manifest.json so repeat/offline builds stay reproducible and
  tamper-checked. The MSI filename flows into installer.iss via
  `/DWireGuardMsi=`; upstream fetch failures fall back to the previously
  pinned version instead of breaking the build. First run picked up
  wireguard-amd64-1.1.msi (the pin had sat at 0.5.3 since 2024).

### Fixed
- **`install-service` could not upgrade an existing registration ("The
  parameter is incorrect").** `mgr.Service.UpdateConfig` passes
  `Config.ServiceType` to ChangeServiceConfig verbatim -- unlike CreateService
  it has no zero-value defaulting, and 0 is not SERVICE_NO_CHANGE but an
  invalid service type. Every upgrade therefore failed before it could rewrite
  ImagePath or restart the daemon, silently (the [Run] step ignores exit
  codes). The config now sets ServiceType/ErrorControl explicitly alongside
  StartType.
- **The Windows service died instantly on every start -- the daemon never ran
  at all.** `CreateService` passed `"is", "auto"` as binary arguments,
  cargo-culted from the x/sys/windows/svc/mgr doc example (where they are
  arguments to *that example's* binary). SCM baked them into ImagePath, and
  `runAgent` treats any positional argument as a config-file path, so the
  daemon started with config path `is`, failed, and exited before binding the
  tray IPC socket or dialing the Directory: red tray, "daemon socket not
  available", host absent from the fleet. Fixed three ways: no more stray
  arguments at creation; an explicit positional argument is only honored when
  it actually exists on disk; and upgrades rewrite ImagePath so previously
  broken installs are repaired on the spot. Service startup errors now also go
  to `%ProgramData%\Theta42\agent.log` (a service has no stderr), and
  `install-service` waits for RUNNING and warns loudly instead of exiting
  while the daemon is silently dying.
- **The Windows installer's "get a join key" flow never actually captured the
  key.** The loopback listener's request-line regex was written with C-style
  escapes (`^\\w+\\s+...`) inside a PowerShell string -- but PowerShell does
  not process backslash escapes, so the regex demanded a *literal* backslash
  and never matched a real request. Every callback returned an empty join key,
  the installer silently pre-filled nothing, and the installed agent sat with
  blank credentials retrying forever (red tray, host never appears in the
  Directory). The listener also now tolerates browsers' speculative/preconnect
  sockets (requests without a key get a 400 and it keeps listening) and gives
  up after 110s instead of hanging forever.
- **Upgrading the Windows agent failed to replace a running tray binary.**
  The installer never stopped the tray or the theta-agent service, so both exe
  images stayed locked during file copy. `PrepareToInstall` now kills the tray
  and stops the service (waiting for SCM to report STOPPED) before files are
  replaced, and `install-service` upgrades an existing registration in place
  (stop -> update config -> start) instead of early-returning and leaving the
  old daemon running.
- **Upgrades wiped the machine's enrollment.** `agent.yml` was rewritten on
  every install run with blank `auth_token` / `public_key`, orphaning the
  issued token (only its hash lives on the server). The installer now carries
  the existing `server_url`, `auth_token`, `public_key` and `join_key` across
  an upgrade unless new credentials are explicitly supplied.
- **mDNS discovery did not work from the Windows installer.** The wizard's
  hand-rolled raw-UDP query is gone; the "Discover local Directory" button now
  runs the bundled agent's own hardened browse (`theta-agent discover
  --urls-only`, incl. the IPv6-disabled Query workaround), and a narrow,
  program-scoped Windows Firewall allow rule (inbound UDP 5353 for the agent
  binary) is added for the browse and removed afterwards. A matching permanent
  rule is installed for the agent itself so runtime local-discovery works
  behind the default firewall posture; both rules are removed on uninstall.

## [v2.9.0] - 2026-08-22

### Added
- **White-labeling for the Windows logon tile.** New `credential_provider_name`
  in `agent.yml` (and a `/CP_NAME=` installer parameter) replaces the stock
  "OpenCredential <version>" text under the credential-provider tile on the
  Windows logon screen. The provider is located via its `InprocServer32` DLL
  path, branding is re-applied after every OpenCredential seed (the vendor
  installer resets the registration on upgrade), and failures are logged but
  never block logon. See `docs/WHITE_LABELING.md`; `credential_provider_logo`
  is reserved until the provider ships a configurable bitmap.
- **mDNS auto-discovery in the Windows installer wizard.** New "Discover local
  Directory (mDNS)..." button on the connection page browses
  `_theta-suite._tcp.local` (same announcement theta-gateway publishes for
  agent local discovery) and pre-fills the Directory URL from its TXT
  `directoryHost` — parity with what `install.sh` has done on Linux.

### Fixed
- **`theta-agent update` no longer fails on Windows.** The CLI self-update path
  used a plain rename over the running service exe, which Windows locks; it now
  stages `<self>.new` and hands the swap to the detached session helper (the
  same flow remote `update_binary` already used). Unix keeps the direct rename.
- **Installer no longer produces double-slash URLs.** A Directory URL pasted
  with a trailing slash (`https://sso.example.com/`) made the "Log in to the
  Directory" button open `https://sso.example.com//install-agent/authorize?...`,
  which some deployments reject. All URL handling in the wizard and in the
  written `agent.yml` now strips trailing slashes.

## [2.8.3] - 2026-08-22
- Added docs/KNOWN_ISSUES.md for multi-site known limits and tradeoffs.

# Changelog

All notable changes to the `theta-agent` daemon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.8.2] - 2026-08-18

### Added
- **`local_discovery` is now configurable in `agent.yml`.** Added
  `local_discovery: true` (default) to `agent.yml.example` and `Config` in
  `config.go`. Set to `false` to disable the passive mDNS listener and leave
  `/etc/hosts` untouched.

### Fixed
- **Local-discovery no longer overrides `/etc/hosts` when normal DNS already
  resolves the server to the LAN IP.** Previously the daemon wrote the managed
  hosts block unconditionally on every mDNS announcement, even when the
  discovered IP matched what DNS already returned. It now checks the current
  resolution first and only overrides when the IP actually differs, avoiding
  unnecessary edits and preserving any operator-managed entry.

## [v2.8.1] - 2026-08-13

### Fixed
- **Windows release binaries are now actually Authenticode-signed.**
  `release.yml`'s signing step had two bugs that meant it silently never ran
  on any release regardless of whether Azure credentials existed: the `if:`
  guard checked a job `env` var that was never populated from the secret,
  and the action itself (`trusted-signing-action`) has been renamed
  `azure/artifact-signing-action@v2` with an updated input schema. It also
  requires a Windows runner specifically — the job ran on `ubuntu-latest`,
  which fails deep inside the action's PowerShell with an opaque
  `Get-PackageInfo` error rather than a clear "wrong OS" message. Set up the
  Azure Artifact Signing account, certificate profile, and GitHub OIDC
  federation (a GitHub `azure-signing` environment, since Azure federated
  credentials require an exact subject match with no wildcards and can't
  match "any tag"), and end-to-end verified the full chain signs a real
  Windows PE with `Get-AuthenticodeSignature` reporting `Status: Valid`
  before wiring it into this release.

## [v2.8.0] - 2026-08-13

### Added
- **`theta-agent discover`**: browses `_theta-suite._tcp` on the local
  network and lists every distinct site announced (site slug, directory
  URL, version). Read-only — never writes `agent.yml` and is never acted on
  by the agent daemon itself; a human (or `install.sh`) decides what to do
  with the result. `--urls-only` prints just `https://<directoryHost>`, one
  per line; `--json` prints the full announcement list.
- **`install.sh` auto-discovers `--url`** when `--join-key` is given without
  it: exactly one site found on the LAN → used automatically; zero or
  multiple → the operator is told to pass `--url` explicitly rather than
  guessing. `--token` enrollment still requires `--url` explicitly.
  Deliberately scoped to a *fresh, unenrolled* agent only — mDNS is
  unauthenticated, so this only ever changes which site an admin is offered
  to enroll a brand-new host against, never which directory an
  already-enrolled agent talks to (see AGENT_LOCAL_DISCOVERY_SPEC.md for why
  that's a separate, harder problem left deliberately unbuilt).

## [v2.7.0] - 2026-08-13

### Fixed
- **mDNS local-discovery could route to a Docker bridge IP instead of the
  directory's real LAN address.** The announcer side (`theta-gateway`'s
  `mdns_announce.js`) had the same class of bug just fixed in this agent's
  own telemetry: the underlying mDNS library answers with an address record
  built from *every* local interface with no filtering, so on the announcing
  host (which also runs Docker) the response could resolve to a
  `docker0`/`br-*` bridge gateway address (e.g. `172.18.0.1`) instead of the
  real LAN IP — reproduced live: "announced locally at 172.18.0.1 ... failed
  to pin a direct host route: no local interface contains 172.18.0.1".

### Added
- **The agent now prefers an explicit `directoryAddr` TXT field over the raw
  mDNS response address.** The announcer computes `directoryAddr` from its
  own filtered (non-virtual) interfaces and includes it in the
  `_theta-suite._tcp` TXT record alongside a new `directoryHost`, `site`, and
  `version` field. When an announcement's `directoryHost` matches the
  hostname this agent connects to, its `directoryAddr` host is used instead
  of the mDNS response's own address — correct even if a future mDNS library
  version regresses the announcer-side interface filter. The site name and
  suite version are logged when discovered, laying the groundwork for a
  roaming agent (e.g. a laptop moving between sites) or a fresh install to
  identify which site's directory it's physically near.

## [v2.6.1] - 2026-08-13

### Fixed
- **A host's reported IP could be a Docker/Podman bridge address instead of
  its real LAN IP.** `ip_addresses` was built from `net.InterfaceAddrs()`,
  which flattens every interface's addresses together with no filtering —
  `docker0`, `br-*`, `veth*`, `cni*`, `podman0`, etc. all contributed, and Go
  gives no ordering guarantee that puts the real NIC first. The directory
  takes `ip_addresses[0]` as a host's address, so on a Docker/Podman host
  this could surface an unreachable `172.17/18.x.x` bridge-gateway address
  instead of the host's actual address. Interfaces matching known
  container/VM bridge prefixes are now skipped when collecting IPs.

## [v2.6.0] - 2026-08-12

### Added
- **Register and monitor services of many types.** `theta-agent register <type>
  <name>` / `theta-agent unregister <type> <name>` now supports `systemd`,
  `docker`, `podman`, `process`, `systemd-timer`, `cron`, `lxc`, and
  `kvm`/`libvirt`. The agent persists each registration in `agent.yml`
  (with its subtype), reports per-service status and resource usage in the 30s
  telemetry stream, and pushes a signed `register_service`/`unregister_service`
  frame over the agent WebSocket so the directory creates or removes the child
  service resource under the host immediately.
- **Per-service rich metrics.** The telemetry `services` array now carries CPU%,
  memory, restart count and uptime for each registered service, plus
  schedule-aware fields (`next_run`, `last_run`, `triggered_count`) for
  `systemd-timer` and `cron`, and VM `status` for `lxc`/`kvm`/`libvirt`.
- **Cron schedule parser.** A real five-field cron parser (`*`, lists, ranges,
  steps, named tokens `JAN`/`SUN`, and the day-of-month/day-of-week OR rule)
  computes next/last fire times instead of only reporting "configured".
- **`process` subtype reads `/proc` directly** — no external tool — so any
  process not under an init system can be tracked.
- **Shell tab-completion** for every service type (bash + zsh), installed by
  `install.sh` or `theta-agent install-completions`; `completions/` scripts are
  shipped as release artifacts.

### Changed
- `agent.yml` `services:` entries may be written as objects
  (`- name: nginx` / `subtype: systemd`); the plain scalar form still loads
  (treated as `systemd`) for backwards compatibility.

## [v2.5.1] - 2026-08-12

### Changed
- **Release workflow publishes per-platform and independently** — `create-release`
  shells out the tag's GitHub release first (no build dependencies), then
  `publish-linux` (agent + tray for linux) and `publish-windows` (agent, tray,
  helper, installer, Azure-signing) each attach only their own artifacts,
  gated on their own builds. A Linux build failure can no longer hold up the
  Windows installer, or vice versa. SHA256SUMS is generated best-effort
  afterwards over the signed files.

## [v2.5.0] - 2026-08-12

### Added
- **LDAP byte-pump tunnel (`ldap_tunnel` capability + `ldap_socket` config).**
  The agent serves a local LDAP socket (default `/run/theta/ldap.sock`,
  root:theta `0660`) and relays raw LDAP bytes to the SSO over the WSS channel;
  the SSO pipes them into its real OpenLDAP and returns the response. The agent
  never parses LDAP. Point SSSD at it with
  `ldap_uri = ldapi://%2frun%2ftheta%2fldap.sock`.
- **`safeWriter`** — serializes WebSocket writes (Gorilla allows only one
  concurrent writer; telemetry, heartbeat, the LDAP tunnel and command
  responses all write to the same socket, and concurrent writes corrupt the
  stream). On WSS loss the agent closes local socket connections so SSSD falls
  back to its local cache.
- **Secrets engine (`secrets` capability + `secrets` config).** Renders local
  templates embedding OpenBao secrets (`{{ bao "secret/data/nodes/<id>/<name>#<key>" }}`),
  fetching values from the SSO (the agent never holds a Vault token), rendering
  each target atomically at `0600`, and running the configured reload. Triggered
  by a signed `render_secrets` command.
- **Capability reporting.** The agent reports its enabled capabilities in its
  `discovery` frame; the SSO stores them and the Directory UI shows them as
  badges on the host's Metrics tab.
- **IAM engine (`iam` capability).** The SSO pushes node-scoped identity config
  as a signed `iam_apply` command; the agent verifies the Ed25519 signature
  (fail-closed) and applies it locally: sudo rules (`/etc/sudoers.d/theta-iam-<node_id>`,
  validated with `visudo -c`), SSH keys (`AuthorizedKeysCommand`), access
  control (`/etc/security/access.conf`), and revocation (flush SSSD cache with
  `sss_cache -E`, drop sessions with `pkill -u`).

### Fixed
- **Re-running the installer with a new join key no longer silently drops it.**
  When `/etc/theta42/agent.yml` already existed, the `--url`/`--token`/
  `--join-key`/`--public-key` arguments were discarded entirely, so a host
  whose config was missing its credential (or that was re-provisioned with a
  fresh key) stayed unauthenticated forever — the agent logged "No
  auth_token or join_key in agent.yml" and retried in 5 minutes. The
  installer now merges exactly the lines the operator supplied into the
  existing config, leaving everything else untouched.
- **Linux tray companion shipped for the first time.** `install.sh` installs
  `theta-agent-tray-linux-*` on desktops, but no release ever contained one —
  the download 404'd silently (`2>/dev/null`) and no tray icon appeared. The
  release workflow now builds `theta-agent-tray-linux-amd64` and
  `-linux-arm64` (`CGO_ENABLED=0`, its Linux backend is DBus), and the
  installer's tray arch detection no longer hardcodes amd64.

## [v2.4.0] - 2026-08-11

### Added
- **"Log in to the Directory and get a join key..." on the wizard's connection page** — the old "open the page" button is now an OAuth-style flow: the installer starts a loopback listener, opens the Directory's `/install-agent/authorize` page, and when the logged-in admin is granted a join key, the Directory redirects back and the installer pre-fills the Server URL + Join Key fields automatically. (Directory side: `/install-agent/authorize` in theta-directory.)

### Changed
- **Local discovery is now always on** — `prefer_local_directory` was removed from the config (and the wizard); the agent always watches for a local `_theta-suite._tcp` announcement and only ever acts when it fronts the agent's own `server_url` host. The "Use local discovery" wizard checkbox was removed.
- The connection page's feature description no longer mentions a discovery toggle.

## [v2.3.0] - 2026-08-10

### Added
- **Windows directory logon (OpenCredential)** — LDAP-backed sign-in is now real and *directory-driven*. The agent advertises `capabilities.configure_ldap`; the Directory pushes its own LDAP settings (it already does for Linux SSSD, derived from `conf.stack.ldapBaseDn`), and on Windows the agent parses the base DN from that push, persists it to `agent.yml`, and seeds the OpenCredential credential provider's registry config (`HKLM\SOFTWARE\OpenCredential3`): the LDAP plugin authenticates a directory user by simple-bind as `uid=<user>,ou=people,<base>` on the agent's loopback tunnel (`127.0.0.1:389`) and acts as the gateway, so members of `ldap_admin_group` (default `admins`) are granted local `Administrators`; the LocalMachine plugin stays enabled as a fallback so a local admin can never be locked out. No LDAP details are typed at install time — they come from the Directory. `configure-login` remains as a manual re-seed tool.
- **Installer wizard** now asks two plain questions on the connection page (Directory URL + join key already existed): **"Allow sign in on this computer with Directory accounts"** (`capabilities.configure_ldap`) and **"Use local discovery to find a Directory on this network"** (`prefer_local_directory`, the mDNS/layer-2 path), plus a clean options page (telemetry, WireGuard, remote reboot). Silent mode gets matching params (`/SSO_LOGON`, `/LOCAL_DISCOVERY`, `/TELEMETRY`, `/WIREGUARD`, `/REBOOT`).

### Fixed
- **Installer wrote an invalid `desktop_helper` path.** `desktop_helper: "C:\Program Files\Theta42\theta-agent-helper-windows-amd64.exe"` is not valid YAML (`\T` isn't an escape), so an installer-written `agent.yml` would fail to load and the service would crash-loop. Backslashes are now escaped.
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
