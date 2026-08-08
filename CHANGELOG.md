# Changelog

All notable changes to the `theta-agent` daemon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
