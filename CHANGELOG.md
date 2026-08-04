# Changelog

All notable changes to the `theta-agent` daemon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
