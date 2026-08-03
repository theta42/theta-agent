# Theta Agent

Theta Agent is a unified endpoint management daemon for the theta42 stack. It replaces legacy bash installation scripts and one-way metric scripts with a powerful, 2-way Command & Control (C2) Go daemon.

The agent dials out to the central SSO Manager via a persistent WebSocket connection, enabling real-time telemetry, dynamic discovery, and secure remote operations.

## Core Functionality

### 1. Telemetry & Observability
- **Host Discovery**: Pushes a comprehensive profile (IPs, OS, Kernel, CPU, RAM/Disk) upon connection and automatically updates when network interface IPs change.
- **Continuous Monitoring**: Streams metrics every 30 seconds:
  - CPU, RAM, and Root Disk usage.
  - **ZFS Health**: Monitors pool status via `zpool list`.
  - **GPU Utilization**: Tracks NVIDIA GPU usage via `nvidia-smi`.
- **Health Checks**: Sends a periodic heartbeat to the SSO Manager to signal agent viability.

### 2. Remote Operations (C2)
The agent provides a powerful set of administrative tools, categorized by risk:

#### Standard Operations
- **Config Reload**: Triggers a reload of `/etc/theta42/agent.yml` from disk without restarting the process.
- **Log Streaming**: Fetch the last 100 lines of the agent's system logs via the C2 channel.

#### High-Risk Operations (Require Cryptographic Signatures)
To prevent unauthorized execution, these commands must be signed with a private key corresponding to the `public_key` in `agent.yml`:
- **Service Control**: Restart approved systemd services.
- **System Control**: Trigger a full system reboot.
- **Config Management**: Update `/etc/sssd/sssd.conf` and restart `sssd`.
- **Remote Execution**: Execute raw bash scripts.
- **Self-Update**: Securely download, verify (SHA256), and apply a new binary version.

## The Security Model (Blast Radius & Zero-Trust)

Because Theta Agent runs as `root`, it is a high-value target. To prevent lateral movement and contain the blast radius, it operates on a **strict, local-first capability matrix**.

### Local Configuration Wins
The agent will **only** execute commands that are explicitly enabled in its local configuration file (`/etc/theta42/agent.yml`). The central SSO Manager cannot override these settings.

### Cryptographic Hardening
All high-risk commands require an Ed25519 signature. The agent verifies the signature against the `public_key` provided in the local config. If the signature is missing or invalid, the command is rejected regardless of the capability matrix.

### Capability Matrix

| Capability | Risk Level | Description | Impact |
|------------|------------|-------------|---------|
| `telemetry` | Safe | Read-only metrics. | Pushes system health to SSO Manager. |
| `configure_ldap` | Moderate | Configures SSSD. | Updates `/etc/sssd/sssd.conf` and restarts `sssd`. |
| `reboot` | High | System reboot. | Triggers an immediate host reboot. |
| `service_control` | High | Service management. | Restarts services listed in the allowed list. |
| `arbitrary_bash` | CRITICAL | Raw bash execution. | Executes any script sent by the manager as root. |

## Configuration

Configuration is stored in YAML format at `/etc/theta42/agent.yml`.

### Example `agent.yml`
```yaml
server_url: "wss://sso.theta42.local"
auth_token: "your-unique-host-token"
public_key: "base64-encoded-ed25519-public-key"
location: "dc-01-rack-12"
capabilities:
  telemetry: true
  configure_ldap: true
  reboot: true
  service_control: ["nginx", "gitea", "sssd"]
  arbitrary_bash: false
```

## Installation

1. **Build**: Compile for your target architecture (see CI/CD artifacts).
2. **Deploy**: Place the binary in `/usr/local/bin/theta-agent`.
3. **Configure**: Create `/etc/theta42/agent.yml` with the required token and capabilities.
4. **Service**: Set up as a systemd unit (example: `/etc/systemd/system/theta-agent.service`).

For the fastest deployment, use the installation script:
```bash
curl -fsSL https://sso.example.com/resources/theta-agent/install.sh | sh -s -- "BASE64_ENCODED_CONFIG"
```

## Development & Testing

The agent uses a decoupled execution engine for safety and testability.
- Run unit tests: `go test -v ./...`
- The test suite uses a `MockExecutor` to verify that system commands are only triggered when the corresponding capability is enabled in the configuration.
