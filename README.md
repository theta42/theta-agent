# Theta Agent

Theta Agent is a lightweight, cross-platform host telemetry, secret delivery, and desktop control daemon for the [Theta Suite](https://github.com/theta42/theta-suite) ecosystem. Built in Go, it replaces legacy bash scripts and one-way metrics with a secure, 2-way WebSocket connection to **Theta Directory** (`theta-directory`).

The agent dials out over a single persistent outbound WebSocket connection (`wss://sso.example.com/api/agent/ws`), enabling real-time telemetry, hardware discovery, desktop session controls, and secret delivery.

## What you get

Install the agent on a node and it becomes a managed member of the directory — over a **single outbound connection**, with no inbound ports, no LDAP hostname/firewall/TLS setup, and no manual secret copying.

- **Directory logins (LDAP byte pump).** SSSD/PAM on the node authenticates through the agent's local socket, which forwards raw LDAP bytes to the SSO's OpenLDAP. OS logins work across any network — laptops, CGNAT, cloud VMs — and fall back to the local SSSD cache when offline.
- **Secrets delivered on-demand.** Services, scripts, and Docker containers fetch secrets dynamically via `theta-agent get-secret DB_PASSWORD` or `theta-agent get-secrets --env`. Zero plaintext secrets on disk! Multi-level secret inheritance (Global Site -> Host -> Service) is resolved automatically.
- **IAM managed centrally.** Sudo rules, SSH keys, and login access are pushed from the SSO to the node. Add a user to a group and their access appears on the right hosts; revoke them and their sessions are dropped.
- **Telemetry & remote operations.** Host discovery, live metrics, and signed remote commands (reboot, service control, config, self-update) — the original C2 capabilities.

Everything is gated by a strict, local-first capability matrix and high-risk operations are Ed25519-signed (see below).

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

Verification is **fail-closed**: an agent with no `public_key` configured rejects
every high-risk command. (Before protocol v1.2.0 it logged "skipping signature
verification" and executed them, so an agent installed without a key would run
`reboot`, `configure_ldap` and `arbitrary_bash` unverified.)

### Enrollment
The agent's token must be **issued by the SSO**. The server stores only its
SHA-256 and rejects anything else at the WebSocket handshake, so a token cannot
be minted client-side, and an enrollment can be revoked or rotated centrally —
either drops the agent's live connection immediately. See `PROTOCOL.md` §1.1.

### Capability Matrix

| Capability | Risk Level | Description | Impact |
|------------|------------|-------------|---------|
| `telemetry` | Safe | Read-only metrics. | Pushes system health to SSO Manager. |
| `configure_ldap` | Moderate | Configures SSSD. | Updates `/etc/sssd/sssd.conf` and restarts `sssd`. |
| `ldap_tunnel` | Moderate | Local LDAP byte-pump socket. | Forwards raw LDAP bytes to the SSO for SSSD/PAM (DESIGN.md §4). |
| `secrets` | Moderate | Renders OpenBao secrets. | Renders `/etc/theta/templates/*.tpl` to targets, atomic + reload (DESIGN.md §5). |
| `iam` | High | Applies node IAM. | Writes sudo rules, SSH keys, access control; revokes sessions (DESIGN.md §6). |
| `reboot` | High | System reboot. | Triggers an immediate host reboot. |
| `service_control` | High | Service management. | Restarts services listed in the allowed list. |
| `arbitrary_bash` | CRITICAL | Raw bash execution. | Executes any script sent by the manager as root. |

## Configuration

Configuration is stored in YAML format at `/etc/theta42/agent.yml`.

### Example `agent.yml`
```yaml
server_url: "wss://sso.theta42.local"
auth_token: "issued-by-the-sso-at-enrollment"
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
3. **Enroll**: In the SSO, open **Directory → Install Agent**, name the host, bind
   it to a host resource, and press **Enroll & issue token**. The SSO mints the
   token (shown once) and gives you its public key. Tokens the server did not
   issue are rejected.
4. **Configure**: Create `/etc/theta42/agent.yml` with the issued `auth_token`,
   the SSO's `public_key`, and your capabilities.
4. **Service**: Set up as a systemd unit (example: `/etc/systemd/system/theta-agent.service`).

For the fastest deployment, use the installation script:
```bash
curl -fsSL https://sso.example.com/resources/theta-agent/install.sh | sh -s -- "BASE64_ENCODED_CONFIG"
```

The **Install Agent** modal generates that command for you after enrollment,
with the token and public key already embedded. The equivalent flag form is:

```bash
curl -fsSL https://sso.example.com/resources/theta-agent/install.sh | sh -s -- \
  --url "https://sso.example.com" --token "<ISSUED_TOKEN>" --public-key "<BASE64_PUBLIC_KEY>"
```

## Development & Testing

The agent uses a decoupled execution engine for safety and testability.
- Run unit tests: `go test -v ./...`
- The test suite uses a `MockExecutor` to verify that system commands are only triggered when the corresponding capability is enabled in the configuration.
