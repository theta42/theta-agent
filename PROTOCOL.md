# Theta Agent Protocol Specification (v1.1.0)

This document defines the communication protocol between the `theta-agent` (Client) and the `sso-manager` (Server).

## 1. Connection Establishment

The agent establishes a persistent outbound WebSocket connection.

- **Endpoint**: `wss://<manager-url>/api/agent/ws`
- **Authentication**: The agent must provide a unique host token as a query parameter:
  - `wss://<manager-url>/api/agent/ws?token=<HOST_TOKEN>`

## 2. Message Format

All messages are exchanged as JSON objects following the `WSMessage` structure.

```json
{
  "type": "string",
  "payload": {
    "key": "value"
  }
}
```

## 3. Client $\rightarrow$ Server Messages

### 3.1 Discovery (One-time & On-Change)
Sent immediately upon connection and whenever the agent detects a change in its own network IP addresses.

- **Type**: `discovery`
- **Payload**:
  - `hostname`: (string) System hostname.
  - `ip_addresses`: (array of strings) List of all non-loopback IPv4 addresses.
  - `os`: (string) OS and Platform.
  - `kernel`: (string) Kernel version.
  - `cpu`: (string) CPU model.
  - `ram_total_gb`: (float) Total system RAM in GB.
  - `disk_total_gb`: (float) Total root disk capacity in GB.
  - `location`: (string) Physical location from config.

### 3.2 Telemetry (Periodic)
Sent every 30 seconds.

- **Type**: `telemetry`
- **Payload**:
  - `cpu_usage_percent`: (float) Current CPU load.
  - `ram_usage_percent`: (float) Current RAM utilization.
  - `disk_usage_percent`: (float) Current root disk utilization.
  - `zfs_health`: (string) Primary ZFS pool status (e.g., "ONLINE").
  - `gpu_usage_percent`: (float) Average NVIDIA GPU utilization (-1.0 if unavailable).
  - `timestamp`: (string) RFC3339 timestamp.

### 3.3 Heartbeat (Periodic)
Sent every 60 seconds to maintain the connection and signal health.

- **Type**: `heartbeat`
- **Payload**:
  - `timestamp`: (string) RFC3339 timestamp.

### 3.4 Command Response
Sent in response to any command received from the server.

- **Type**: `response` (Implicitly handled as the answer to a command)
- **Payload**:
  - `status`: (string) Either `"ok"` or `"error"`.
  - `message`: (string) Human-readable result or error description.
  - `output`: (string, optional) Stdout/stderr for execution commands.

---

## 4. Server $\rightarrow$ Client Messages

### 4.1 Standard Commands
These commands are executed if the corresponding capability is enabled in `agent.yml`.

| Command | Payload | Effect |
| :--- | :--- | :--- |
| `reload_config` | `{}` | Agent re-reads `/etc/theta42/agent.yml` from disk. |
| `fetch_logs` | `{}` | Agent returns the last 100 lines of `journalctl -u theta-agent`. |

### 4.2 High-Risk Commands (Signed)
These commands **require** an Ed25519 signature in the payload. The agent verifies the signature against the `public_key` in its config.

**Signature Format**:
- The `signature` field contains the base64-encoded Ed25519 signature of the payload (with the `signature` key removed).

| Command | Payload | Effect |
| :--- | :--- | :--- |
| `reboot` | `{ "signature": "..." }` | Triggers system reboot. |
| `service_restart` | `{ "service": "...", "signature": "..." }` | Restarts specific systemd service. |
| `configure_ldap` | `{ "config": "...", "signature": "..." }` | Writes `/etc/sssd/sssd.conf` and restarts `sssd`. |
| `arbitrary_bash` | `{ "script": "...", "signature": "..." }` | Executes raw bash script. |
| `update_binary` | `{ "url": "...", "sha256": "...", "signature": "..." }` | Downloads, verifies, and replaces the agent binary. |

## 5. Cryptographic Verification Process

To send a high-risk command:
1. Create the payload (e.g., `{"script": "uptime"}`).
2. Canonicalize the JSON (sort keys alphabetically, remove whitespace).
3. Sign the canonical bytes using the private Ed25519 key.
4. Add the base64 signature to the payload: `{"script": "uptime", "signature": "..."}`.
5. Send as a `WSMessage`.

The agent performs the reverse process to verify authenticity before execution.
