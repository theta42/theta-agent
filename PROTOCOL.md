# Theta Agent Protocol Specification (v1.2.0)

This document defines the communication protocol between the `theta-agent` (Client) and the `sso-manager` (Server).

## 1. Connection Establishment

The agent establishes a persistent outbound WebSocket connection.

- **Endpoint**: `wss://<manager-url>/api/agent/ws`
- **Authentication**: The agent must provide its enrollment token as a query parameter:
  - `wss://<manager-url>/api/agent/ws?token=<AGENT_TOKEN>`

### 1.1 Enrollment (changed in v1.2.0)

Two credentials can appear in `agent.yml`. The agent presents `auth_token` when
it has one, otherwise `join_key`:

| Field | Meaning |
| :--- | :--- |
| `auth_token` | This agent's own token, issued by the server. Long-term identity. |
| `join_key` | Bootstrap credential (`tjk_…`), exchanged for an `auth_token` on first connect. |

**Join-key flow.** The agent connects presenting a join key and
`?hostname=<its hostname>`. The server enrolls the host and answers with a
`config` frame carrying `enrolled: true`, `auth_token` and `public_key`. The
agent writes both into `agent.yml`, blanks `join_key`, and uses its own token
from then on. This is what makes "install the agent with a key" sufficient to
add a host — no value has to be copied between two machines by hand.

The public key is accepted on first connect (trust on first use) over the same
channel that issued the token. Pre-register the host instead if you need the
trust anchor pinned out of band.



The token **must be issued by the server**. An administrator enrolls the agent in
the SSO (Directory → Agents, or `POST /api/agent/enroll`), which mints the token,
stores only its SHA-256, and displays the raw value once. That value goes into
`auth_token` in `agent.yml`.

Up to v1.1.0 the token was generated in the browser and never recorded
server-side, so the server accepted *any* string: anyone who could reach
`/api/agent/ws` could register as a node, publish discovery/telemetry, and
receive commands addressed to a token they guessed. Tokens the server did not
issue are now rejected.

The server accepts the WebSocket upgrade before authenticating, so an
authentication failure arrives as a **close frame**, not an HTTP status:

| Code | Meaning | Agent behaviour |
| :--- | :--- | :--- |
| `4001` | Credential unknown — neither an issued token nor a valid join key | Back off (5 min); the credential will not fix itself |
| `4002` | Superseded — another connection authenticated as this agent | Normal reconnect |
| `4003` | Enrollment revoked or deleted by an administrator | Back off (5 min) |
| `4004` | Token rotated — `agent.yml` holds the superseded value | Back off (5 min); re-copy the token |

Revocation and rotation both drop any live socket immediately, so they take
effect without waiting for the agent to reconnect.

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

### 2.1 `ldap_tunnel` — the LDAP byte pump (DESIGN.md §4)

The agent serves a local LDAP socket for SSSD/PAM. It is a **pure byte pump**:
the agent forwards raw LDAP bytes to the SSO, which relays them into its real
OpenLDAP and pipes the response back. Neither side parses LDAP.

- **Type**: `ldap_tunnel` (bidirectional — sent by both agent and SSO)
- **Payload**:
  - `conn_id`: (string) correlates one local LDAP connection.
  - `data`: (string, optional) base64-encoded raw LDAP bytes.
  - `close`: (bool, optional) ends the connection.

The agent reads its local socket and sends `data` chunks up; the SSO relays them
into OpenLDAP and sends OpenLDAP's response chunks back down; the agent writes
them to the socket. `close:true` ends a connection. When the WSS is down the
agent cannot forward bytes, so it closes local socket connections and SSSD falls
back to its local cache.

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

### 3.5 Telemetry Service Metrics

The periodic `telemetry` frame (sent every 30 seconds) carries an optional
`services` array reporting the live status of every registered service in the
agent's `services:` list (see §4.3). Supported `subtype`s: `systemd`, `docker`,
`podman`, `process`, `systemd-timer`, `cron`, `lxc`, `kvm`/`libvirt`. The
directory uses it to surface each registered service as a child `service`
resource of the host and its health.

- **Payload key**: `services` (array of `{ "name": string, "active": bool,
  "subtype": string, ... }`).
  Each entry carries live resource usage and state:
  - `substate`, `load_state` (string): runtime sub/load state.
  - `cpu_usage_percent` (float): CPU rate over the last ~30s window (`-1` until a
    second sample exists).
  - `memory_bytes` (uint64): current RSS (systemd `MemoryCurrent`, docker/podman
    stats, or process `VmRSS`).
  - `n_restarts` (uint64): cumulative restart count (0 for `process`, which has
    no init-managed counter).
  - `uptime_seconds` (uint64): seconds since start.
  - `next_run`, `last_run` (string RFC3339): schedule (`systemd-timer`, `cron`).
  - `triggered_count` (uint64): number of firings observed for a `cron` entry
    since the agent started (incremented each tick the last-run advances).
  - `status` (string): VM state (`lxc`, `kvm`/`libvirt`).
- A service removed from `agent.yml` stops appearing here; the directory drops
  its child resource on the next reconciliation.

### 3.6 Service Registration (Agent → Server)

The agent declares a service it wants the directory to track as a child of its
host. Sent by `theta-agent register <type> <name>`. The server answers with a
`response` frame.

- **Type**: `register_service`
- **Payload**:
  - `service`: (string) the unit/container/process/VM/timer name.
  - `subtype`: (string, optional) `systemd`, `docker`, `podman`, `process`,
    `systemd-timer`, `cron`, `lxc`, `kvm`/`libvirt`. Defaults to `systemd`.

### 3.7 Service Unregistration (Agent → Server)

Removes a service from the directory's child resource graph.

- **Type**: `unregister_service`
- **Payload**:
  - `service`: (string) the service name to remove.

---

## 4. Server $\rightarrow$ Client Messages

### 4.0 `config`

Sent immediately on a successful connection.

- **Type**: `config`
- **Payload**:
  - `message`: (string) human-readable greeting.
  - `protocol_version`: (string) the server's protocol version.
  - `agent_id`: (string) this agent's id in the SSO.
  - `enrolled`: (bool, optional) present and `true` only when this connection
    just enrolled via a join key.
  - `auth_token`: (string, optional) the issued per-agent token — **persist it**.
  - `public_key`: (string, optional) the key to pin — **persist it**.

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
| `render_secrets` | `{ "signature": "..." }` | Renders the configured secret templates to their targets (DESIGN.md §5). |
| `iam_apply` | `{ "node_id", "revision", "access_control", "signature" }` | Applies node IAM: sudo rules, SSH keys, access control, revocation (DESIGN.md §6). |
| `register_service` | `{ "service": "...", "subtype": "...", "signature": "..." }` | Registers a systemd service as a child resource of this host (gated by `capabilities.service_registration`). |
| `unregister_service` | `{ "service": "...", "signature": "..." }` | Removes a registered service's child resource (gated by `capabilities.service_registration`). |

## 5. Cryptographic Verification Process

To send a high-risk command:
1. Create the payload (e.g., `{"script": "uptime"}`).
2. Canonicalize the JSON (see 5.1).
3. Sign the canonical bytes using the private Ed25519 key.
4. Add the base64 signature to the payload: `{"script": "uptime", "signature": "..."}`.
5. Send as a `WSMessage`.

The agent performs the reverse process to verify authenticity before execution.

### 5.1 Canonical form

Both sides must produce **byte-identical** input to sign/verify:

- keys sorted alphabetically
- no insignificant whitespace
- the `signature` key omitted
- **no HTML escaping** — `<`, `>` and `&` are emitted literally
- no trailing newline

The escaping rule is load-bearing. Go's `encoding/json` escapes those three
characters by default while JavaScript's `JSON.stringify` does not, so a payload
containing any of them hashed differently on each side and verification failed.
For `arbitrary_bash` that is most real scripts (`>` redirection, `&&`). The Go
client uses `json.Encoder` with `SetEscapeHTML(false)`.

Example — payload `{"script": "echo a > b && c", "comment": "x&y"}` canonicalizes to:

```
{"comment":"x&y","script":"echo a > b && c"}
```

### 5.2 The server signing key (changed in v1.2.0)

The server's Ed25519 key pair is **persistent**, stored in OpenBao at
`secret/agent/signing-key`. `public_key` in `agent.yml` is the base64-encoded raw
32-byte public key, available from the enrollment response or
`GET /api/agent/nodes`.

Previously the pair was generated in memory at process start, so it changed on
every restart and no agent could meaningfully pin it. If the server cannot load
or persist a key it now **refuses to send high-risk commands** rather than
signing with a key no agent has seen.

### 5.3 Agent-side verification is fail-closed (changed in v1.2.0)

An agent with no `public_key` configured **rejects** every high-risk command.
Until v1.1.0 it logged "skipping signature verification" and executed them,
which meant an agent installed without a key would run `reboot`,
`configure_ldap` and `arbitrary_bash` from anything that reached its socket.
