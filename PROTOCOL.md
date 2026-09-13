# Theta Agent Protocol Specification (v1.4.0)

This document defines the communication protocol between the `theta-agent` (Client) and the `sso-manager` (Server).

**v1.4.0** documents two things that were already load-bearing and written down
nowhere — the `?prev_token=` re-enrollment proof (§1.1) and the `site_name` /
`organization_name` config fields (§4.0) — and fixes the response envelope on
the agent side (§3.4) so command answers are no longer discarded. The server
accepts the old typeless form, so the two sides can be upgraded in either order.

**v1.3.0** is additive over v1.2.0 and needs no coordinated upgrade: the two new
`config` fields (§4.0) are optional, and the mesh REST endpoints (§6) and tray
IPC fields (§7) are new surfaces rather than changes to existing ones. An older
agent ignores what it does not know; an older server simply never sends it.

## 1. Connection Establishment

The agent establishes a persistent outbound WebSocket connection.


- **Endpoint**: `wss://<manager-url>/api/agent/ws`
- **Authentication**: The agent presents its enrollment token (its own
  `auth_token` once enrolled, otherwise `join_key`). Preferred: set the
  `Authorization` header to the raw token; the server also accepts `?token=<…>`
  in the query string for compatibility, but the header keeps the credential
  out of proxy/server access logs where a URL query string would be recorded.
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

**Re-enrolling a host the directory already knows (`prev_token`).** A join key on
its own cannot enroll a hostname that is already registered — otherwise anyone
holding the fleet-wide key could collide on a name and rotate the real host's
token out from under it. To re-enroll, the agent presents the token it held
before its enrollment was cleared:

| Where | Value |
| :--- | :--- |
| `X-Theta-Prev-Token` header (preferred) | the superseded `auth_token` |
| `?prev_token=<…>` query parameter | the same, for agents that cannot set headers |

The server rotates the existing enrollment onto a fresh token **only** on an
exact match, and otherwise closes `4001` — the same answer as an unknown
credential, so a caller probing hostnames learns nothing. This is contract G-2.

The agent keeps that value in `prev_auth_token` in `agent.yml`:
`reset-enrollment` and the tray's re-enroll move `auth_token` there rather than
blanking it, and a successful enrollment clears it again. It is **not** a
credential the agent will authenticate with — `Credential()` never returns it —
only the proof of continuity for this one exchange.

> Without it, `reset-enrollment` was a one-way door: the host dialled with its
> join key, collided with its own hostname, and was rejected `4001` on every
> attempt from then on. Only deleting the agent row in the directory by hand
> could recover it.



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
  - `uptime_seconds`: (uint64) Seconds since boot.
  - `wireguard`: (object, optional) `{ "active": bool, "ready": bool }` — whether
    the tunnel interface is up, and whether the userspace tools (`wg`,
    `wg-quick`) are installed at all. `ready: false` is what separates "the mesh
    is configured and down" from "this host can never bring it up".
  - `timestamp`: (string) RFC3339 timestamp.

### 3.3 Heartbeat (Periodic)
Sent every 60 seconds to maintain the connection and signal health.

- **Type**: `heartbeat`
- **Payload**:
  - `timestamp`: (string) RFC3339 timestamp.

### 3.4 Command Response

Sent in response to any command received from the server. Like every other
frame, it is a full `{type, payload}` envelope — **the `type` is not optional**.

- **Type**: `response`
- **Payload**:
  - `status`: (string) Either `"ok"` or `"error"`.
  - `message`: (string) Human-readable result or error description.
  - `output`: (string, optional) Stdout/stderr for execution commands.
  - command-specific keys where the command has them: `service`, `subtype`,
    `action` (`systemd_action`), `subAction` (`desktop_control`), `logs`
    (`fetch_logs`), `pool` (`zpool_scrub`), `error`.

Up to v2.21.9 the agent wrote a bare `{"status": …, "message": …}` with no
envelope at all. The server drops any frame without a string `type` — silently,
since an unparseable frame is not something to log per connection — so **every
command response the agent sent was discarded**: the fleet view's "last
response" was permanently null and no command's output ever reached the UI.

Servers accept the typeless form as a `response` for compatibility with agents
that predate the fix. New agents must send the envelope.

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
    second sample exists). **Always present**, as are `memory_bytes`,
    `n_restarts`, `uptime_seconds`, `cpu_ns` and `triggered_count`: zero is a
    real reading for each (an idle service, one that has never restarted), and
    omitting it made that indistinguishable from "not reported", which the
    directory renders as a blank rather than a value. `-1` is the sentinel for
    "no sample yet" precisely so that `0` can mean zero.
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
  its child resource on the next reconciliation. A child the directory learned
  about from another source as well (a docker-socket scan, a seeded catalog
  entry) is kept and merely loses `theta-agent` from its `discovery_sources`:
  this agent no longer watching something is not evidence that the thing is
  gone.
- **`services` is always present, even when empty** (since v2.22.0). An absent
  key means "this agent reports nothing about services" and the directory prunes
  nothing on it; `"services": []` means "none left" and prunes. Earlier agents
  omitted the key when the list was empty, which is why nothing could safely be
  pruned and a service deleted from `agent.yml` by hand kept a child resource
  reporting stale health indefinitely.

**The daemon re-reads `agent.yml` before each telemetry frame** (since v2.14.0).
`theta-agent register` runs in its own process: it writes the service into
`agent.yml` and asks the running daemon to push the frame over its own
WebSocket (tray IPC; a one-shot connection only when the daemon is down). The
daemon held its configuration in memory, so a just-registered service never
appeared in `services:` on the wire — the directory created the child resource
from the registration frame and then received no status sample for it,
indefinitely.

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
  - `site_lan_endpoint`: (string, optional) `host:port` that only resolves or
    routes on the home LAN — the site's resolver at its **physical** address.
    Reaching it is the agent's primary "am I home" signal.
  - `site_public_ip`: (string, optional) the home site's egress address. A
    weaker fallback: CGNAT gives unrelated sites the same one, and a multi-WAN
    site has several. Used only when no LAN endpoint is reachable.
  - `site_name`: (string, optional) the site this host belongs to, for display
    in the tray.
  - `organization_name`: (string, optional) the white-label name the directory
    is configured with. The agent shows it in the tray title/tooltip and on the
    Windows logon tile, overriding `credential_provider_name` in `agent.yml`
    (docs/WHITE_LABELING.md).

  > **The credentials half of this frame is load-bearing**, and the optional
  > half must never be able to cost an agent the whole frame. An agent that
  > enrolled with a join key and does not receive its `auth_token` persists
  > nothing, re-dials with the join key, collides with its own hostname and is
  > locked out (§1.1). A server-side error while computing the hints above did
  > exactly that for every agent in the fleet, so each optional piece is now
  > gathered independently of the rest.

  > Both hints are optional and the agent must cope without them. With
  > **neither**, it assumes it is **away** — a false "home" silently disables
  > auto-VPN, while a false "away" only brings up a tunnel.

### 4.1 Standard Commands
These commands are executed if the corresponding capability is enabled in `agent.yml`.

| Command | Payload | Effect |
| :--- | :--- | :--- |
| `reload_config` | `{}` | Agent re-reads `/etc/theta42/agent.yml` from disk. |
| `fetch_logs` | `{}` | Agent returns the last 100 lines of `journalctl -u theta-agent`. |

### 4.2 High-Risk Commands (Signed)
These commands **require** an Ed25519 signature in the payload. The agent verifies the signature against the `public_key` in its config.

> This table is the contract, and the server keeps its own copy of it
> (`HIGH_RISK_COMMANDS` in `routes/api_agent.js`) that decides what gets signed
> on the way out. The two drifting apart is silent in both directions: a command
> the agent verifies and the server does not sign is refused at the far end with
> "signature verification failed", which looks like a key problem and is not.
> Anything added here must be added there.

**Signature Format**:
- The `signature` field contains the base64-encoded Ed25519 signature of the `{type, payload}` envelope (contract G-1): the command's `type` is bound into the canonical bytes alongside the payload, and the `signature` key is omitted. Binding `type` in prevents a signature for one command type from being replayed as another (no type-portable replay).

| Command | Payload | Effect |
| :--- | :--- | :--- |
| `reboot` | `{ "signature": "..." }` | Triggers system reboot. |
| `service_restart` | `{ "service": "...", "signature": "..." }` | Restarts specific systemd service. |
| `configure_ldap` | `{ "config": "...", "signature": "..." }` | Writes `/etc/sssd/sssd.conf` and restarts `sssd`. |
| `arbitrary_bash` | `{ "script": "...", "signature": "..." }` | Executes raw bash script. |
| `update_binary` | `{ "url": "...", "sha256": "...", "signature": "..." }` | Downloads, verifies, and replaces the agent binary. |
| `render_secrets` | `{ "signature": "..." }` | Renders the configured secret templates to their targets (DESIGN.md §5). |
| `iam_apply` | `{ "node_id", "revision", "access_control", "signature" }` | Applies node IAM: sudo rules, SSH keys, access control, revocation (DESIGN.md §6). See §4.6. |
| `zpool_scrub` | `{ "pool": "...", "signature": "..." }` | Starts a scrub of a ZFS pool (gated by `capabilities.storage`). |
| `register_service` | `{ "service": "...", "subtype": "...", "signature": "..." }` | Registers a systemd service as a child resource of this host (gated by `capabilities.service_registration`). |
| `unregister_service` | `{ "service": "...", "signature": "..." }` | Removes a registered service's child resource (gated by `capabilities.service_registration`). |
| `shutdown` | `{ "signature": "..." }` | Powers the host off (gated by `capabilities.reboot`). |
| `wireguard_apply` | `{ "config": "...", "siteId": 1, "exitSiteId": null, "signature": "..." }` | Stores the peer config, and brings the tunnel up **if it should be up right now** (gated by `capabilities.wireguard`). See §4.3. |
| `wireguard_remove` | `{ "signature": "..." }` | Tears the tunnel down (gated by `capabilities.wireguard`). |
| `desktop_control` | `{ "subAction": "...", "user": "...", "signature": "..." }` | Lock, log out, blank the display, or suspend. See §4.4. |
| `systemd_action` | `{ "service": "...", "subtype": "...", "action": "...", "signature": "..." }` | Start/stop/restart/reload a registered service. See §4.5. |

### 4.5 `systemd_action` — service lifecycle (changed in v2.14.0)

Despite the name (kept for wire compatibility), this drives every kind of
service the agent can register, not just systemd units:

| `subtype` | Command run |
| :--- | :--- |
| `systemd`, absent, or unknown | `systemctl <action> <service>` |
| `docker` / `podman` | `docker\|podman <action> <service>` (`status` → `inspect`) |
| `openrc` | `rc-service <service> <action>` — note the reversed argument order |

`action` is an **allowlist**: `start`, `stop`, `restart`, `reload`, `status`.
Anything else is refused without running a command. The action is interpolated
into an argv, so this is a closed set rather than a passthrough — signature
verification makes an arbitrary value hard to reach, but "hard to reach" is not
"closed". `reload` is refused for containers, which have no equivalent; quietly
substituting a restart would be a surprising thing to do to a running service.

`status` is the one action that does **not** require a signature — it reads and
changes nothing.

Before v2.14.0 every subtype was sent to `systemctl`, so restarting a docker
container targeted a unit that did not exist.

### 4.3 `wireguard_apply` and the private-key placeholder

The Directory never holds a client private key, so a config it renders for an
agent-owned device carries the literal placeholder:

```
PrivateKey = <generated on this device>
```

The agent substitutes the private half of the keypair it generated at mesh
enrolment (§6) before handing the config to `wg-quick`. A config that already
contains a real key — one an admin generated by hand — is applied unchanged, and
the agent does not touch its key file in that case.

An agent that receives a placeholder it cannot fill answers `error` rather than
writing a config that cannot come up.

#### Storing is not the same as connecting (changed in v2.15.0)

`wireguard_apply` used to run `wg-quick up` unconditionally. That made a config
undeliverable ahead of the moment it was needed: pushing one to a host sitting
at home raised the tunnel, and the next home-monitor tick tore it straight back
down — a flap on every exit change, and the reason nothing pushed a config at
enrolment.

The config is now always persisted; whether it is *run* is a separate decision:

| `auto_vpn` | Tunnel raised on apply? |
| :--- | :--- |
| on | Only when the tunnel should be up right now — away from home, or a **remote** exit selected (see §4.3.1). |
| off | Only if it is already up, so a new exit takes effect. A tunnel the user deliberately left down is not raised. |

The response is `wireguard config stored` rather than `wireguard applied` when
the config was persisted without being raised.

Re-applying over a live tunnel cycles it (`wg-quick down` then `up`;
`/uninstalltunnelservice` then `/installtunnelservice` on Windows). `wg-quick up`
refuses an interface that already exists, so re-applying used to fail outright —
which is exactly what changing your exit does.

#### 4.3.1 `siteId` / `exitSiteId`

`siteId` is the site this device belongs to; `exitSiteId` is the site it egresses
through, or `null` for its own site's local breakout. Both are sent with the
config so the agent never has to ask, and both are what decide whether the
tunnel should be up:

| Location | Exit | Tunnel |
| :--- | :--- | :--- |
| away | any, including none | **up** — the point of auto-VPN |
| home | none, or this device's own site | down |
| home | another site | **up** — a geolocation exit is wanted at home too |

Selecting your own site as the exit means "egress where I normally would",
which a device sitting at home is already doing; it is not a reason to hold a
tunnel up. An `exitSiteId` the agent has no metadata for is treated as remote —
a deliberate selection is better honoured than ignored.

An older Directory that omits both fields leaves the agent on what it learned
at enrolment (§6).

### 4.4 `desktop_control`

`subAction` is one of `lock_session` / `lock`, `logout_user` / `logout`,
`display_off`, `sleep_host` / `sleep`. `user` is optional and only meaningful
for `logout_user`.

On Linux these are driven through **logind**, which is display-server agnostic
and so behaves the same under X11 and Wayland. Sessions are resolved with
`loginctl` rather than assumed: the daemon runs as root outside any session and
has neither a display nor the user's `XAUTHORITY`. `display_off` is the one
exception — DPMS is an X11 concept, so on a Wayland session the agent locks
instead and says so in its response rather than silently doing something else.

The response payload carries `subAction`, `output` and `error`. A failure is
reported rather than masked, so "nothing happened" is distinguishable from
"done".

### 4.6 `iam_apply` — who sent it, and what it carries

The directory builds this payload from the group model and sends it from
`POST /api/agent/nodes/:id/iam`; `GET` on the same path returns exactly what
would be sent without sending it. It is **operator-triggered, not pushed on
connect**, unlike `configure_ldap`: the agent writes
`/etc/security/access.conf`, which ends in `-:ALL:ALL`, so applying a login
policy is a change that can lock people out of a machine — not something a
reconnect should set off across a fleet.

Of the four `access_control` fields, only `allowed_login_groups` is derived:

| Field | Sent | Why |
| :--- | :--- | :--- |
| `allowed_login_groups` | yes | The group model already answers "who may reach this host" (docs/GROUPS.md), including grants inherited from an ancestor resource. `viewer`/`member` is catalog visibility, not a shell, so only `access` and above appears. |
| `sudo_rules` | **no** | The only rule derivable from "this group has admin here" is `ALL/ALL` — the landmine removed from the LDAP side (gaps.md H12). Scoped sudo is design gap D5. |
| `ssh_keys` | **no** | The agent serves an `AuthorizedKeysCommand` per login; a pushed snapshot goes stale. |
| `revoke_users` | **no** | Needs a trigger model (DESIGN.md §6 calls it TBD). A list computed at push time names people who are already gone. |

The agent writes `+:root:ALL` as the first line of `access.conf` whatever the
directory sent. The file denies everything not listed, and root at the console is
the only way back into a host whose pushed group list turns out not to cover its
administrators — a remote policy push must not be able to make a host
unrecoverable.

## 5. Cryptographic Verification Process

To send a high-risk command:
1. Create the payload (e.g., `{"script": "uptime"}`).
2. Build the signing envelope `{"type": "<commandType>", ...payload}` (contract G-1 — the type is bound into the signature).
3. Canonicalize the JSON (see 5.1).
4. Sign the canonical bytes using the private Ed25519 key.
5. Add the base64 signature to the payload: `{"script": "uptime", "signature": "..."}`.
6. Send as a `WSMessage` carrying the command `type` and the now-signed payload.

The agent performs the reverse process to verify authenticity before execution: it rebuilds the same `{type, payload}` envelope from the `WSMessage`, canonicalizes it, and verifies the Ed25519 signature against the pinned `public_key`.

### 5.1 Canonical form

Both sides must produce **byte-identical** input to sign/verify:

- keys sorted alphabetically
- no insignificant whitespace
- the `type` key included (it is part of the signed envelope)
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

## 6. Mesh identity and exits (REST, not the WSS channel)

WireGuard membership is negotiated over ordinary authenticated REST rather than
the command channel, because it is the *agent* initiating rather than the
Directory commanding. All three endpoints authenticate with the same Bearer
token the agent presents on its WebSocket, and all three act only on the calling
agent's own device — there is no device id on the wire that could name another
host.

### 6.1 `POST /api/v1/agent/mesh/enroll`

Registers this host's WireGuard public key.

- **Request**: `{ "publicKey": "<44-char base64>" }`
- **Response**: `{ "status": "ok", "client": { "id", "name", "assignedIp", "siteId", "exitSiteId" }, "rotated": <bool> }`

The agent generates a Curve25519 keypair on first use (RFC 7748 clamping, the
same `wg genkey` applies) and persists the **private** half locally:

| Platform | Path | Mode |
| :--- | :--- | :--- |
| Linux | `/etc/theta42/wg_private.key` | `0600`, root only |
| Windows | `%ProgramData%\Theta42\wg\private.key` | SYSTEM only |

Only the public half is ever sent, which is what lets the Directory honestly say
it does not store client private keys. The key is stable for the life of the
host — regenerating it would orphan the peer entry the Directory built.

Idempotent by agent id: the agent calls this on **every** connect, and the
server converges on one device row rather than accumulating one per restart and
exhausting the site's address pool. `rotated` is true when the stored key
differed and was replaced.

### 6.2 `GET /api/v1/agent/mesh/exits`

The exits this device may use, and the one it is on.

- **Response**: `{ "status": "ok", "current": <siteId|null>, "exits": [ { "siteId", "name", "country", "city", "isLocal" } ] }`

`current` is `null` for local breakout. `isLocal` marks the device's own site,
which is a valid pick but means "no exit" in practice.

### 6.3 `PUT /api/v1/agent/mesh/exit`

Routes this device through an exit.

- **Request**: `{ "siteId": <n|null> }` — `null` means local breakout.
- **Response**: `{ "status": "ok", "current": <n|null>, "pushed": <bool> }`

The Directory pushes the re-rendered peer config back down this agent's WSS
channel as a `wireguard_apply` on success; `pushed` reports whether that
actually went out. Best-effort by design: the selection is already persisted and
the gateway reconciles on its own, so an in-flight reconnect does not lose the
change.

Permission is checked as it would be for the owning user — deliberately *not*
with admin override — so a compromised agent token cannot route itself through a
site its owner may not use.

## 7. Tray IPC (`theta-agent` ↔ `theta-agent-tray`)

A local newline-delimited JSON stream over a Unix socket. The daemon binds it
and streams status; the tray connects and sends commands.

| Platform | Socket |
| :--- | :--- |
| Linux | `/run/theta/tray.sock`, falling back to `/tmp/theta-tray.sock` |
| Windows | `%ProgramData%\Theta42\tray.sock` |

Windows has no `/run`, and the daemon runs as SYSTEM while the tray runs as the
logged-in user, so the socket lives in the shared data directory the installer
creates with a Users-writable ACL.

### 7.1 Daemon → tray: `TrayStatus`

Pushed on every state change.

| Field | Meaning |
| :--- | :--- |
| `color` | `red` (no directory), `yellow` (connected, away), `green` (home), `blue` (tunnel up) |
| `connected`, `is_home`, `vpn_active`, `auto_vpn` | current state |
| `site_name`, `agent_public_ip`, `home_public_ip`, `status_text` | display |
| `config_path` | where `agent.yml` lives — see §7.3 |
| `exits` | `[{ site_id, name, country, city, is_local }]`, the exit picker's contents |
| `current_exit_site_id` | selected exit, **absent for local breakout** |

### 7.2 Tray → daemon: `TrayCommand`

| Command | Field | Effect |
| :--- | :--- | :--- |
| `set_auto_vpn` | `value` (bool) | Persists the auto-connect preference to `agent.yml`. |
| `vpn_connect` / `vpn_disconnect` | — | Brings the tunnel up or down now. |
| `set_exit` | `site_id` (`*int`) | Routes this device through a site; **`null`/absent means local breakout**. |
| `reinit` | — | Blanks enrolment so the agent re-enrols on reconnect, keeping the old token as the `prev_token` proof (§1.1). **Refused** when `agent.yml` holds an `auth_token` but no `join_key`: there would be nothing left to authenticate with, and only an operator editing the file by hand could recover the host. Same guard as `theta-agent reset-enrollment`. |
| `register_service` / `unregister_service` | `service` (string), `subtype` (string, optional) | Sent by the **CLI** (`theta-agent register/unregister`), not the tray: the daemon pushes the frame over its own WebSocket. The CLI never opens a competing connection — the directory allows one connection per agent, so a second one supersedes the daemon's (4002) and the frame is lost. |
| `open_config` | — | **Deprecated.** See §7.3. |

`site_id` is a pointer precisely because `0` is a plausible site-id shape and
"no exit" had to remain distinguishable from "site zero" on the wire.

### 7.3 Why the tray opens `agent.yml` itself

`open_config` used to ask the daemon to run `xdg-open`/`explorer`. That could
never work: on Linux the daemon is a root systemd service with no `DISPLAY` and
no session bus, and on Windows a SYSTEM service in **session 0**, which is
isolated from the interactive desktop. Neither can put a window on a user's
screen.

The tray now opens the file itself using `config_path` from the status stream,
because it is already running inside the session that owns the display. The
daemon still accepts `open_config` from older tray binaries, but only logs where
the config is — it does not pretend to have opened anything.
