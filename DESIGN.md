# theta-agent v2 — Simplified Architecture (LDAP-over-HTTPS)

**Status:** Draft for review · **Supersedes:** the WebRTC/SCTP spec (WebRTC dropped)

This document defines the v2 architecture for `theta-agent`. It replaces the
earlier WebRTC/SCTP design with a strictly simpler model: **one agent per node,
one outbound WSS channel, and the agent provides local LDAP + secrets + IAM.**
The core problem it solves is the original ask — *LDAP binds are painful across
hostnames, networks, and TLS cert chains* — by making the client stop speaking
LDAP and instead do an HTTPS call to the SSO, where the directory is reachable.

---

## 1. Overview

```
APP (no agent)                          SSO
  HTTPS POST /ldap/bind ──────────────► [LDAP-over-HTTPS API] ──► OpenLDAP
  HTTPS POST /ldap/search ───────────►        ▲
                                              │ raw bytes
NODE (with theta-agent)                       │
  SSSD ──► /run/theta/ldap.sock ──► agent ──► WSS (ldap_tunnel) ─┘
  secrets: /etc/theta/templates/*.tpl ──► agent ──► HTTPS ──► OpenBao
  IAM: sudoers.d / authorized_keys ──► agent ◄── WSS ◄── IAM engine
```

Two ways to reach the directory, both simple:
- **Apps (no agent):** call the HTTPS LDAP API directly — one bind/search
  contract, no LDAP protocol.
- **Nodes (with agent):** the agent is a **pure byte pump** — it forwards raw
  LDAP bytes from a local socket to the SSO, which relays them into OpenLDAP.
  The agent never parses LDAP.

---

## 2. Transport

- **Single transport: persistent outbound WebSocket (WSS) over TCP 443.** No
  WebRTC, no SCTP, no UDP, no ICE, no fallback logic. The agent dials out; the
  SSO never needs an inbound port.
- **Authentication:** the existing token / join-key enrollment model carries
  over unchanged (see `PROTOCOL.md` §1.1). The agent presents its per-agent
  token; the SSO rejects anything it did not issue.
- **Message framing:** the existing `WSMessage` JSON envelope (`type` + `payload`)
  carries all traffic. Message types are extended for LDAP, secrets, and IAM
  (below). No binary framing, no stream multiplexing. The LDAP tunnel carries
  raw bytes as base64 in `ldap_tunnel` messages (see §4).

---

## 3. LDAP-over-HTTPS API (SSO side)

A small service (or routes in the existing proxy/sso) that performs the real
LDAP operation against OpenLDAP, which is reachable from the SSO network. This
is the pinepain/ldap-auth-proxy model: the client never speaks LDAP.

| Endpoint | Request | Response |
| :--- | :--- | :--- |
| `POST /api/v1/ldap/bind` | `{username, password}` | `200 {dn, attributes}` or `401` |
| `POST /api/v1/ldap/search` | `{base_dn, scope, filter, attributes}` | `200 {entries: [...]}` |

- **bind** performs a real LDAP bind server-side and returns the bound DN and
  identity attributes.
- **search** runs a real LDAP search server-side and returns entries.
- **Authorization:** the API authorizes the *caller* (an app, or an agent acting
  for a node). OpenLDAP enforces the actual directory ACLs. This resolves the
  original spec's contradiction — we do not parse BER to enforce per-operation
  policy; the directory does.

### 3.1 Consumers

- **Apps/services:** call the API directly over HTTPS. No LDAP hostname, no
  LDAPS cert chain, no cross-network LDAP firewall rule.
- **theta-agent:** does **not** use this API. It tunnels raw LDAP bytes to the
  SSO's OpenLDAP over the WSS channel instead (see §4) — a byte pump, not a
  translation. The HTTPS API is for apps that have no agent on their network.

---

## 4. Agent local LDAP socket — a pure byte pump (for SSSD/PAM)

The agent provides a local LDAP endpoint so SSSD/PAM on the node can
authenticate without direct LDAP connectivity. **The agent does not speak LDAP
at all.** It is a dumb byte pump: whatever bytes land on the local socket are
forwarded to the SSO, which relays them into its real OpenLDAP and pipes the
response back.

```
SSSD ──► /run/theta/ldap.sock ──► agent ──► WSS (ldap_tunnel) ──► SSO ──► OpenLDAP
  ◄───────────────────────────────────────────────────────────────────────◄
```

- **Socket:** a **Unix domain socket** at `/run/theta/ldap.sock`, owned by root,
  mode `0660` (root + theta group). A unix socket is preferred over
  `127.0.0.1:389` because filesystem permissions restrict *which local processes*
  can connect — any process can reach a TCP port, only root/theta can reach the
  socket.
- **Tunnel framing:** each local connection gets a `conn_id`. Bytes are carried
  over the existing WSS channel as `ldap_tunnel` messages:
  `{type:"ldap_tunnel", payload:{conn_id, data:<base64>, close:bool}}`. The
  agent reads the socket and sends chunks up; the SSO relays them into OpenLDAP
  and sends OpenLDAP's response chunks back down; the agent writes them to the
  socket. `close:true` ends a connection.
- **SSSD config:** `ldap_uri = ldapi://%2frun%2ftheta%2fldap.sock`, StartTLS off
  (the transport to the SSO is already TLS/WSS; the local hop is plaintext on a
  root-owned socket).

### 4.1 Offline boot handling (validated)

If the agent cannot reach the SSO (WSS down), it cannot forward bytes, so it
closes local socket connections. SSSD sees a connection failure and falls back
to its local cache. **This has been validated against real SSSD behavior:** any
user/group seen in the last N days can log in offline — a laptop user can log in
on the road, and an admin can still reach a broken service host to fix it.

### 4.2 Open question — `ldapi://` support

SSSD's `ldap_uri` accepts `ldapi://` unix-socket URIs on modern versions, but
this must be confirmed on the target SSSD build. If unsupported, fall back to
`127.0.0.1:389` with a local firewall rule restricting the port to loopback.

---

## 5. Secrets engine

The agent renders OpenBao secrets to local files, reusing the existing
`@simpleworkjs/bao-conf` patterns rather than inventing a parallel mechanism.

- **Templates:** `/etc/theta/templates/*.tpl` declare the secrets a service
  needs, e.g. `DB_PASS="{{ bao "secret/data/nodes/node-42/db#password" }}"`.
- **Flow:** the agent requests the secret paths over the WSS channel → the SSO
  fetches from OpenBao (node-scoped to `/secret/data/nodes/${NODE_ID}/*`) →
  the agent renders the file **atomically** (write temp + rename) with mode
  `0600` → runs the configured post-render action (`systemctl reload <svc>`).
- **Rotation:** on a rotation/invalidation event pushed down the channel, the
  agent re-fetches, re-renders, and reloads.
- **Note:** OpenBao KV v2 secrets have no leases; "renewal" is a re-read on
  invalidation, not a lease renewal. (Dynamic secrets, if used, are a separate
  path.)

---

## 6. IAM engine

The SSO pushes node-scoped identity config down the WSS channel; the agent
applies it locally.

- **Sudo rules:** write `/etc/sudoers.d/theta-iam-<node_id>`, run `visudo -c`,
  and atomically swap on success.
- **SSH keys:** sync user public keys via `AuthorizedKeysCommand` (the agent
  implements the command the SSH daemon calls per login) — *not* a non-standard
  `/etc/ssh/authorized_keys.d/` directory.
- **Access control:** configure SSSD / `/etc/security/access.conf` for allowed
  login groups.
- **Revocation:** on account disable / group drop, flush local SSSD caches and
  drop active sessions for the affected user (mechanism TBD — `loginctl` vs
  `pkill -u`; high-risk, needs a defined trigger/event model).

### 6.1 Security — signed IAM payloads

Sudo rules and SSH keys grant root-equivalent access, so **every IAM push is
Ed25519-signed** using the existing signature model (`PROTOCOL.md` §5). The agent
verifies the signature against its pinned `public_key` before applying anything.
Unsigned or invalid IAM payloads are rejected fail-closed.

---

## 7. Security model

- **Fail-closed, capability-matrix philosophy carries over** from v1: the agent
  only applies what its local config permits; the SSO cannot override local
  settings.
- **Local socket auth:** only root/theta can reach `/run/theta/ldap.sock`.
- **Signed high-risk operations:** IAM pushes (and any new high-risk command)
  require the Ed25519 signature.
- **Node-scoped secrets:** OpenBao access is restricted to the node's own path
  prefix.
- **Blast radius:** the agent runs as root; the unix socket + signature model +
  node-scoped secrets contain the damage if the agent is compromised.

---

## 8. What this drops from the original spec

- WebRTC / SCTP / DTLS / UDP / ICE — **gone**, WSS only.
- Three SCTP streams — **replaced** by one WSS channel with message types.
- The "node-scoped authorization" contradiction — **resolved**: the API
  authorizes the caller, OpenLDAP enforces ACLs.
- LDAP parsing in the agent — **gone**. The agent is a byte pump; it never
  parses LDAP. The SSO relays raw bytes into its real OpenLDAP.

---

## 9. Open questions / verification items

1. **SSSD `ldapi://` unix-socket support** on the target build (§4.2).
2. **Revocation mechanism** — implemented as `sss_cache -E` + `pkill -u <user>`
   (§6). The event model (what triggers a push) is still to be wired into the
   SSO UI/engine.
3. **`AuthorizedKeysCommand`** — implemented: the agent installs
   `/usr/local/bin/theta-authorized-keys` which cats the user's key file
   (`/etc/theta/authorized_keys/<user>`). sshd must be configured with
   `AuthorizedKeysCommand /usr/local/bin/theta-authorized-keys %u` (§6).
4. **Versioning/migration** — is v2 a replacement for v1, or a parallel mode?
   The existing `/api/agent/ws` vs the new `/api/v1/ldap/*` paths need a story.
5. **SSO relay target** — the SSO relays tunnel bytes into its local OpenLDAP
   (slapd). The target address comes from `conf.ldap.url`; confirm it is a
   plaintext LDAP port reachable from the SSO process (§4).
6. **Secrets node scope** — the agent's node scope is its agent id
   (`secret/data/nodes/<agent-id>/*`). Confirm this matches how node secrets are
   provisioned in OpenBao (§5).
