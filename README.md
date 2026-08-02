# Theta Agent

Theta Agent is a unified endpoint management daemon for the theta42 stack. It replaces legacy bash installation scripts (like `ldap-client`) and one-way metric scripts (`telemetry-agent`) with a powerful, 2-way Command & Control (C2) Go daemon.

The agent dials out to the central SSO Manager via a persistent WebSocket connection, enabling:
- **Continuous Telemetry:** Streams CPU/RAM/ZFS/GPU health to the central inventory.
- **Dynamic Discovery:** Automatically updates host IP and metadata on changes.
- **Remote Operations:** Allows SSO Manager administrators to remotely configure LDAP, restart systemd services, or execute maintenance scripts.

## The Security Model (Blast Radius & Zero-Trust)

Because Theta Agent runs as `root` (required to configure `/etc/sssd/sssd.conf`, restart services, and read hardware sensors), it represents a high-value target. If the central SSO Manager were compromised, a naive agent would allow an attacker to gain root shell execution on every server in the fleet.

To prevent lateral movement and contain the blast radius, **Theta Agent operates on a strict, local-first capability matrix.**

### 1. Local Configuration Wins
The agent will **only** execute commands that are explicitly enabled in its local configuration file (`/etc/theta/agent.yml`). 
- By default, the agent is locked down to read-only telemetry and basic LDAP configuration.
- The central SSO Manager cannot override these settings. An administrator must physically (or via local config management) edit the local `agent.yml` file to grant the agent more permissions.

### 2. The Capability Matrix
Capabilities are segmented into modules. You only enable what a specific server needs:

| Capability | Risk Level | Description |
|------------|------------|-------------|
| `telemetry` | Safe | Read-only. Pushes system metrics back to the SSO Manager. |
| `configure_ldap` | Moderate | Allows the SSO manager to push down an updated SSSD configuration file. |
| `reboot` | High | Allows the SSO Manager to trigger a system reboot. |
| `service_control` | High | Allows starting/stopping/restarting systemd services. **Must be scoped** to specific services (e.g., `['gitea', 'nginx']`). |
| `arbitrary_bash` | CRITICAL | Allows the execution of raw bash scripts sent from the SSO Manager. Useful for GitOps deployments on worker nodes, but highly dangerous. |

### 3. Outbound-Only Communication
The agent does not open any listening ports on the host firewall. It uses a long-lived outbound WebSocket connection to the SSO Manager. 

### 4. Cryptographic Authentication
Every agent is issued a unique, long-lived host token during installation. The SSO Manager verifies this token to ensure commands are only routed to the intended host, and telemetry is properly attributed.

## Example Configuration

See `agent.yml.example` for a secure baseline configuration.

## Installation

*(Coming soon: Build instructions and `theta-agent install` guide)*
