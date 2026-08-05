# Installation Guide: Theta Agent

Theta Agent is designed for rapid deployment across the fleet. The recommended method is via the "One-Liner" install, which marries the agent to a specific SSO Manager instance.

## Prerequisite: enroll the host

The agent's token is issued by the SSO, not chosen by you. In the SSO open
**Directory → Install Agent**, name the host, bind it to a host resource, and
press **Enroll & issue token**. You get:

- the **agent token** — shown once; only its hash is stored
- the **SSO public key** — pinned by the agent to verify high-risk commands

The modal builds the install command below with both already filled in. A token
the SSO did not issue is rejected at connect time with close code `4001`.

## Quick Start (The One-Liner)

The SSO Manager provides a pre-generated installation command. Copy and paste it into your terminal as root:

### Option A: Full Configuration (Recommended)
Use this for precise control over capabilities:
```bash
curl -fsSL https://sso.example.com/resources/theta-agent/install.sh | sh -s -- "BASE64_ENCODED_CONFIG"
```

### Option B: Minimal Setup
Use this for rapid deployment with basic telemetry:
```bash
curl -fsSL https://sso.example.com/resources/theta-agent/install.sh | sh -s -- \
  --url "https://sso.example.com" --token "<ISSUED_TOKEN>" --public-key "<BASE64_PUBLIC_KEY>"
```

### What this does:
1. Downloads the latest `theta-agent` binary.
2. Decodes the base64 configuration string into `/etc/theta42/agent.yml`.
3. Installs a systemd service unit.
4. Starts the agent automatically.

---

## Manual Installation

If you are in an air-gapped environment or prefer manual control:

### 1. Deploy Binary
Place the `theta-agent` binary in `/usr/local/bin/` and ensure it is executable:
```bash
chmod +x /usr/local/bin/theta-agent
```

### 2. Configure
Create the configuration directory and the `agent.yml` file:
```bash
mkdir -p /etc/theta42
nano /etc/theta42/agent.yml
```
Ensure the file has restricted permissions:
```bash
chmod 600 /etc/theta42/agent.yml
```

### 3. Setup systemd
Create the file `/etc/systemd/system/theta-agent.service`:
```ini
[Unit]
Description=Theta Agent Unified Endpoint Management
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/theta-agent
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=theta-agent

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
systemctl daemon-reload
systemctl enable theta-agent
systemctl start theta-agent
```

## Troubleshooting

### Verifying Connection
Check the logs to ensure the agent has successfully connected to the SSO Manager:
```bash
journalctl -u theta-agent -f
```
You should see: `Successfully connected to SSO Manager.`

### Configuration Errors
If the agent fails to start, verify the config file exists and is valid YAML:
```bash
ls -l /etc/theta42/agent.yml
```

### Root Privileges
The agent must run as root to execute system commands like `reboot` and `systemctl restart`. If you manually run the binary, ensure you use `sudo`.
